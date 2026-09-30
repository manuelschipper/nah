#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use effinterp_engine::{
    Engine, GITHUB_ACTIONS_DRIVER, SourcePurpose, SourceRefusal, SourceRequest, SourceResolver,
    SourceResponse, UnavailableReason, default_limits,
};
use effinterp_proto::{
    CoverageLevel, Domain, ExecutionEdgeKind, ExecutionRealm, ResourceExpr, Subject, validate_plan,
};

struct MapResolver(HashMap<String, String>);

struct ShallowMapResolver {
    sources: HashMap<String, String>,
    requests: Arc<Mutex<Vec<(String, SourcePurpose)>>>,
}

impl SourceResolver for MapResolver {
    fn matching(&self, pattern: &effinterp_engine::SourcePattern) -> Option<Vec<String>> {
        Some(
            self.0
                .keys()
                .filter(|path| pattern.matches(path))
                .cloned()
                .collect(),
        )
    }

    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0
            .get(request.path.trim_start_matches('/'))
            .map_or_else(
                || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
                |source| SourceResponse::Source(source.as_bytes().to_vec()),
            )
    }

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let path = path.trim_start_matches('/');
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        Some(
            self.0
                .keys()
                .filter(|candidate| {
                    candidate.as_str() != path
                        && candidate
                            .rsplit_once('/')
                            .map_or("", |(candidate_parent, _)| candidate_parent)
                            == parent
                })
                .cloned()
                .collect(),
        )
    }
}

impl SourceResolver for ShallowMapResolver {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.requests
            .lock()
            .unwrap()
            .push((request.path.to_string(), request.purpose));
        if request.purpose == SourcePurpose::DependencySource {
            return SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::DependencyDenied,
            ));
        }
        self.sources.get(request.path).map_or_else(
            || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |source| SourceResponse::Source(source.as_bytes().to_vec()),
        )
    }

    fn siblings(&self, _path: &str) -> Option<Vec<String>> {
        None
    }
}

fn exec(argv: &[&str], cwd: Option<&str>) -> Subject {
    Subject::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: cwd.map(|s| s.to_string()),
        context: Default::default(),
    }
}

fn ops(plan: &effinterp_proto::Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

#[test]
fn sh_c_nests_shell_source() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(
            &["sh", "-c", "rm -rf \"$TMPDIR/build\""],
            Some("/work"),
        ))
        .unwrap();
    validate_plan(&plan).unwrap();

    // process.exec sh and its argument code sink, then the nested shell's read
    // of $TMPDIR and the nested rm's process.exec + filesystem.delete.
    assert_eq!(
        ops(&plan),
        vec![
            "process.exec",
            "process.code_execution",
            "environment.read",
            "process.exec",
            "filesystem.delete"
        ]
    );
    let delete = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    // The symbolic $TMPDIR survives the shell -> nested-shell transition.
    assert!(matches!(delete.resource, ResourceExpr::Join { .. }));
    // One nested shell invocation, analyzed.
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| { matches!(&n.subject, Subject::Shell { .. }) && n.boundary.is_none() })
    );
}

#[test]
fn sh_without_c_is_opaque() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(&["sh", "./script.sh"], Some("/work")))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unrecoverable_source")
    );
}

#[test]
fn github_actions_requires_a_supported_shell() {
    for shell in ["", "pwsh"] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&exec(
                &[
                    GITHUB_ACTIONS_DRIVER,
                    "run",
                    ".github/workflows/check.yml",
                    "rm -rf /unsupported-shell",
                    shell,
                    "",
                    "",
                ],
                None,
            ))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_ci_step")
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
    }

    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(
            &[
                GITHUB_ACTIONS_DRIVER,
                "run",
                ".github/workflows/check.yml",
                "rm -rf /bash-shell",
                "bash",
                "",
                "",
            ],
            None,
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn github_actions_driver_names_are_not_shell_commands() {
    for command in ["github-actions", "github-actions-container"] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: format!("{command} workflow.yml 'rm -rf /unsupported' bash"),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::Process { executable, .. }
                } if executable == command)
        }));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_command")
        );
    }
}

#[test]
fn env_strips_assignments_and_runs_command() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(
            &["env", "FOO=1", "BAR=x", "rm", "-rf", "/tmp/z"],
            Some("/w"),
        ))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert_eq!(
        ops(&plan),
        vec!["process.exec", "process.exec", "filesystem.delete"]
    );
    let delete = plan.effects.last().unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path }
        } if path == "/tmp/z"
    ));
    let nested = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv.first().is_some_and(|arg| arg == "rm")))
        .expect("wrapped command node");
    assert_eq!(
        nested.environment.get("FOO").and_then(Option::as_ref),
        Some(&ResourceExpr::Literal {
            value: "1".to_string()
        })
    );
    assert_eq!(
        nested.environment.get("BAR").and_then(Option::as_ref),
        Some(&ResourceExpr::Literal {
            value: "x".to_string()
        })
    );
    assert!(
        plan.execution_graph
            .edges
            .iter()
            .any(|edge| edge.kind == ExecutionEdgeKind::ToolModel)
    );

    // Any argument containing `=` is an assignment, including a name the
    // shell would reject, so the command is the word after it.
    let exported = Engine::new()
        .analyze(&exec(
            &["env", "BASH_FUNC_f%%=() { rm /tmp/a; }", "rm", "/tmp/z"],
            Some("/w"),
        ))
        .unwrap();
    validate_plan(&exported).unwrap();
    assert_eq!(
        ops(&exported),
        vec!["process.exec", "process.exec", "filesystem.delete"]
    );

    for subject in [
        exec(
            &["env", "BASH_FUNC_f%%=() { rm /tmp/a; }", "bash", "-c", "f"],
            Some("/w"),
        ),
        Subject::Shell {
            source: "f() { rm /tmp/a; }; export -f f; bash -c f".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        },
    ] {
        let plan = Engine::new().analyze(&subject).unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path }
                    } if path == "/tmp/a")
            }),
            "{subject:?}: {:?}",
            plan.effects
        );
    }

    // `-S` splits its string into the command and its arguments; a string
    // whose grammar this model does not interpret runs nothing. A `--` in the
    // string ends env's options as it does on argv, and the attached
    // `--split-string=` spelling is the same option, not an assignment.
    for argv in [
        &["env", "-S", "rm -rf '/tmp/z z'"][..],
        &["env", "-S", "-- X=1 rm -rf '/tmp/z z'"][..],
        &["env", "--split-string=rm -rf '/tmp/z z'"][..],
    ] {
        let split = Engine::new().analyze(&exec(argv, Some("/w"))).unwrap();
        validate_plan(&split).unwrap();
        assert_eq!(
            ops(&split),
            vec!["process.exec", "process.exec", "filesystem.delete"],
            "{argv:?}"
        );
        assert!(matches!(
            &split.effects.last().unwrap().resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/tmp/z z"
        ));
    }
    let substituted = Engine::new()
        .analyze(&exec(&["env", "-S", "rm -rf $TARGET"], Some("/w")))
        .unwrap();
    validate_plan(&substituted).unwrap();
    assert_eq!(ops(&substituted), vec!["process.exec"]);
    assert!(
        substituted
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
}

#[test]
fn package_scripts_and_make_targets_use_explicit_graph_edges() {
    let resolver = MapResolver(HashMap::from([
        (
            "package.json".to_string(),
            r#"{"scripts":{"build":"rm -rf /package-output"}}"#.to_string(),
        ),
        (
            "Makefile".to_string(),
            "deploy:\n\trm -rf /build-output\n".to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "npm run build; make deploy".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let kinds: Vec<_> = plan
        .execution_graph
        .edges
        .iter()
        .map(|edge| edge.kind)
        .collect();
    assert!(kinds.contains(&ExecutionEdgeKind::PackageScript));
    assert!(kinds.contains(&ExecutionEdgeKind::BuildTarget));
    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/package-output"
        )
    }));
    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/build-output"
        )
    }));
}

#[test]
fn make_options_and_recipe_lines_preserve_exact_execution() {
    let options = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([
            (
                "dist/Makefile".to_string(),
                "dist:\n\trm -rf /wrong-dist\ndeploy:\n\trm -rf /right-deploy\n".to_string(),
            ),
            (
                "Makefile".to_string(),
                "4:\n\trm -rf /wrong-j\ndeploy:\n\trm -rf /right-j\n".to_string(),
            ),
        ]))))
        .analyze(&Subject::Shell {
            source: "make -C dist deploy; make -j 4 deploy".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&options).unwrap();
    for path in ["/right-deploy", "/right-j"] {
        assert!(options.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    for path in ["/wrong-dist", "/wrong-j"] {
        assert!(!options.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }

    let lines = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "work/Makefile".to_string(),
            "deploy:\n\tcd /prod\n\trm -rf data\nvars:\n\t$(RM) /var-target\n".to_string(),
        )]))))
        .analyze(&exec(&["make", "deploy"], Some("work")))
        .unwrap();
    validate_plan(&lines).unwrap();
    assert!(
        lines.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "work/data"
            )
        }),
        "{:?}",
        lines.effects
    );
    assert!(!lines.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/prod/data"
        )
    }));

    let variable = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "Makefile".to_string(),
            "vars:\n\t$(RM) /var-target\n".to_string(),
        )]))))
        .analyze(&exec(&["make", "vars"], None))
        .unwrap();
    validate_plan(&variable).unwrap();
    assert!(!variable.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::Process { executable, .. }
            } if executable == "RM"
        )
    }));
    assert!(
        variable
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_build_target")
    );
}

#[test]
fn make_nonexecuting_modes_and_empty_default_goal_do_not_run_recipes() {
    let resolver = MapResolver(HashMap::from([(
        "Makefile".to_string(),
        "CC := gcc\n.PHONY: all clean deploy\nall:\nclean:\n\trm -rf /clean-output\ndeploy:\n\trm -rf /build-output\n"
            .to_string(),
    )]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "make; make -n deploy; make -q deploy; make -t deploy".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in ["/clean-output", "/build-output"] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count()
            >= 3
    );
}

#[test]
fn make_default_goal_selection_is_conservative() {
    let resolver = MapResolver(HashMap::from([
        (
            "pattern.mk".to_string(),
            "%.log:\n\trm -rf /pattern-output\n  all:\n\trm -rf /real-default\n".to_string(),
        ),
        (
            "comment.mk".to_string(),
            "# Build helpers: run make deploy\ndeploy:\n\trm -rf /comment-output\n".to_string(),
        ),
        (
            "default.mk".to_string(),
            "  .DEFAULT_GOAL := all\nclean:\n\trm -rf /clean-output\nall:\n\trm -rf /all-output\n"
                .to_string(),
        ),
        (
            "conditional.mk".to_string(),
            "ifeq ($(CI),true)\ndeploy:\n\trm -rf /ci-only\nendif\ndeploy:\n\trm -rf /normal\n"
                .to_string(),
        ),
        (
            "ifdef.mk".to_string(),
            "ifdef CI\ndeploy:\n\trm -rf /ifdef-only\nendif\ndeploy:\n\trm -rf /ifdef-normal\n"
                .to_string(),
        ),
    ]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "make -f pattern.mk; make -f comment.mk; make -f default.mk; make -f conditional.mk deploy; make -f ifdef.mk deploy".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in ["/real-default", "/comment-output", "/all-output"] {
        assert!(plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    for path in [
        "/pattern-output",
        "/clean-output",
        "/ci-only",
        "/normal",
        "/ifdef-only",
        "/ifdef-normal",
    ] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count()
            >= 2
    );
}

#[test]
fn make_unsupported_syntax_remains_a_typed_boundary() {
    let resolver = MapResolver(HashMap::from([
        (
            "oneshell.mk".to_string(),
            ".ONESHELL: # shared shell\ndeploy:\n\tcd /tmp\n\trm -rf artifacts\n".to_string(),
        ),
        (
            "spaced-oneshell.mk".to_string(),
            ".ONESHELL : prerequisite\ndeploy:\n\tcd /tmp\n\trm -rf artifacts\n".to_string(),
        ),
        (
            "assignment.mk".to_string(),
            "release: CFLAGS=-O2\nrelease:\n\trm -rf /release-output\n".to_string(),
        ),
        (
            "continuation.mk".to_string(),
            "build:\n\tcc -o app \\\n\t\tmain.c\n".to_string(),
        ),
    ]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "make -f oneshell.mk deploy; make -f spaced-oneshell.mk deploy; make -f assignment.mk release; make -f continuation.mk build; make 日本語; gmake -ü".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert!(!plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::Process { executable, .. }
            } if executable == "main.c"
        )
    }));
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count()
            >= 6
    );
}

#[test]
fn make_recipe_continues_after_make_comments() {
    let resolver = MapResolver(HashMap::from([(
        "Makefile".to_string(),
        "deploy:\n\techo before\n# a make comment\n\trm -rf /comment-output\n".to_string(),
    )]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&exec(&["make", "deploy"], None))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/comment-output"
        )
    }));
}

#[test]
fn make_recipe_prefixes_and_overrides_match_execution() {
    let resolver = MapResolver(HashMap::from([
        (
            "prefix.mk".to_string(),
            "deploy:\n\t @rm -rf /at-output\n\t - rm -rf /dash-output\n".to_string(),
        ),
        (
            "override.mk".to_string(),
            "deploy:\ndeploy:\n\trm -rf /override-output\npreserve:\n\trm -rf /preserved-output\npreserve:\n"
                .to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source:
                "make -f prefix.mk deploy; make -f override.mk deploy; make -f override.mk preserve"
                    .to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in [
        "/at-output",
        "/dash-output",
        "/override-output",
        "/preserved-output",
    ] {
        assert!(plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    for executable in ["@rm", "-"] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::Process {
                        executable: actual,
                        ..
                    }
                } if actual == executable
            )
        }));
    }
}

#[test]
fn just_recipe_prefixes_are_not_part_of_the_command() {
    let resolver = MapResolver(HashMap::from([(
        "justfile".to_string(),
        "deploy:\n    @rm -rf /just-at\n    -rm -rf /just-dash\n".to_string(),
    )]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&exec(&["just", "deploy"], None))
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in ["/just-at", "/just-dash"] {
        assert!(plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    for executable in ["@rm", "-rm"] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::Process {
                        executable: actual,
                        ..
                    }
                } if actual == executable
            )
        }));
    }
}

#[test]
fn just_default_recipe_selection_is_definitive() {
    let resolver = MapResolver(HashMap::from([
        (
            "empty.just".to_string(),
            "first:\n\nsecond:\n  rm -rf /just-second\n".to_string(),
        ),
        (
            "quiet.just".to_string(),
            "@first:\n  rm -rf /just-first\n\nsecond:\n  rm -rf /just-later\n".to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "just -f empty.just; just -f quiet.just".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/just-first"
        )
    }));
    for path in ["/just-second", "/just-later"] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
}

#[test]
fn just_and_task_working_directories_propagate_or_widen() {
    let resolver = MapResolver(HashMap::from([
        (
            "working.just".to_string(),
            "[working-directory('just-sub')]\nbuild:\n  rm -rf out\n".to_string(),
        ),
        (
            "dynamic.just".to_string(),
            "[working-directory(env_var('DIR'))]\nbuild:\n  rm -rf dynamic-out\n".to_string(),
        ),
        (
            "WorkingTask.yml".to_string(),
            "version: '3'\ntasks:\n  build:\n    dir: task-sub\n    cmds:\n      - rm -rf out\n"
                .to_string(),
        ),
        (
            "DynamicTask.yml".to_string(),
            "version: '3'\ntasks:\n  build:\n    dir: '{{.DIR}}'\n    cmds:\n      - rm -rf dynamic-out\n"
                .to_string(),
        ),
    ]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "just -f working.just build; task -t WorkingTask.yml build; just -f dynamic.just build; task -t DynamicTask.yml build".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for directory in ["just-sub", "task-sub"] {
        assert!(
            plan.effects.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Join { parts }
                        if parts.iter().any(|part| matches!(
                            part,
                            ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                            } if actual == directory
                        ))
                        && parts.iter().any(|part| matches!(
                            part,
                            ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path }
                            } if path == "out"
                        ))
                )
            }),
            "missing {directory}/out: {:#?}",
            plan.effects
        );
    }
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effinterp_proto::display_resource(&effect.resource).contains("dynamic-out")
    }));
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count()
            >= 2
    );
}

#[test]
fn task_execution_fields_are_parsed_or_fail_closed() {
    let resolver = MapResolver(HashMap::from([(
        "Taskfile.yml".to_string(),
        "version: '3'\ntasks:\n  quoted-dir:\n    \"dir\": quoted\n    cmds:\n      - rm -rf out\n  spaced-dir:\n    dir : spaced\n    cmds:\n      - rm -rf out\n  quoted-deps:\n    \"deps\": [build]\n    cmds:\n      - rm -rf /quoted-deps\n  spaced-deps:\n    deps : [build]\n    cmds:\n      - rm -rf /spaced-deps\n  environment:\n    env: {TARGET: /task-env}\n    cmds:\n      - rm -rf /task-env\n  status-check:\n    status: ['true']\n    cmds:\n      - rm -rf /status-skipped\n"
            .to_string(),
    )]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "task quoted-dir; task spaced-dir; task quoted-deps; task spaced-deps; task environment; task status-check".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for directory in ["quoted", "spaced"] {
        assert!(plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Join { parts }
                    if parts.iter().any(|part| matches!(
                        part,
                        ResourceExpr::Concrete {
                            identity: effinterp_proto::ResourceIdentity::FsPath { path }
                        } if path == directory
                    ))
                    && parts.iter().any(|part| matches!(
                        part,
                        ResourceExpr::Concrete {
                            identity: effinterp_proto::ResourceIdentity::FsPath { path }
                        } if path == "out"
                    ))
            )
        }));
    }
    for path in [
        "/quoted-deps",
        "/spaced-deps",
        "/task-env",
        "/status-skipped",
    ] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count(),
        4
    );
}

#[test]
fn just_context_and_recipe_arguments_are_exact() {
    let resolver = MapResolver(HashMap::from([
        (
            "multi.just".to_string(),
            "[private, working-directory(\"multi-sub\")]\nbuild:\n  rm -rf multi-out\n".to_string(),
        ),
        (
            "comment.just".to_string(),
            "[working-directory('comment-sub')] # context\nbuild:\n  rm -rf comment-out\n"
                .to_string(),
        ),
        (
            "setting.just".to_string(),
            "set working-directory := 'setting-sub'\n\nbuild:\n  rm -rf setting-out\n".to_string(),
        ),
        (
            "nested/justfile".to_string(),
            "build:\n  rm -rf nested-out\n".to_string(),
        ),
        (
            "other/no-cd.just".to_string(),
            "[no-cd]\nbuild:\n  rm -rf no-cd-out\n".to_string(),
        ),
        (
            "missing.just".to_string(),
            "build target:\n  rm -rf /missing-required\n".to_string(),
        ),
        (
            "provided.just".to_string(),
            "build target:\n  rm -rf /provided-required\n".to_string(),
        ),
        (
            "default.just".to_string(),
            "build target='fallback':\n  rm -rf /default-parameter\n".to_string(),
        ),
    ]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "just -f multi.just build; just -f comment.just build; just -f setting.just build; just -f nested/justfile build; just -f other/no-cd.just build; just -f missing.just build; just -f provided.just build value; just -f default.just build".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for (directory, path) in [
        ("multi-sub", "multi-out"),
        ("comment-sub", "comment-out"),
        ("setting-sub", "setting-out"),
        ("nested", "nested-out"),
    ] {
        assert!(
            plan.effects.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Join { parts }
                        if parts.iter().any(|part| matches!(
                            part,
                            ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                            } if actual == directory
                        ))
                        && parts.iter().any(|part| matches!(
                            part,
                            ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                            } if actual == path
                        ))
                )
            }),
            "missing {directory}/{path}: {:#?}",
            plan.effects
        );
    }
    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Join { parts }
                if parts.iter().any(|part| matches!(
                    part,
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path }
                    } if path == "no-cd-out"
                ))
                && !parts.iter().any(|part| matches!(
                    part,
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path }
                    } if path == "other"
                ))
        )
    }));
    for path in ["/provided-required", "/default-parameter"] {
        assert!(plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    assert!(!plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/missing-required"
        )
    }));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_build_target")
    );
}

#[test]
fn just_and_task_file_directories_follow_tool_precedence() {
    let resolver = MapResolver(HashMap::from([
        (
            "sub/justfile".to_string(),
            "build:\n  rm -rf just-out\n".to_string(),
        ),
        (
            "other/sub/justfile".to_string(),
            "build:\n  rm -rf /wrong-justfile\n".to_string(),
        ),
        (
            "s/no-setting.just".to_string(),
            "set working-directory := 'wd'\n\n[no-cd]\nbuild:\n  rm -rf no-setting-out\n"
                .to_string(),
        ),
        (
            "s/no-attribute.just".to_string(),
            "[no-cd, working-directory('x')]\nbuild:\n  rm -rf no-attribute-out\n".to_string(),
        ),
        (
            "compact.just".to_string(),
            "set working-directory:='compact'\n\nbuild:\n  rm -rf compact-out\n".to_string(),
        ),
        (
            "compact-shell.just".to_string(),
            "set shell:=[\"python3\", \"-c\"]\n\nbuild:\n  rm -rf /shell-output\n".to_string(),
        ),
        (
            "composed.just".to_string(),
            "set working-directory := 'setting'\n\n[working-directory('attribute')]\nbuild:\n  rm -rf composed-out\n"
                .to_string(),
        ),
        (
            "sub/Taskfile.yml".to_string(),
            "version: '3'\ntasks:\n  from-file:\n    cmds:\n      - rm -rf task-file-out\n  from-dir:\n    cmds:\n      - rm -rf task-dir-out\n"
                .to_string(),
        ),
        (
            "other/sub/Taskfile.yml".to_string(),
            "version: '3'\ntasks:\n  from-dir:\n    cmds:\n      - rm -rf /wrong-taskfile\n"
                .to_string(),
        ),
    ]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "just -d other -f sub/justfile build; just -f s/no-setting.just build; just -f s/no-attribute.just build; just -f compact.just build; just -f compact-shell.just build; just -d cli -f composed.just build; task -t sub/Taskfile.yml from-file; task from-dir -d other -t sub/Taskfile.yml".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for (leaf, required, forbidden) in [
        ("just-out", &["other"][..], &["sub"][..]),
        ("no-setting-out", &[][..], &["s", "wd"][..]),
        ("no-attribute-out", &[][..], &["s", "x"][..]),
        ("compact-out", &["compact"][..], &[][..]),
        (
            "composed-out",
            &["cli", "setting", "attribute"][..],
            &[][..],
        ),
        ("task-file-out", &["sub"][..], &[][..]),
        ("task-dir-out", &["other"][..], &["sub"][..]),
    ] {
        let parts = plan
            .effects
            .iter()
            .find_map(|effect| match &effect.resource {
                ResourceExpr::Join { parts }
                    if parts.iter().any(|part| {
                        matches!(
                            part,
                            ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path }
                            } if path == leaf
                        )
                    }) =>
                {
                    Some(parts)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing relative effect for {leaf}: {:#?}", plan.effects));
        for directory in required {
            assert!(parts.iter().any(|part| matches!(
                part,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == directory
            )));
        }
        for directory in forbidden {
            assert!(!parts.iter().any(|part| matches!(
                part,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == directory
            )));
        }
    }
    for path in ["/wrong-justfile", "/wrong-taskfile", "/shell-output"] {
        assert!(!plan.effects.iter().any(|effect| matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
            } if actual == path
        )));
    }
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_build_target")
    );
}

#[test]
fn unsupported_build_execution_semantics_remain_typed_boundaries() {
    let resolver = MapResolver(HashMap::from([
        (
            "shell.mk".to_string(),
            "SHELL := /usr/bin/python3\n.SHELLFLAGS := -c\n\ndeploy:\n\tos.remove(\"/make-shell\")\n"
                .to_string(),
        ),
        (
            "prereq.mk".to_string(),
            "prepare:\n\trm -rf /make-prepare\ndeploy: prepare\n\trm -rf /make-deploy\n"
                .to_string(),
        ),
        (
            "safe.mk".to_string(),
            "deploy:\n\trm -rf /make-file\n".to_string(),
        ),
        (
            "shebang.just".to_string(),
            "deploy:\n  #!/usr/bin/env python3\n  import os\n  os.remove(\"/just-shebang\")\n"
                .to_string(),
        ),
        (
            "shell.just".to_string(),
            "set shell := [\"python3\", \"-c\"]\n\ndeploy:\n  os.remove(\"/just-shell\")\n"
                .to_string(),
        ),
        (
            "assignment.just".to_string(),
            "flags := \"-a\" + \\\n  \"/not-a-command\"\n\nbuild:\n  rm -rf /just-build\n"
                .to_string(),
        ),
        (
            "dependency.just".to_string(),
            "build:\n  rm -rf /just-dependency\n\ndeploy: build\n  rm -rf /just-deploy\n"
                .to_string(),
        ),
        (
            "Taskfile.yml".to_string(),
            "version: '3'\ntasks:\n  build:\n    cmds:\n      - rm -rf /task-build\n  deploy:\n    cmds:\n      - task: build\n      - rm -rf /task-deploy\n  dependency-array:\n    deps: [build]\n    cmds:\n      - rm -rf /task-array\n  dependency-map:\n    deps:\n      - task: build\n    cmds:\n      - rm -rf /task-map\n"
                .to_string(),
        ),
    ]));
    let plan = Engine::new().with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "make -f shell.mk deploy; make -f prereq.mk deploy; make -f safe.mk --eval 'deploy: ; rm -rf /make-eval' deploy; just -f shebang.just deploy; just -f shell.just deploy; just -f assignment.just; just -f dependency.just deploy; task deploy; task dependency-array; task dependency-map".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in [
        "/make-shell",
        "/make-prepare",
        "/make-deploy",
        "/make-file",
        "/make-eval",
        "/just-shebang",
        "/just-shell",
        "/just-dependency",
        "/just-deploy",
        "/task-build",
        "/task-array",
        "/task-map",
    ] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    for path in ["/just-build", "/task-deploy"] {
        assert!(plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    for executable in ["os.remove", "import", "not-a-command", "task:"] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::Process {
                        executable: actual,
                        ..
                    }
                } if actual == executable
            )
        }));
    }
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count()
            >= 6
    );
}

#[test]
fn cargo_and_gradle_require_run_in_the_command_position() {
    let resolver = MapResolver(HashMap::from([
        (
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n".to_string(),
        ),
        (
            "src/main.rs".to_string(),
            "fn main() { std::fs::remove_file(\"/cargo-output\"); }\n".to_string(),
        ),
        (
            "build.gradle".to_string(),
            "plugins { id 'application' }\nmainClass = 'com.acme.Main'\n".to_string(),
        ),
        (
            "src/main/java/com/acme/Main.java".to_string(),
            "import java.nio.file.Files; import java.nio.file.Path; public class Main { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/gradle-output\")); } }".to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "cargo xtask run; gradle build -x run".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in ["/cargo-output", "/gradle-output"] {
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_build_target")
            .count()
            >= 2
    );
}

#[test]
fn build_tools_launch_exact_local_entrypoints() {
    let resolver = MapResolver(HashMap::from([
        (
            "justfile".to_string(),
            "deploy:\n  rm -rf /from-just\n".to_string(),
        ),
        (
            "Taskfile.yml".to_string(),
            "version: '3'\ntasks:\n  ship:\n    cmds:\n      - rm -rf /from-task\n".to_string(),
        ),
        (
            "Cargo.toml".to_string(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n".to_string(),
        ),
        (
            "src/main.rs".to_string(),
            "fn main() { std::fs::remove_file(\"/from-cargo\"); }\n".to_string(),
        ),
        (
            "cmd/app/main.go".to_string(),
            "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/from-go\") }\n"
                .to_string(),
        ),
        (
            "pom.xml".to_string(),
            "<project><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.Main</mainClass></configuration></plugin></plugins></build></project>".to_string(),
        ),
        (
            "build.gradle".to_string(),
            "plugins { id 'application' }\nmainClass = 'com.acme.Main'\n".to_string(),
        ),
        (
            "src/main/java/com/acme/Main.java".to_string(),
            "import java.nio.file.Files; import java.nio.file.Path; public class Main { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/from-java\")); } }".to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source:
                "just deploy; task ship; cargo run; go run ./cmd/app; mvn exec:java; gradle run"
                    .to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        plan.execution_graph
            .edges
            .iter()
            .filter(|edge| edge.kind == ExecutionEdgeKind::BuildTarget)
            .count()
            >= 6
    );
    for path in [
        "/from-just",
        "/from-task",
        "/from-cargo",
        "/from-go",
        "/from-java",
    ] {
        assert!(
            plan.effects.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                    } if actual == path
                )
            }),
            "missing {path}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn maven_main_class_is_scoped_to_the_exec_plugin() {
    let resolver = MapResolver(HashMap::from([
        (
            "pom.xml".to_string(),
            "<project><build><plugins><plugin><artifactId>maven-jar-plugin</artifactId><configuration><mainClass>com.acme.Wrong</mainClass></configuration></plugin><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.Right</mainClass></configuration></plugin></plugins></build></project>".to_string(),
        ),
        (
            "src/main/java/com/acme/Wrong.java".to_string(),
            "import java.nio.file.Files; import java.nio.file.Path; public class Wrong { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/maven-wrong\")); } }".to_string(),
        ),
        (
            "src/main/java/com/acme/Right.java".to_string(),
            "import java.nio.file.Files; import java.nio.file.Path; public class Right { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/maven-right\")); } }".to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&exec(&["mvn", "exec:java"], None))
        .unwrap();
    validate_plan(&plan).unwrap();

    for (path, expected) in [("/maven-right", true), ("/maven-wrong", false)] {
        assert_eq!(
            plan.effects.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }
                    } if actual == path
                )
            }),
            expected
        );
    }
}

#[test]
fn go_package_with_sibling_sources_stays_a_typed_boundary() {
    let resolver = MapResolver(HashMap::from([
        (
            "cmd/app/main.go".to_string(),
            "package main\nfunc main() { helper() }\n".to_string(),
        ),
        (
            "cmd/app/helper.go".to_string(),
            "package main\nimport \"os\"\nfunc helper() { os.RemoveAll(\"/go-helper-output\") }\n"
                .to_string(),
        ),
    ]));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "go run ./cmd/app".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(!plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/go-helper-output"
        )
    }));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unrecoverable_source"
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("sibling Go sources"))
    }));
    assert!(!plan.execution_graph.edges.iter().any(|edge| {
        edge.kind == ExecutionEdgeKind::BuildTarget
            && plan.execution_graph.nodes[edge.to.0 as usize].selected_source_path()
                == Some("cmd/app/main.go")
    }));
}

#[test]
fn direct_local_shell_requires_shebang_evidence() {
    let subject = Subject::Shell {
        source: "./deploy".to_string(),
        cwd: None,
        context: Default::default(),
    };
    let positive = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "deploy".to_string(),
            "#!/bin/sh\nrm -rf /from-script\n".to_string(),
        )]))))
        .analyze(&subject)
        .unwrap();
    validate_plan(&positive).unwrap();
    assert!(positive.execution_graph.edges.iter().any(|edge| {
        edge.kind == ExecutionEdgeKind::Script
            && positive.execution_graph.nodes[edge.to.0 as usize].selected_source_path()
                == Some("deploy")
    }));
    assert!(positive.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/from-script"
        )
    }));
    assert!(positive.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && effinterp_proto::display_resource(&effect.resource).contains("deploy")
    }));
    assert!(positive.effects.iter().any(|effect| {
        effect.operation.0 == "process.code_execution"
            && effect.attributes.get("source")
                == Some(&effinterp_proto::AttrValue::String("file".to_string()))
    }));

    let negative = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "deploy".to_string(),
            "rm -rf /from-script\n".to_string(),
        )]))))
        .analyze(&subject)
        .unwrap();
    assert!(!negative.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/from-script"
        )
    }));
    assert!(!negative.boundaries.is_empty());
}

#[test]
fn shell_script_launches_bind_positional_arguments() {
    // File launches must preserve concrete and symbolic operands through
    // positional expansion and mutation. Absolute runtime/model paths keep the
    // explicit PATH fixture from claiming unobserved command selection.
    for launch in ["./s.sh", "/bin/sh ./s.sh", "/bin/bash s.sh", "s.sh"] {
        let argv0_write = format!("printf x > {}", launch.split_whitespace().last().unwrap());
        for (script, arguments, expected) in [
            ("printf x > \"$0\"", "./unused", argv0_write.as_str()),
            ("/bin/cat \"$1\"", "./bd", "/bin/cat ./bd"),
            ("/bin/cat \"$1\"", "\"$TARGET\"", "/bin/cat \"$TARGET\""),
            (
                "/bin/cat \"$@\"",
                "./one './two words'",
                "/bin/cat ./one './two words'",
            ),
            ("shift; /bin/cat \"$@\"", "./skip ./keep", "/bin/cat ./keep"),
            ("set -- ./new; /bin/cat \"$1\"", "./old", "/bin/cat ./new"),
            ("/bin/cat \"$@\"", "", "/bin/cat"),
            ("\"$1\" init --help", "./bd", "./bd init --help"),
            (
                "/bin/cat \"$2\"",
                "./ignore \"$TARGET\"",
                "/bin/cat \"$TARGET\"",
            ),
        ] {
            let script = format!("#!/bin/sh\n{script}\n");
            let context = effinterp_proto::HostContext {
                env: [("PATH".to_string(), "/work/bin".to_string())].into(),
                ..Default::default()
            };
            let plan = Engine::new()
                .with_causality_detail(true)
                .with_resolver(Box::new(MapResolver(HashMap::from([
                    ("work/s.sh".to_string(), script.clone()),
                    ("work/bin/s.sh".to_string(), script),
                ]))))
                .analyze(&Subject::Shell {
                    source: format!("{launch} {arguments}"),
                    cwd: Some("/work".to_string()),
                    context,
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let expected_plan = Engine::new()
                .analyze(&Subject::Shell {
                    source: expected.to_string(),
                    cwd: Some("/work".to_string()),
                    context: Default::default(),
                })
                .unwrap();
            for effect in &expected_plan.effects {
                assert!(
                    plan.effects.iter().any(|actual| {
                        actual.operation == effect.operation && actual.resource == effect.resource
                    }),
                    "missing {effect:?} for {launch} {arguments}: {:?}",
                    plan.effects
                        .iter()
                        .map(|e| (
                            e.operation.as_str(),
                            effinterp_proto::display_resource(&e.resource)
                        ))
                        .collect::<Vec<_>>()
                );
            }
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0.starts_with("system."))
            );
            if arguments.starts_with("./ignore") {
                let effect = plan
                    .effects
                    .iter()
                    .find(|effect| {
                        effect.operation.0 == "filesystem.read"
                            && expected_plan
                                .effects
                                .iter()
                                .any(|expected| expected.resource == effect.resource)
                    })
                    .unwrap();
                let index = if launch.contains(' ') { 3 } else { 2 };
                let mut pending = effect.provenance.clone();
                let mut seen = std::collections::BTreeSet::new();
                while let Some(reference) = pending.pop() {
                    if seen.insert(reference) {
                        pending.extend(&plan.provenance[reference.0 as usize].antecedents);
                    }
                }
                assert!(seen.iter().any(|reference| matches!(
                    plan.provenance[reference.0 as usize].kind,
                    effinterp_proto::ProvenanceKind::Argument { index: actual } if actual == index
                )), "missing launch argument provenance for {launch}");
            }
            let reads = |plan: &effinterp_proto::Plan| {
                plan.effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "filesystem.read")
                    .map(|effect| effect.resource.clone())
                    .filter(|resource| {
                        !matches!(resource, ResourceExpr::Concrete {
                            identity: effinterp_proto::ResourceIdentity::FsPath { path }
                        } if path == "/work/s.sh" || path == "/work/bin/s.sh")
                    })
                    .map(|resource| serde_json::to_string(&resource).unwrap())
                    .collect::<std::collections::BTreeSet<_>>()
            };
            assert_eq!(
                reads(&plan),
                reads(&expected_plan),
                "{launch} {arguments}: {expected}"
            );
        }
    }
}

#[test]
fn sourced_shell_keeps_caller_positional_parameters() {
    let plan = Engine::new()
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "sourced.sh".to_string(),
            "cat \"$1\"; shift; cat \"$@\"".to_string(),
        )]))))
        .analyze(&Subject::Shell {
            source: "set -- /first /second; . ./sourced.sh; cat \"$1\"".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let paths = plan
        .effects
        .iter()
        .filter_map(|effect| match (&effect.operation.0[..], &effect.resource) {
            (
                "filesystem.read",
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                },
            ) => Some(path.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, ["sourced.sh", "/first", "/second", "/second"]);
}

#[test]
fn source_alternatives_isolate_argument_restoration_and_written_content() {
    // Predicted script bytes need no disk resolver.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "printf 'rm /written\\n' > a.sh; source ./a.sh".into(),
            cwd: Some("".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effinterp_proto::display_resource(&effect.resource) == "fs:/written"
    }));
    for setter in [false, true] {
        for nested in [false, true] {
            let source_call = r#"source "alt/${CHOICE}.sh" /passed"#;
            let command = if nested {
                r#"set -- /outer; source ./wrapper.sh /wrapper; rm "$1""#.to_string()
            } else {
                format!(r#"set -- /outer; {source_call}; rm "$1""#)
            };
            let files = HashMap::from([
                ("wrapper.sh".into(), source_call.into()),
                ("alt/a.sh".into(), "rm /stale-disk".into()),
                (
                    "alt/b.sh".into(),
                    if setter {
                        r#"rm "$1"; set -- /changed"#
                    } else {
                        r#"rm "$1"; shift"#
                    }
                    .into(),
                ),
            ]);
            let plan = Engine::new()
                .with_resolver(Box::new(MapResolver(files)))
                .analyze(&Subject::Shell {
                    source: format!("printf 'rm \"$1\"\\n' > alt/a.sh; {command}"),
                    cwd: Some("".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let deletes: Vec<_> = plan
                .effects
                .iter()
                .filter(|effect| effect.operation.0 == "filesystem.delete")
                .collect();
            assert_eq!(deletes.len(), 3, "setter={setter}, nested={nested}");
            for effect in &deletes[..2] {
                assert_eq!(
                    effinterp_proto::display_resource(&effect.resource),
                    "fs:/passed"
                );
                assert!(effect.condition.is_some());
            }
            if setter {
                assert!(!matches!(
                    deletes[2].resource,
                    ResourceExpr::Concrete { .. }
                ));
            } else {
                assert_eq!(
                    effinterp_proto::display_resource(&deletes[2].resource),
                    "fs:/outer"
                );
            }
            assert!(deletes[2].condition.is_none());
            let input = plan
                .execution_graph
                .nodes
                .iter()
                .find(|node| node.selected_source_path() == Some("alt/a.sh"))
                .unwrap()
                .input
                .as_ref()
                .unwrap();
            assert_eq!(
                input.role,
                effinterp_proto::ExecutionInputRole::ExplicitInvocation
            );
            assert_eq!(
                input.assurance,
                effinterp_proto::ExecutionAssurance::Alternatives
            );
            assert!(matches!(
                input.content,
                effinterp_proto::ExecutionContent::Predicted { .. }
            ));
        }
    }
}

#[test]
fn invoked_source_patterns_use_runtime_cwd_and_keep_bare_search_opaque() {
    for operand in ["lib/helper.sh", "lib/${HELPER}.sh", "helper.sh"] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([
                (
                    "bin/main.sh".into(),
                    format!("source \"{operand}\"; rm /after"),
                ),
                ("lib/helper.sh".into(), "rm /runtime-cwd".into()),
                (
                    "bin/lib/helper.sh".into(),
                    "rm /wrong-script-directory".into(),
                ),
                ("helper.sh".into(), "rm /unobserved-path-winner".into()),
            ]))))
            .analyze_with_cwds(
                &exec(&["bash", "bin/main.sh"], Some("/work")),
                Some(""),
                Some(""),
            )
            .unwrap();
        validate_plan(&plan).unwrap();
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| effinterp_proto::display_resource(&effect.resource))
            .collect();
        if operand.contains('/') {
            assert_eq!(deletes, ["fs:/runtime-cwd", "fs:/after"], "{operand}");
        } else {
            assert_eq!(deletes, ["fs:/after"]);
            assert!(plan.execution_graph.nodes.iter().any(|node| {
                node.boundary.is_some()
                    && node.input.as_ref().is_some_and(|input| {
                        input.role == effinterp_proto::ExecutionInputRole::ExplicitInvocation
                            && input.selected.is_none()
                            && matches!(
                                input.content,
                                effinterp_proto::ExecutionContent::Unobserved { .. }
                            )
                    })
            }));
        }
    }
}

#[test]
fn direct_python_version_shebang_nests_source() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "tool".to_string(),
            "#!/usr/bin/env python3.12\nimport os\nos.remove('/versioned-python')\n".to_string(),
        )]))))
        .analyze(&exec(&["./tool"], Some("")))
        .unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "/versioned-python"
            )
    }));
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_command")
    );
}

#[test]
fn resolver_refusal_reason_is_boundary_evidence() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::new())))
        .analyze(&exec(&["python3", "missing.py"], Some("")))
        .unwrap();

    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unrecoverable_source"
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.ends_with(": missing"))
    }));
}

#[test]
fn invocation_sources_do_not_admit_dependency_sources() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(ShallowMapResolver {
            sources: HashMap::from([
                (
                    "x.py".to_string(),
                    "import helpers\nimport os\nos.remove('/invocation-source')\n".to_string(),
                ),
                (
                    "helpers.py".to_string(),
                    "import os\nos.remove('/dependency-source')\n".to_string(),
                ),
            ]),
            requests: Arc::clone(&requests),
        }))
        .analyze(&exec(&["python3", "x.py"], Some("")))
        .unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effinterp_proto::display_resource(&effect.resource).contains("invocation-source")
    }));
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effinterp_proto::display_resource(&effect.resource).contains("dependency-source")
    }));
    // The resolver's refusal of the first dependency probe ends traversal.
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.as_slice(),
        &[
            ("x.py".to_string(), SourcePurpose::InvocationInput),
            (
                "helpers/__init__.py".to_string(),
                SourcePurpose::DependencySource
            ),
        ]
    );
    let input = plan.execution_graph.nodes.iter().filter_map(|node| node.input.as_ref()).find(|input| {
        matches!(&input.selector, effinterp_proto::ExecutionSelector::Dependency { specifier } if specifier == "helpers")
    }).unwrap();
    assert_eq!(
        input.role,
        effinterp_proto::ExecutionInputRole::DependencyRequest
    );
    assert_eq!(input.phase, effinterp_proto::ExecutionPhase::Import);
    assert!(matches!(
        input.content,
        effinterp_proto::ExecutionContent::Unobserved {
            reason: effinterp_proto::ExecutionInputReason::DependencyNotTraversed
        }
    ));
}

#[test]
fn runtime_owned_modules_do_not_create_dependency_boundaries() {
    let node_source = [
        "os",
        "crypto",
        "net",
        "url",
        "events",
        "stream",
        "zlib",
        "assert",
        "dns",
        "tls",
        "readline",
        "vm",
        "worker_threads",
        "querystring",
        "buffer",
        "timers",
        "string_decoder",
        "assert/strict",
        "dns/promises",
        "node:sqlite",
    ]
    .into_iter()
    .map(|module| format!("require('{module}');"))
    .collect::<String>()
        + "require('left-pad'); const fs = require('fs'); fs.unlinkSync('/node-runtime-module');";
    for (argv, path, source, expected_dependency) in [
        (vec!["node", "x.js"], "x.js", node_source, Some("left-pad")),
        (
            vec!["python3", "x.py"],
            "x.py",
            "import json\nimport os\nimport subprocess\nos.remove('/python-runtime-module')\n"
                .to_string(),
            None,
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                path.to_string(),
                source,
            )]))))
            .analyze(&exec(&argv, Some("")))
            .unwrap();

        validate_plan(&plan).unwrap();
        let dependency_requests = plan
            .execution_graph
            .nodes
            .iter()
            .filter_map(|node| node.input.as_ref())
            .filter_map(|input| match &input.selector {
                effinterp_proto::ExecutionSelector::Dependency { specifier } => {
                    Some(specifier.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            dependency_requests,
            expected_dependency.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            plan.execution_graph
                .nodes
                .iter()
                .filter(|node| {
                    node.boundary.is_some()
                        && node.input.as_ref().is_some_and(|input| {
                            matches!(
                                input.selector,
                                effinterp_proto::ExecutionSelector::Dependency { .. }
                            )
                        })
                })
                .count(),
            usize::from(expected_dependency.is_some())
        );
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource(&effect.resource).contains("runtime-module")
        }));
    }
}

// A manifest or recipe must not admit a helper's effects, even through shell wrappers.
// Its refusal must also leave later direct invocations able to resolve their source.
#[test]
fn package_and_make_scripts_do_not_resolve_helper_files() {
    for (command, manifest) in [
        ("npm test", "package.json"),
        ("make -f Makefile deploy", "Makefile"),
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let plan = Engine::new().with_causality_detail(true)
            .with_resolver(Box::new(ShallowMapResolver {
                sources: HashMap::from([
                    ("package.json".to_string(), r#"{"scripts":{"pretest":"python3 helper.py","test":"sh -c 'node -r ./helper.js helper.js'","posttest":"node helper.js"}} "#.to_string()),
                    ("Makefile".to_string(), "deploy:\n\tpython3 helper.py\n\tsh -c 'node -r ./helper.js helper.js'\n".to_string()),
                    ("helper.py".to_string(), "import os\nos.remove('/forbidden-helper')".to_string()),
                    ("helper.js".to_string(), "require('fs').unlinkSync('/forbidden-helper')".to_string()),
                    ("direct.js".to_string(), "require('fs').unlinkSync('/direct-output')".to_string()),
                ]),
                requests: requests.clone(),
            }))
            .analyze(&Subject::Shell {
                source: format!("{command}; node direct.js"),
                cwd: Some("".to_string()),
                context: Default::default(),
            }).unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (manifest.to_string(), SourcePurpose::InvocationInput),
                ("direct.js".to_string(), SourcePurpose::InvocationInput),
            ]
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
        );
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("process"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Partial)
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource)
                        .contains("/forbidden-helper"))
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource)
                        .contains("/direct-output"))
        );
    }
}

#[test]
fn distinct_invocation_source_limit_refuses_before_resolution() {
    let mut limits = default_limits();
    limits.insert("max_resolved_source_files".to_string(), 1);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let resolver = ShallowMapResolver {
        sources: HashMap::from([
            (
                "first.py".to_string(),
                "import os\nos.remove('/first-script')\n".to_string(),
            ),
            (
                "second.py".to_string(),
                "import os\nos.remove('/second-script')\n".to_string(),
            ),
        ]),
        requests: Arc::clone(&requests),
    };
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&Subject::Shell {
            source: "python3 first.py\npython3 second.py".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "/first-script"
            )
    }));
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "/second-script"
            )
    }));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.limit.as_deref() == Some("max_resolved_source_files")
    }));
    assert!(!requests.lock().unwrap().iter().any(|(path, purpose)| {
        path == "second.py" && *purpose == SourcePurpose::InvocationInput
    }));
}

#[test]
fn symbolic_container_cwd_survives_nested_shell_hops() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "docker run -w \"$DIR\" alpine sh -c 'rm x'".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(
        matches!(
            &delete.resource,
            ResourceExpr::Join { parts }
                if matches!(parts.first(), Some(ResourceExpr::Environment { name }) if name == "DIR")
        ),
        "effect: {:#?}\ngraph: {:#?}",
        delete.resource,
        plan.execution_graph
    );
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .filter(|node| !node.realm.is_host())
            .all(|node| matches!(
                &node.cwd,
                Some(ResourceExpr::Environment { name }) if name == "DIR"
            ))
    );
}

#[test]
fn env_flag_with_value_is_skipped() {
    // -u NAME consumes NAME; the command is `rm`.
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(&["env", "-u", "PATH", "rm", "/tmp/a"], Some("/w")))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(ops(&plan).contains(&"filesystem.delete"));
    let nested = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv.first().is_some_and(|arg| arg == "rm")))
        .expect("wrapped command node");
    assert_eq!(nested.environment.get("PATH"), Some(&None));
}

#[test]
fn nested_ssh_replaces_the_outer_remote_realm() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(
            &["ssh", "a", "ssh", "b", "rm", "-rf", "/x"],
            Some("/w"),
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.realm,
        ExecutionRealm::Remote {
            endpoint: "b".to_string()
        }
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.connect")
            .count(),
        2
    );
}

#[test]
fn nested_ssh_obeys_the_execution_depth_limit() {
    let mut limits = default_limits();
    limits.insert("max_execution_depth".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&exec(
            &["ssh", "a", "ssh", "b", "ssh", "c", "rm", "-rf", "/x"],
            Some("/w"),
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_execution_depth"))
    );
}

#[test]
fn nested_depth_limit_ends_in_opaque_boundary() {
    // Deeply nested `sh -c "sh -c ..."` must stop at the depth limit with an
    // opaque nested invocation, never an unbounded recursion or silent stop.
    let mut limits = default_limits();
    limits.insert("max_execution_depth".to_string(), 2);
    let src = "sh -c 'sh -c \"sh -c true\"'";
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: src.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| n.boundary.is_some())
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_execution_depth"))
    );
}

#[test]
fn deterministic_across_runs() {
    let subject = exec(&["sh", "-c", "cp a b && rm c"], Some("/w"));
    let engine = Engine::new().with_causality_detail(true);
    let a = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    let b = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    assert_eq!(a, b);
}

// Missing hooks or unsafe tail quoting would hide real effects or invent shell commands.
#[test]
fn package_script_selection_preserves_hook_order_arguments_and_read_evidence() {
    for argv in [
        vec!["npm", "test", "ignored", "--", "a'b", "; rm /injected"],
        vec!["npm", "run-script", "test", "--", "a'b", "; rm /injected"],
        vec!["npm", "run", "test", "--", "a'b", "; rm /injected"],
        vec!["yarn", "test", "a'b", "; rm /injected"],
        vec!["pnpm", "run", "test", "a'b", "; rm /injected"],
        vec!["bun", "run-script", "test", "a'b", "; rm /injected"],
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(ShallowMapResolver {
                sources: HashMap::from([(
                    "/work/package.json".to_string(),
                    r#"{"scripts":{"pretest":"rm /pre","test":"rm /main","posttest":"rm /post"}}"#
                        .to_string(),
                )]),
                requests: requests.clone(),
            }))
            .analyze(&exec(&argv, Some("/work")))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            *requests.lock().unwrap(),
            vec![(
                "/work/package.json".to_string(),
                SourcePurpose::InvocationInput
            )]
        );
        let edges: Vec<_> = plan
            .execution_graph
            .edges
            .iter()
            .filter(|edge| edge.kind == ExecutionEdgeKind::PackageScript)
            .collect();
        let sources: Vec<_> = edges
            .iter()
            .map(|edge| {
                let node = &plan.execution_graph.nodes[edge.to.0 as usize];
                assert_eq!(node.selected_source_path(), Some("/work/package.json"));
                let Subject::Shell { source, cwd, .. } = &node.subject else {
                    panic!()
                };
                assert_eq!(cwd.as_deref(), Some("/work"));
                source.as_str()
            })
            .collect();
        assert_eq!(
            sources,
            ["rm /pre", "rm /main 'a'\\''b' '; rm /injected'", "rm /post"],
            "{argv:?}"
        );
        let read = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap();
        assert!(edges.iter().all(|edge| {
            read.provenance
                .iter()
                .all(|node| edge.evidence.contains(node))
        }));
        for (edge, name) in edges.iter().zip(["pretest", "test", "posttest"]) {
            assert!(edge.evidence.iter().any(|node| matches!(&plan.provenance[node.0 as usize].kind,
                effinterp_proto::ProvenanceKind::ToolArgument { name: field } if field == &format!("/work/package.json:scripts.{name}"))));
        }
        assert!(!plan.effects.iter().any(|effect| matches!(&effect.resource,
            ResourceExpr::Concrete { identity: effinterp_proto::ResourceIdentity::FsPath {path} } if path == "/injected")));
    }
}

// A built-in collision must not execute a same-named manifest script, while a script-tail
// workspace-looking flag must remain a literal argument to a selected shorthand script.
#[test]
fn package_script_shorthand_respects_builtin_precedence_and_option_position() {
    for manager in ["yarn", "pnpm", "bun"] {
        for tail in [
            "-w",
            "--ignore-scripts",
            "--filter",
            "--filter=app",
            "--cwd",
            "--cwd=app",
            "--dir",
            "--dir=app",
        ] {
            for argv in [
                vec![manager, "lint", tail],
                vec![manager, "run", "lint", tail],
            ] {
                let plan = Engine::new()
                    .with_causality_detail(true)
                    .with_resolver(Box::new(MapResolver(HashMap::from([(
                        "package.json".to_string(),
                        r#"{"scripts":{"lint":"rm /main"}}"#.to_string(),
                    )]))))
                    .analyze(&exec(&argv, None))
                    .unwrap();
                validate_plan(&plan).unwrap();
                let edges: Vec<_> = plan
                    .execution_graph
                    .edges
                    .iter()
                    .filter(|edge| edge.kind == ExecutionEdgeKind::PackageScript)
                    .collect();
                assert_eq!(edges.len(), 1, "{manager} {tail}");
                assert!(matches!(
                    &plan.execution_graph.nodes[edges[0].to.0 as usize].subject,
                    Subject::Shell { source, .. } if source == &format!("rm /main '{tail}'")
                ));
            }
        }
    }

    for (manager, commands) in [
        ("bun", &["test", "build"][..]),
        ("pnpm", &["audit", "why", "pack", "list", "ls"][..]),
        ("yarn", &["cache", "why", "config", "licenses", "pack"][..]),
    ] {
        for command in commands {
            let plan = Engine::new()
                .with_causality_detail(true)
                .with_resolver(Box::new(MapResolver(HashMap::from([(
                    "package.json".to_string(),
                    serde_json::json!({"scripts": {*command: "rm /must-not-run"}}).to_string(),
                )]))))
                .analyze(&exec(&[manager, command], None))
                .unwrap();
            validate_plan(&plan).unwrap();
            assert!(
                !plan
                    .execution_graph
                    .edges
                    .iter()
                    .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript),
                "{manager} {command}"
            );
            let boundary = plan
                .boundaries
                .iter()
                .find(|boundary| boundary.reason.as_str() == "unmodeled_subcommand")
                .unwrap();
            for domain in ["filesystem", "network", "process"] {
                assert!(boundary.domains.contains(&Domain::new(domain)));
                assert_eq!(
                    plan.coverage
                        .0
                        .get(&Domain::new(domain))
                        .map(|claim| &claim.level),
                    Some(&CoverageLevel::Partial)
                );
            }
        }
    }

    for (manager, command) in [("bun", "test"), ("bun", "build"), ("pnpm", "ls")] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "package.json".to_string(),
                serde_json::json!({"scripts": {command: "rm /main"}}).to_string(),
            )]))))
            .analyze(&exec(&[manager, "run", command], None))
            .unwrap();
        assert!(
            plan.execution_graph
                .edges
                .iter()
                .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript),
            "{manager} run {command}"
        );
    }
}

#[test]
fn package_scripts_refuse_invalid_manifests_workspace_selection_and_absent_sources() {
    for manifest in [
        "[]",
        "null",
        "invalid",
        r#"{"scripts":{"pretest":"rm /pre"}}"#,
        r#"{"scripts":{"test":false,"pretest":"rm /pre"}}"#,
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "package.json".to_string(),
                manifest.to_string(),
            )]))))
            .analyze(&exec(&["npm", "test"], None))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_package_script")
        );
        assert!(
            !plan
                .execution_graph
                .edges
                .iter()
                .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript)
        );
        assert!(ops(&plan).contains(&"filesystem.read"));
    }
    for argv in [
        &["npm", "-w", "app", "run", "test"][..],
        &["npm", "run", "test", "--workspaces"][..],
        &["pnpm", "-r", "run", "test"][..],
        &["pnpm", "run", "--filter", "app", "test"][..],
        &["pnpm", "run", "--filter=app", "test"][..],
        &["bun", "run", "--filter", "app", "test"][..],
        &["bun", "run", "--filter=app", "test"][..],
        &["bun", "run", "--parallel", "--filter", "app", "test"][..],
        &["bun", "run", "--if-present", "test"][..],
        &["pnpm", "--filter=app", "test"][..],
        &["pnpm", "-w", "test"][..],
        &["yarn", "workspace", "app", "test"][..],
        &["yarn", "workspaces", "run", "test"][..],
        &["bun", "--filter", "app", "run", "test"][..],
    ] {
        let plan = Engine::new().with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "package.json".to_string(),
                r#"{"scripts":{"test":"rm /root","--filter":"rm /wrong","--filter=app":"rm /wrong","app":"rm /wrong","--if-present":"rm /wrong"}} "#.to_string(),
            )]))))
            .analyze(&exec(argv, None)).unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            !plan
                .execution_graph
                .edges
                .iter()
                .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript),
            "{argv:?}"
        );
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
                .any(|b| b.reason.as_str() == "unresolved_package_script"
                    && b.detail.as_deref() == Some("workspace/lifecycle selection is not modeled")),
            "{argv:?}"
        );
    }
    // npm and pnpm's `--if-present` runs a present script as usual and makes
    // a missing one a no-op.
    for (argv, followed) in [
        (&["pnpm", "run-script", "--if-present", "test"][..], true),
        (&["npm", "run", "test", "--if-present"][..], true),
        (&["npm", "run", "absent", "--if-present"][..], false),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "package.json".to_string(),
                r#"{"scripts":{"test":"rm /root","--if-present":"rm /wrong"}}"#.to_string(),
            )]))))
            .analyze(&exec(argv, None))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            plan.execution_graph
                .edges
                .iter()
                .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript),
            followed,
            "{argv:?}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_package_script"),
            "{argv:?}"
        );
    }
    for argv in [
        &["npm", "test"][..],
        &["bun", "run", "test"][..],
        &["npm", "run"][..],
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&exec(argv, None))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_package_script"
                    && b.class == effinterp_proto::BoundaryClass::Unresolved)
        );
    }
}

#[test]
fn package_install_verbs_never_select_named_scripts() {
    for manager in ["npm", "yarn", "pnpm", "bun"] {
        for verb in [
            "install",
            "i",
            "add",
            "remove",
            "rm",
            "uninstall",
            "upgrade",
            "update",
            "up",
            "link",
            "unlink",
            "publish",
            "init",
            "create",
            "exec",
            "dlx",
            "x",
            "",
        ] {
            let plan = Engine::new()
                .with_causality_detail(true)
                .with_resolver(Box::new(MapResolver(HashMap::from([(
                    "package.json".to_string(),
                    serde_json::json!({"scripts": {verb: "rm /must-not-run"}}).to_string(),
                )]))))
                .analyze(&exec(&[manager, verb], None))
                .unwrap();
            assert!(
                !plan
                    .execution_graph
                    .edges
                    .iter()
                    .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript),
                "{manager} {verb}"
            );
        }
    }
}

#[test]
fn package_runner_exec_modes_launch_their_child() {
    let child = |plan: &effinterp_proto::Plan, argv: &[&str]| {
        plan.execution_graph
            .edges
            .iter()
            .find(|edge| {
                matches!(&plan.execution_graph.nodes[edge.to.0 as usize].subject,
                    Subject::Exec { argv: child, .. } if child == argv)
            })
            .cloned()
    };
    let inferred = |plan: &effinterp_proto::Plan, edge: &effinterp_proto::ExecutionEdge| {
        edge.evidence.iter().any(|node| {
            matches!(&plan.provenance[node.0 as usize].kind,
                effinterp_proto::ProvenanceKind::ModelApplication { model }
                    if model == effinterp_engine::PACKAGE_BINARY_INFERENCE_MODEL)
        })
    };
    let analyze = |argv: &[&str]| {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&exec(argv, Some("/work")))
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    // Only a package operand, never a command named beside `--package`, is
    // certified as the package the child's binary comes from. Yarn Classic
    // forwards the words after `--`; pnpm drops one `--` after `exec`.
    for (argv, launched, from_package) in [
        (
            &["npm", "exec", "--", "@scope/pkg", "run"][..],
            &["@scope/pkg", "run"][..],
            true,
        ),
        (&["npm", "x", "-y", "pkg"][..], &["pkg"][..], true),
        (
            &[
                "npm",
                "exec",
                "--package=@scope/pkg",
                "--",
                "tool",
                "--flag",
            ][..],
            &["tool", "--flag"][..],
            false,
        ),
        (
            &["yarn", "dlx", "@scope/pkg"][..],
            &["@scope/pkg"][..],
            true,
        ),
        (
            &["yarn", "dlx", "-p", "@scope/pkg", "tool"][..],
            &["tool"][..],
            false,
        ),
        (
            &["yarn", "exec", "tool", "a", "--", "--flag"][..],
            &["tool", "a", "--flag"][..],
            false,
        ),
        (
            &["yarn", "exec", "--", "tool", "--flag"][..],
            &["tool", "--flag"][..],
            false,
        ),
        (
            &["pnpm", "exec", "tool", "--flag"][..],
            &["tool", "--flag"][..],
            false,
        ),
        (
            &["pnpm", "exec", "--", "tool", "-c"][..],
            &["tool", "-c"][..],
            false,
        ),
        (
            &["pnpm", "exec", "-c", "tool"][..],
            &["-c", "tool"][..],
            false,
        ),
        (&["bun", "--cwd=sub", "x", "tool"][..], &["tool"][..], true),
        // A registry spec of a reviewed package runs its binary; any other
        // spec keeps the operand, since a package's name need not be its
        // binary's (typescript runs tsc, uglify-js runs uglifyjs).
        (
            &["npx", "-y", "rimraf@5", "a"][..],
            &["rimraf", "a"][..],
            true,
        ),
        (&["pnpm", "dlx", "rimraf@latest"][..], &["rimraf"][..], true),
        (&["bunx", "rimraf@>=5 <7"][..], &["rimraf"][..], true),
        (
            &["bunx", "typescript@5.0.4", "a.ts"][..],
            &["typescript@5.0.4", "a.ts"][..],
            true,
        ),
        (
            &["npx", "uglify-js@3.14.0"][..],
            &["uglify-js@3.14.0"][..],
            true,
        ),
        (&["bunx", "@scope/pkg@1"][..], &["@scope/pkg@1"][..], true),
        // npm exec and pnpx select a reviewed binary as npx does; npx's `-p`
        // is `--package`, so the word after it is an explicit command.
        (
            &["npm", "exec", "--", "rimraf@5", "a"][..],
            &["rimraf", "a"][..],
            true,
        ),
        (&["pnpx", "rimraf@latest"][..], &["rimraf"][..], true),
        (
            &["npx", "-p", "@scope/pkg", "tool"][..],
            &["tool"][..],
            false,
        ),
    ] {
        let plan = analyze(argv);
        let edge = child(&plan, launched).unwrap_or_else(|| panic!("{argv:?}"));
        assert_eq!(inferred(&plan, &edge), from_package, "{argv:?}");
        // `bun --cwd=DIR x` still launches from the original cwd.
        assert_eq!(
            plan.execution_graph.nodes[edge.to.0 as usize].cwd,
            Some(ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath {
                    path: "/work".into()
                }
            }),
            "{argv:?}"
        );
    }
    // A package's binary comes from its manifest, which is not observed: the
    // operand is neither a path nor a modeled program, so `@scope/rm` whose
    // bin is anything but rm deletes nothing.
    for argv in [
        &["npm", "exec", "--", "@scope/rm", "/x"][..],
        &["yarn", "dlx", "rm", "/x"][..],
        &["npx", "@scope/rm@1", "/x"][..],
        &["bun", "x", "npm:rm@1", "/x"][..],
        // Git shorthand and a local path after a reviewed name select
        // another package entirely.
        &["npx", "rimraf@mishoo/UglifyJS#v3.14.0", "/x"][..],
        &["pnpm", "dlx", "rimraf@./tools/report-only", "/x"][..],
        // rimraf 1.0.0 through 2.1.4 declare no binary, and a selector that
        // is neither a valid range nor a reviewed tag establishes no release.
        &["npx", "rimraf@1.0.0", "/x"][..],
        &["bunx", "rimraf@~2.1", "/x"][..],
        &["npx", "rimraf@>garbage", "/x"][..],
        &["pnpm", "dlx", "rimraf@next", "/x"][..],
        &["npm", "exec", "--", "rimraf@1.0.0", "/x"][..],
        &["yarn", "dlx", "rimraf@next", "/x"][..],
        &["pnpx", "@scope/rm", "/x"][..],
        // pnpm dlx runs the installed package's binary, never a same-named
        // program on PATH: the `rm` package declares none.
        &["pnpx", "rm", "-rf", "/x"][..],
        &["pnpm", "dlx", "rm", "/x"][..],
        // Without a `packageManager` pin, `yarn dlx` may be Classic's
        // project script `dlx`.
        &["yarn", "dlx", "rimraf", "/x"][..],
        // A component above node-semver's MAX_SAFE_INTEGER is not a version,
        // and its successor must not overflow the analysis.
        &["npx", "rimraf@18446744073709551615", "/x"][..],
        &["npx", "rimraf@5.18446744073709551615", "/x"][..],
        &["npx", "rimraf@^0.0.18446744073709551615", "/x"][..],
        &["npx", "rimraf@9007199254740992", "/x"][..],
    ] {
        let plan = analyze(argv);
        assert!(!ops(&plan).contains(&"filesystem.delete"), "{argv:?}");
        assert!(!ops(&plan).contains(&"filesystem.read"), "{argv:?}");
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_command"
                    && b.detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("is not established"))),
            "{argv:?}"
        );
    }
    // pnpm stops parsing its options at `dlx`: a later `--package` word is
    // the package operand, and the command after it is not launched.
    for argv in [
        &["pnpx", "--package=rimraf", "rimraf", "/x"][..],
        &["pnpm", "dlx", "--package=rimraf", "rimraf", "/x"][..],
    ] {
        let plan = analyze(argv);
        assert!(child(&plan, &["rimraf", "/x"]).is_none(), "{argv:?}");
        assert!(!ops(&plan).contains(&"filesystem.delete"), "{argv:?}");
    }
    // A `packageManager` pin does not establish which yarn runs, so it only
    // adds readings: a Berry pin establishes the reviewed binary, a Classic
    // pin adds the project script `dlx` beside the package launch, and an
    // invalid pin adds nothing.
    let yarn = |pin: &str, argv: &[&str]| {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "package.json".to_string(),
                serde_json::json!({"packageManager": pin, "scripts": {"dlx": "true"}}).to_string(),
            )]))))
            .analyze(&exec(argv, None))
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    let script = |plan: &effinterp_proto::Plan| {
        plan.execution_graph
            .edges
            .iter()
            .any(|edge| edge.kind == ExecutionEdgeKind::PackageScript)
    };
    let berry = yarn("yarn@4.5.0", &["yarn", "dlx", "rimraf", "/x"]);
    let edge = child(&berry, &["rimraf", "/x"]).unwrap();
    assert!(inferred(&berry, &edge));
    assert!(ops(&berry).contains(&"filesystem.delete"));
    // node-semver refuses a core number above MAX_SAFE_INTEGER and a version
    // longer than 256 characters, so neither establishes a generation.
    for pin in [
        "yarn@1.22.22".to_string(),
        "yarn@1.garbage".to_string(),
        "yarn@4.9007199254740992.0".to_string(),
        "yarn@1.9007199254740992.0".to_string(),
        format!("yarn@4.0.0-{}", "a".repeat(251)),
        format!("yarn@1.0.0-{}", "a".repeat(251)),
    ] {
        let pin = pin.as_str();
        let plan = yarn(pin, &["yarn", "dlx", "rimraf", "/x"]);
        let edge = child(&plan, &["rimraf", "/x"]).unwrap_or_else(|| panic!("{pin}"));
        assert!(inferred(&plan, &edge), "{pin}");
        assert!(!ops(&plan).contains(&"filesystem.delete"), "{pin}");
        assert_eq!(script(&plan), pin == "yarn@1.22.22", "{pin}");
    }
    // A Classic pin with Berry running keeps the explicit command.
    let classic = yarn("yarn@1.22.22", &["yarn", "dlx", "-p", "@scope/pkg", "tool"]);
    assert!(script(&classic));
    let edge = child(&classic, &["tool"]).unwrap();
    assert!(!inferred(&classic, &edge));
    // A workspace selector runs the child where Nah cannot name, including a
    // call body's relative paths.
    for (argv, launched) in [
        (
            &["npm", "exec", "--workspace=web", "--", "tool"][..],
            Some(&["tool"][..]),
        ),
        (&["pnpm", "-r", "exec", "tool"][..], Some(&["tool"][..])),
        (&["npm", "exec", "-w", "web", "-c", "rm relative"][..], None),
    ] {
        let plan = analyze(argv);
        if let Some(launched) = launched {
            let edge = child(&plan, launched).unwrap_or_else(|| panic!("{argv:?}"));
            assert!(
                !matches!(
                    plan.execution_graph.nodes[edge.to.0 as usize].cwd,
                    Some(ResourceExpr::Concrete { .. })
                ),
                "{argv:?}"
            );
        } else {
            let delete = plan
                .effects
                .iter()
                .find(|e| e.operation.0 == "filesystem.delete")
                .unwrap();
            assert!(
                !serde_json::to_string(&delete.resource)
                    .unwrap()
                    .contains("/work"),
                "{argv:?}"
            );
        }
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_package_script"),
            "{argv:?}"
        );
    }
    // A call body runs in a shell; with `--package` the runner installs the
    // packages before it.
    for (argv, installs) in [
        (&["npm", "exec", "-c", "rm /x"][..], false),
        (&["pnpm", "-c", "exec", "rm", "/x"][..], false),
        (&["npm", "exec", "--package=x", "-c", "rm /x"][..], true),
        (&["pnpm", "--package=x", "-c", "dlx", "rm", "/x"][..], true),
    ] {
        let plan = analyze(argv);
        assert!(ops(&plan).contains(&"filesystem.delete"), "{argv:?}");
        assert_eq!(
            ops(&plan).contains(&"network.download"),
            installs,
            "{argv:?}"
        );
    }
    // `pnpm -C DIR exec` runs the child from DIR.
    let plan = analyze(&["pnpm", "-C", "sub", "exec", "tool"]);
    let edge = child(&plan, &["tool"]).unwrap();
    assert_eq!(
        plan.execution_graph.nodes[edge.to.0 as usize].cwd,
        Some(ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath {
                path: "/work/sub".into()
            }
        })
    );
    // npm reads an option after the command as its own without `--`; Yarn
    // Classic reads options before `--` and lets an unknown one take the next
    // word; pnpm reads the words after `dlx` as the command, so `-c` there
    // names a package; Bun's separated `--cwd` leaves `x` a script name. No
    // child is planned.
    for argv in [
        &["npm", "exec", "eslint", "--fix"][..],
        &["yarn", "exec", "tool", "--disable", "hooks"][..],
        &["pnpm", "dlx", "-c", "rm /x"][..],
        &["bun", "--cwd", "sub", "x", "tool"][..],
    ] {
        let plan = analyze(argv);
        assert_eq!(plan.execution_graph.nodes.len(), 1, "{argv:?}");
    }
    // `bun --cwd=DIR run` runs the script from DIR's manifest; the separated
    // spelling runs no script. Script shorthand moves with either spelling.
    for (argv, runs) in [
        (&["bun", "--cwd=sub", "run", "test"][..], true),
        (&["bun", "--cwd", "sub", "run", "test"][..], false),
        (&["bun", "--cwd", "sub", "lint"][..], true),
        (&["bun", "--cwd=sub", "lint"][..], true),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([
                (
                    "work/package.json".to_string(),
                    r#"{"scripts":{"test":"rm /root","lint":"rm /root"}}"#.to_string(),
                ),
                (
                    "work/sub/package.json".to_string(),
                    r#"{"scripts":{"test":"rm /moved","lint":"rm /moved"}}"#.to_string(),
                ),
            ]))))
            .analyze(&exec(argv, Some("work")))
            .unwrap();
        validate_plan(&plan).unwrap();
        let effects = serde_json::to_string(&plan.effects).unwrap();
        assert_eq!(effects.contains("/moved"), runs, "{argv:?}");
        assert!(!effects.contains("/root"), "{argv:?}");
    }
}

#[test]
fn npm_start_default_nests_node_and_keeps_hooks() {
    for name in ["start", "stop", "restart"] {
        let manifest = if name == "start" {
            r#"{"scripts":{"prestart":"rm /pre","poststart":"rm /post"}}"#.to_string()
        } else {
            serde_json::json!({"scripts": {name: "rm /main"}}).to_string()
        };
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([
                ("package.json".to_string(), manifest),
                (
                    "server.js".to_string(),
                    "require('fs').unlinkSync('/server-output')".to_string(),
                ),
            ]))))
            .analyze(&exec(&["npm", name], None))
            .unwrap();
        validate_plan(&plan).unwrap();
        let edges: Vec<_> = plan
            .execution_graph
            .edges
            .iter()
            .filter(|edge| edge.kind == ExecutionEdgeKind::PackageScript)
            .collect();
        assert_eq!(edges.len(), if name == "start" { 3 } else { 1 });
        if name == "start" {
            assert!(
                matches!(&plan.execution_graph.nodes[edges[1].to.0 as usize].subject, Subject::Exec { argv, .. } if argv == &["node", "server.js"])
            );
            assert!(plan.effects.iter().any(|e| {
                e.operation.0 == "filesystem.delete"
                    && serde_json::to_string(&e.resource)
                        .unwrap()
                        .contains("/server-output")
            }));
        }
    }
}

#[test]
fn make_read_evidence_and_refusals_preserve_selected_target_identity() {
    for (command, detail) in [
        ("@-+$(MAKE) -C sub", "recursive make is not followed"),
        ("${MAKE} -C sub", "recursive make is not followed"),
        ("make -C sub", "recursive make is not followed"),
        ("gmake -C sub", "recursive make is not followed"),
        ("rm $(VAR)", "expansion $(VAR)"),
        ("${HEAD} /x", "expansion ${HEAD}"),
        ("rm $@", "expansion $@"),
        ("rm $<", "expansion $<"),
        ("rm $^", "expansion $^"),
        ("rm $*", "expansion $*"),
        ("rm /x \\\n\t /y", "continuation"),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "work/sub/custom.mk".to_string(),
                format!("deploy:\n\t{command}\n\trm /safe\n"),
            )]))))
            .analyze(&exec(
                &["make", "-C", "sub", "-f", "custom.mk", "deploy"],
                Some("work"),
            ))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_build_target"
                    && b.detail.as_deref().unwrap_or("").contains(detail)),
            "{command}"
        );
        let edges: Vec<_> = plan
            .execution_graph
            .edges
            .iter()
            .filter(|edge| edge.kind == ExecutionEdgeKind::BuildTarget)
            .collect();
        assert_eq!(edges.len(), 1, "{command}");
        let read = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap();
        assert!(
            read.provenance
                .iter()
                .all(|node| edges[0].evidence.contains(node))
        );
        assert!(
            serde_json::to_string(&read.resource)
                .unwrap()
                .contains("custom.mk")
        );
        assert!(edges[0].evidence.iter().any(|node| matches!(&plan.provenance[node.0 as usize].kind,
            effinterp_proto::ProvenanceKind::ToolArgument { name } if name.ends_with("custom.mk:deploy"))));
    }
}

#[test]
fn package_and_make_input_refusals_keep_typed_boundaries() {
    struct RefusalResolver(SourceRefusal);
    impl SourceResolver for RefusalResolver {
        fn source_mutation_disjoint(
            &self,
            _: &effinterp_proto::ResourceExpr,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> bool {
            true
        }

        fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
            assert_eq!(request.purpose, SourcePurpose::InvocationInput);
            SourceResponse::Refused(self.0)
        }
        fn siblings(&self, _path: &str) -> Option<Vec<String>> {
            None
        }
    }
    for argv in [&["npm", "test"][..], &["make", "deploy"][..]] {
        for refusal in [
            SourceRefusal::Unavailable(UnavailableReason::NamespaceDenied),
            SourceRefusal::Limit {
                limit: "max_source_bytes",
            },
        ] {
            let plan = Engine::new()
                .with_causality_detail(true)
                .with_resolver(Box::new(RefusalResolver(refusal)))
                .analyze(&exec(argv, Some("/work")))
                .unwrap();
            validate_plan(&plan).unwrap();
            let reason = if matches!(refusal, SourceRefusal::Limit { .. }) {
                "limit_saturated"
            } else if argv[0] == "make" {
                "unresolved_build_target"
            } else {
                "unresolved_package_script"
            };
            assert!(
                plan.boundaries
                    .iter()
                    .any(|boundary| boundary.reason.as_str() == reason
                        && if reason == "limit_saturated" {
                            boundary.limit.as_deref() == Some("max_source_bytes")
                        } else {
                            boundary
                                .detail
                                .as_deref()
                                .unwrap()
                                .contains("namespace_denied")
                        })
            );
        }
    }
}

#[test]
fn selected_input_content_tracks_exact_admitted_bytes_and_refusals() {
    use effinterp_proto::{
        ExecutionContent, ExecutionInputReason, ExecutionInputRole, content_digest,
    };
    struct Resolver {
        response: SourceResponse,
        requests: Arc<Mutex<Vec<String>>>,
    }
    impl SourceResolver for Resolver {
        fn source_mutation_disjoint(
            &self,
            _: &effinterp_proto::ResourceExpr,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> bool {
            true
        }

        fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
            self.requests.lock().unwrap().push(request.path.to_string());
            self.response.clone()
        }
        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    for bytes in [
        b"import os\nos.remove('/direct')\n".to_vec(),
        b"\xef\xbb\xbfprint('bom')\r\n".to_vec(),
        vec![0, 255, 128],
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(Resolver {
                response: SourceResponse::Source(bytes.clone()),
                requests: requests.clone(),
            }))
            .analyze(&exec(&["python3", "/main.py"], Some("/")))
            .unwrap();
        let node = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some("/main.py"))
            .unwrap();
        let input = node.input.as_ref().unwrap();
        assert_eq!(input.role, ExecutionInputRole::ExplicitInvocation);
        assert_eq!(input.requester_component, "python3");
        assert_eq!(
            input.content,
            ExecutionContent::Observed {
                digest: content_digest(&bytes)
            }
        );
        assert_eq!(requests.lock().unwrap().as_slice(), &["/main.py"]);
        match String::from_utf8(bytes) {
            Ok(source) => assert!(
                matches!(&node.subject, Subject::Source { language, source: analyzed, .. } if language == "python" && *analyzed == source)
            ),
            Err(_) => assert_eq!(
                plan.boundaries[node.boundary.unwrap().0 as usize].reason,
                effinterp_proto::BoundaryReason::UNSUPPORTED_SOURCE
            ),
        }
    }
    for (refusal, expected) in [
        (
            SourceRefusal::Unavailable(UnavailableReason::Missing),
            ExecutionInputReason::Missing,
        ),
        (
            SourceRefusal::Unavailable(UnavailableReason::Escapes),
            ExecutionInputReason::Escapes,
        ),
        (
            SourceRefusal::Unavailable(UnavailableReason::NamespaceDenied),
            ExecutionInputReason::NamespaceDenied,
        ),
        (
            SourceRefusal::Unavailable(UnavailableReason::Stale),
            ExecutionInputReason::Stale,
        ),
        (
            SourceRefusal::Unavailable(UnavailableReason::Mismatched),
            ExecutionInputReason::Mismatched,
        ),
        (
            SourceRefusal::Unavailable(UnavailableReason::Ambiguous),
            ExecutionInputReason::Ambiguous,
        ),
        (
            SourceRefusal::Limit {
                limit: "max_source_bytes",
            },
            ExecutionInputReason::Oversize,
        ),
        (
            SourceRefusal::Limit {
                limit: "max_resolved_source_files",
            },
            ExecutionInputReason::BudgetRefused {
                limit: "max_resolved_source_files".to_string(),
            },
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(Resolver {
                response: SourceResponse::Refused(refusal),
                requests: Default::default(),
            }))
            .analyze(&exec(&["python3", "/main.py"], Some("/")))
            .unwrap();
        let node = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some("/main.py"))
            .unwrap();
        assert!(node.boundary.is_some());
        assert_eq!(
            node.input.as_ref().unwrap().content,
            ExecutionContent::Unobserved { reason: expected }
        );
    }
    // A resolver cannot bypass the byte cap; a file-count refusal happens before opening.
    for (byte_cap, file_cap, expected, calls) in [
        (2, 8, ExecutionInputReason::Oversize, 1),
        (
            1024,
            0,
            ExecutionInputReason::BudgetRefused {
                limit: "max_resolved_source_files".to_string(),
            },
            0,
        ),
    ] {
        let mut limits = default_limits();
        limits.insert("max_source_bytes".to_string(), byte_cap);
        limits.insert("max_resolved_source_files".to_string(), file_cap);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let plan = Engine::with_limits(limits)
            .unwrap()
            .with_causality_detail(true)
            .with_resolver(Box::new(Resolver {
                response: SourceResponse::Source(b"true".to_vec()),
                requests: requests.clone(),
            }))
            .analyze(&exec(&["sh", "/main.sh"], Some("/")))
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        let input = plan
            .execution_graph
            .nodes
            .iter()
            .find_map(|node| node.input.as_ref())
            .unwrap();
        assert_eq!(
            input.content,
            ExecutionContent::Unobserved { reason: expected }
        );
        assert_eq!(requests.lock().unwrap().len(), calls);
    }
    let native_bytes = b"\x7fELF\0native".to_vec();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let native = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(Resolver {
            response: SourceResponse::Source(native_bytes.clone()),
            requests: requests.clone(),
        }))
        .analyze(&exec(&["/native"], Some("/")))
        .unwrap();
    effinterp_proto::validate_plan(&native).unwrap();
    let native_input = native
        .execution_graph
        .nodes
        .iter()
        .find(|node| node.selected_source_path() == Some("/native"))
        .unwrap();
    assert_eq!(
        native_input.input.as_ref().unwrap().content,
        ExecutionContent::Observed {
            digest: content_digest(&native_bytes)
        }
    );
    assert_eq!(
        native.boundaries[native_input.boundary.unwrap().0 as usize].reason,
        effinterp_proto::BoundaryReason::UNSUPPORTED_SOURCE
    );
    assert_eq!(requests.lock().unwrap().as_slice(), &["/native"]);
    let inline = Engine::new()
        .with_causality_detail(true)
        .analyze(&exec(&["python3", "-c", "print('inline')"], None))
        .unwrap();
    assert!(inline.execution_graph.nodes.iter().all(|node| {
        node.input
            .as_ref()
            .is_none_or(|input| !matches!(input.content, ExecutionContent::Observed { .. }))
    }));
}

#[test]
fn runtime_selected_shell_input_follows_explicit_source_invocations() {
    use effinterp_proto::{
        ExecutionContent, ExecutionInputRole, ExecutionPhase, OccurrenceKind, Port,
    };
    let source = "echo x > /ambient-effect; . /deep.sh";
    let mut subject = exec(&["bash", "-c", "true"], Some("/"));
    let Subject::Exec { context, .. } = &mut subject else {
        unreachable!()
    };
    context
        .env
        .insert("BASH_ENV".to_string(), "/ambient.sh".to_string());
    context.env.insert("SHELLOPTS".into(), "xtrace".into());
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([
            ("ambient.sh".to_string(), source.to_string()),
            ("deep.sh".to_string(), "rm /deeper-effect".to_string()),
        ]))))
        .analyze(&subject)
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    let (index, selected) = plan
        .execution_graph
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.selected_source_path() == Some("/ambient.sh"))
        .unwrap();
    let input = selected.input.as_ref().unwrap();
    assert_eq!(input.role, ExecutionInputRole::UnexpectedSelected);
    assert_eq!(input.phase, ExecutionPhase::Startup);
    assert_eq!(input.requester_component, "bash");
    assert_eq!(
        input.content,
        ExecutionContent::Observed {
            digest: effinterp_proto::content_digest(source.as_bytes())
        }
    );
    assert!(
        plan.execution_graph
            .edges
            .iter()
            .any(|edge| edge.to.0 as usize == index && edge.kind == ExecutionEdgeKind::Startup)
    );
    assert!(plan.effects.iter().any(|effect| {
        effinterp_proto::display_resource(&effect.resource).contains("deeper-effect")
    }));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.selected_source_path() == Some("/deep.sh")
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::ExplicitInvocation
                    && matches!(input.content, ExecutionContent::Observed { .. })
            })
            && node.boundary.is_none()
    }));
    let graph = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required");
    let read = graph.nodes.iter().find(|node| matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. } if operation.as_str() == "filesystem.read" && effinterp_proto::display_resource(resource).contains("ambient.sh"))).unwrap();
    let mut reached = std::collections::BTreeSet::from([read.id.clone()]);
    loop {
        let before = reached.len();
        for edge in &graph.edges {
            if reached.contains(&edge.from) {
                reached.insert(edge.to.clone());
            }
        }
        if reached.len() == before {
            break;
        }
    }
    assert!(graph.nodes.iter().any(|node| {
        reached.contains(&node.id)
            && node
                .execution
                .is_some_and(|execution| execution.0 as usize == index)
            && matches!(node.occurrence, OccurrenceKind::Port { port: Port::Code })
    }));
    assert!(graph.nodes.iter().any(|node| reached.contains(&node.id) && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. } if operation.as_str() == "filesystem.write" && effinterp_proto::display_resource(resource).contains("ambient-effect"))));
    for argv in [vec!["bash", "-p", "-c", "true"], vec!["sh", "-c", "true"]] {
        let mut excluded = exec(&argv, Some("/"));
        let Subject::Exec { context, .. } = &mut excluded else {
            unreachable!()
        };
        context
            .env
            .insert("BASH_ENV".to_string(), "/ambient.sh".to_string());
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&excluded)
            .unwrap();
        assert!(plan.execution_graph.nodes.iter().all(|node| {
            node.input
                .as_ref()
                .is_none_or(|input| input.role != ExecutionInputRole::UnexpectedSelected)
        }));
    }
    let ambiguous = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "BASH_ENV=\"$UNKNOWN\" bash -c true".to_string(),
            cwd: Some("/".to_string()),
            context: effinterp_proto::HostContext {
                env: std::collections::BTreeMap::from([(
                    "BASH_ENV".to_string(),
                    "/ambient.sh".to_string(),
                )]),
                ..Default::default()
            },
        })
        .unwrap();
    effinterp_proto::validate_plan(&ambiguous).unwrap();
    assert!(
        ambiguous
            .execution_graph
            .nodes
            .iter()
            .any(|node| node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::UnexpectedSelected
                    && matches!(
                        input.content,
                        ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::Ambiguous
                        }
                    )
            }))
    );
}

#[test]
fn per_call_resolver_does_not_leak_into_later_calls() {
    let engine = Engine::new().with_causality_detail(true);
    let subject = Subject::Shell {
        source: "bash script.sh".into(),
        cwd: Some("/work".into()),
        context: Default::default(),
    };
    let resolver = MapResolver(HashMap::from([(
        "work/script.sh".into(),
        "rm -rf /tmp/x".into(),
    )]));
    let deletes_x = |plan: &effinterp_proto::Plan| {
        plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "/tmp/x")
        })
    };
    let resolved = engine.analyze_with_resolver(&subject, &resolver).unwrap();
    assert!(deletes_x(&resolved));
    assert!(resolved.execution_graph.nodes.len() > 1);
    let (with_stats, _) = engine
        .analyze_with_resolver_stats(&subject, &resolver)
        .unwrap();
    assert_eq!(
        effinterp_proto::canonical_json(&resolved),
        effinterp_proto::canonical_json(&with_stats)
    );
    let unresolved = engine.analyze(&subject).unwrap();
    assert!(!deletes_x(&unresolved));
    assert!(unresolved.boundaries.iter().any(|boundary| {
        matches!(
            boundary.reason.as_str(),
            "unrecoverable_source" | "dynamic_source"
        )
    }));
    assert_eq!(
        effinterp_proto::canonical_json(&unresolved),
        effinterp_proto::canonical_json(
            &Engine::new()
                .with_causality_detail(true)
                .analyze(&subject)
                .unwrap()
        )
    );

    let owned = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "work/script.sh".into(),
            "true".into(),
        )]))));
    let before = owned.analyze(&subject).unwrap();
    assert!(deletes_x(
        &owned.analyze_with_resolver(&subject, &resolver).unwrap()
    ));
    assert_eq!(
        effinterp_proto::canonical_json(&before),
        effinterp_proto::canonical_json(&owned.analyze(&subject).unwrap())
    );
}

#[test]
fn refused_nested_fanout_restores_outer_context_for_sibling() {
    // A child saturates after entering a different realm, cwd, and environment.
    // Its following host sibling must still resolve the outer environment and cwd.
    let mut limits = default_limits();
    limits.insert("max_execution_fanout".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "docker run --rm -e DEST=inner -w /inside image sh -c 'rm first; rm second; rm refused'; rm \"$DEST\"".to_string(),
            cwd: Some("/outside".to_string()),
            context: effinterp_proto::HostContext {
                env: std::collections::BTreeMap::from([("DEST".to_string(), "outer".to_string())]),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let graph = &plan.execution_graph;
    let refused = graph.nodes.iter().find(|node| {
        matches!(&node.subject, Subject::Exec { argv, .. } if argv == &["rm", "refused"])
    }).unwrap();
    assert_eq!(
        plan.boundaries[refused.boundary.unwrap().0 as usize]
            .limit
            .as_deref(),
        Some("max_execution_fanout")
    );
    assert!(!refused.realm.is_host());
    assert_eq!(
        refused.cwd,
        Some(ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath {
                path: "/inside".to_string()
            },
        })
    );
    assert_eq!(
        refused.environment.get("DEST"),
        Some(&Some(ResourceExpr::Literal {
            value: "inner".to_string()
        }))
    );
    let sibling = graph
        .nodes
        .iter()
        .find(
            |node| node.realm.is_host() && matches!(&node.subject, Subject::Exec { argv, .. } if argv.first().is_some_and(|head| head == "rm")),
        )
        .unwrap();
    assert!(sibling.boundary.is_none());
    assert!(sibling.realm.is_host());
    assert_eq!(
        sibling.cwd,
        Some(ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath {
                path: "/outside".to_string()
            },
        })
    );
    assert_eq!(
        sibling.environment.get("DEST"),
        Some(&Some(ResourceExpr::Literal {
            value: "outer".to_string()
        }))
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effect.realm.is_host()
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if path == "/outside/outer")
    }));
}

#[test]
fn source_pattern_parent_cancels_one_component_wildcard() {
    let files = HashMap::from([
        ("lib/x.sh".into(), "rm -rf /top".into()),
        ("lib/sub/x.sh".into(), "rm -rf /sub-invented".into()),
        ("lib/other/x.sh".into(), "rm -rf /other-invented".into()),
    ]);
    let plan = Engine::new()
        .with_resolver(Box::new(MapResolver(files)))
        .analyze(&Subject::Shell {
            source: r#"source "lib/${A}/../x.sh""#.into(),
            cwd: Some("".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_source")
    );
    let deleted: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource(&effect.resource))
        .collect();
    assert_eq!(deleted, ["fs:/top"]);
}

#[test]
fn source_patterns_dispatch_only_defining_alternatives_and_bound_the_search() {
    let files = HashMap::from([
        (
            "lib/util.sh".into(),
            "util-setup(){ touch /tmp/util-marker; }; homebrew-util(){ touch /tmp/only-util; }".into(),
        ),
        (
            "lib/cmd/clean.sh".into(),
            "cat \"$1\"; shift; homebrew-clean(){ rm -rf /tmp/cache; }; shared(){ touch /clean; }"
                .into(),
        ),
        (
            "alt/cmd/list.sh".into(),
            "cat \"$1\"; shift; homebrew-list(){ ls /Cellar; }".into(),
        ),
        (
            "lib/cmd/update.sh".into(),
            "cat \"$1\"; shift; source \"${LIB_ROOT}/helpers/extra.sh\"; homebrew-update(){ git fetch origin; }; shared(){ touch /update; }"
                .into(),
        ),
        ("helpers/extra.sh".into(), "inner(){ touch /inner; }".into()),
        ("lib/cmd/deep/unwanted.sh".into(), "touch /unwanted".into()),
    ]);
    let source = r#"set -- /first /second; source "${LIB_ROOT}/lib/util.sh"; util-setup;
        if test -f x; then CMD_PATH="${LIB_ROOT}/lib/cmd/${CMD}.sh"; else CMD_PATH="${LIB_ROOT}/alt/cmd/${CMD}.sh"; fi;
        source "$CMD_PATH"; "homebrew-${CMD}"; homebrew-update; shared; inner; cat "$1""#;
    for cap in [32, 2, 0] {
        let mut limits = default_limits();
        limits.insert("max_source_alternatives".into(), cap);
        let plan = Engine::with_limits(limits)
            .unwrap()
            .with_resolver(Box::new(MapResolver(files.clone())))
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        if cap < 3 {
            let boundaries: Vec<_> = plan
                .boundaries
                .iter()
                .filter(|boundary| boundary.limit.as_deref() == Some("max_source_alternatives"))
                .collect();
            assert_eq!(boundaries.len(), 1);
            assert!(boundaries[0].detail.as_ref().unwrap().contains("3 files"));
            continue;
        }
        assert!(
            !plan.boundaries.iter().any(|boundary| matches!(
                boundary.reason.as_str(),
                "unresolved_source" | "unmodeled_command"
            )),
            "{:?}",
            plan.boundaries
        );
        for (path, count) in [("/first", 3), ("/second", 0)] {
            assert_eq!(plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.read" && matches!(&effect.resource, ResourceExpr::Concrete { identity: effinterp_proto::ResourceIdentity::FsPath { path: actual } } if actual == path)).count(), count);
        }
        // The union retains an unknown source arm, which may leave $1 unchanged.
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.read"
                && !matches!(effect.resource, ResourceExpr::Concrete { .. })
        }));
        effinterp_proto::validate_redacted(&effinterp_proto::redact_plan(&plan)).unwrap();
        let mut invalid = plan.clone();
        let input = invalid
            .execution_graph
            .nodes
            .iter_mut()
            .find_map(|node| {
                node.input.as_mut().filter(|input| {
                    input.assurance == effinterp_proto::ExecutionAssurance::Alternatives
                })
            })
            .unwrap();
        input.selected = Some(ResourceExpr::Literal {
            value: "/outside-candidates".into(),
        });
        assert!(validate_plan(&invalid).is_err());
        let alternatives: Vec<_> = plan
            .execution_graph
            .nodes
            .iter()
            .filter(|node| {
                node.input.as_ref().is_some_and(|input| {
                    input.assurance == effinterp_proto::ExecutionAssurance::Alternatives
                })
            })
            .collect();
        assert_eq!(alternatives.len(), 3);
        for node in alternatives {
            assert!(
                matches!(&node.input.as_ref().unwrap().selection, effinterp_proto::ExecutionSelection::Search { candidates, selected: None } if candidates.len() == 3)
            );
        }
        for path in [
            "/tmp/cache",
            "/Cellar",
            "/clean",
            "/update",
            "/inner",
            "/tmp/only-util",
        ] {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effinterp_proto::display_resource(&effect.resource)
                        .contains(path)
                        && effect.condition.is_some()),
                "missing {path}"
            );
        }
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.metadata"
                    && effinterp_proto::display_resource(&effect.resource)
                        .contains("/tmp/util-marker")
                    && effect.condition.is_none())
        );
        assert!(!plan.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("/unwanted")
        }));
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "git.remote_sync")
                .count(),
            2
        );
    }
}

#[test]
fn shell_file_origins_and_cd_pwd_resolve_source_paths() {
    for directory in [
        r#"$(cd $(dirname "$0"); pwd)"#,
        r#"$(cd $(dirname "$0") && pwd)"#,
        r#"$(dirname "${BASH_SOURCE[0]}")"#,
    ] {
        let files = HashMap::from([
            (
                "test/e2e.sh".into(),
                format!("SRC={directory}; source \"${{SRC}}/e2e/include.sh\"; runTest ./x.sh"),
            ),
            (
                "test/e2e/include.sh".into(),
                r#"runTest(){ bash "$1"; }; touch "$BASH_SOURCE.seen"; touch "$0.seen""#.into(),
            ),
        ]);
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(files)))
            .analyze(&Subject::Exec {
                argv: vec!["bash".into(), "test/e2e.sh".into()],
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_source"),
            "{directory}: {:?}",
            plan.boundaries
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "process.exec"
                    && effinterp_proto::display_resource(&effect.resource).contains("bash"))
        );
        assert!(plan.execution_graph.nodes.iter().any(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv == &["bash", "./x.sh"])));
        for path in ["test/e2e/include.sh.seen", "test/e2e.sh.seen"] {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.0 == "filesystem.metadata"
                        && effinterp_proto::display_resource(&effect.resource).contains(path))
            );
        }
    }
}

#[test]
fn conditional_symbolic_assignments_keep_prior_resources_and_source_uncertainty() {
    // Losing the prior literal or unset value invents a definite resource and
    // makes a conditionally selected source file appear unconditional.
    for initial in ["", "A=/lit;"] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                "lib/a.sh".into(),
                "f(){ touch /from-source; }".into(),
            )]))))
            .analyze(&Subject::Shell {
                source: format!(
                    r#"{initial} if c; then A="${{R}}/lib"; fi; touch -c "$A"; source "$A/a.sh"; f"#
                ),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let resource = &plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && !effinterp_proto::display_resource(&effect.resource).contains("/from-source")
            })
            .unwrap()
            .resource;
        assert!(
            matches!(resource, ResourceExpr::Union { alternatives } if alternatives.len() >= 2),
            "{resource:?}"
        );
        if !initial.is_empty() {
            assert!(effinterp_proto::display_resource(resource).contains("/lit"));
        }
        let sourced = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && effinterp_proto::display_resource(&effect.resource).contains("/from-source")
            })
            .unwrap();
        assert!(sourced.condition.is_some());
    }
}

#[test]
fn source_alternatives_isolate_variables_and_working_directories() {
    // A candidate's assignment or cd must not leak into another candidate,
    // or become a definite resource after the source call.
    for (a, b, c) in [
        ("X=/a", "X=/b", "X=/c"),
        ("X=/a", "Y=1", "true"),
        ("X=\"$OTHER\"", "true", "true"),
        ("cd /tmp/a", "true", "true"),
    ] {
        for call in [
            r#"source "lib/${N}.sh""#,
            "if check; then source ./lib/a.sh; fi",
        ] {
            let files = HashMap::from([
                ("lib/a.sh".into(), a.into()),
                ("lib/b.sh".into(), format!(r#"{b}; touch "$X"; touch rel"#)),
                ("lib/c.sh".into(), c.into()),
            ]);
            let plan = Engine::new()
                .with_resolver(Box::new(MapResolver(files)))
                .analyze(&Subject::Shell {
                    source: format!(r#"X=/keep; {call}; rm -rf "$X"; rm -rf rel"#),
                    cwd: Some("".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            assert!(
                !plan
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason.as_str() == "unresolved_source"),
                "{:?}",
                plan.boundaries
            );
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == "environment.read"
                        && effinterp_proto::display_resource(&effect.resource) == "env:X")
            );
            let deletes: Vec<_> = plan
                .effects
                .iter()
                .filter(|effect| effect.operation.0 == "filesystem.delete")
                .collect();
            assert_eq!(deletes.len(), 2);
            let changed = if a.starts_with("cd ") { 1 } else { 0 };
            assert!(
                !matches!(deletes[changed].resource, ResourceExpr::Concrete { .. }),
                "{a}, {call}: {:?}",
                deletes[changed]
            );
            if call.starts_with("source") && b == "true" {
                let touches: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "filesystem.metadata")
                    .map(|effect| effinterp_proto::display_resource(&effect.resource))
                    .collect();
                assert!(touches.contains(&"fs:/keep".to_string()), "{touches:?}");
                assert!(touches.contains(&"fs:rel".to_string()), "{touches:?}");
            }
        }
    }
}

#[test]
fn sourced_function_alternatives_isolate_variables_and_working_directories() {
    // Alternative function bodies must start from the caller's state, and
    // their writes must not become definite targets after dispatch returns.
    for (a, b, c) in [
        ("X=/a", "X=/b", "X=/c"),
        ("X=/a", "", ""),
        ("X=\"$OTHER\"", "true", "true"),
        ("cd /tmp/a", "true", "true"),
    ] {
        for call in ["fn-run", r#""fn-${NAME}""#] {
            let files = HashMap::from([
                ("lib/a.sh".into(), format!("fn-run(){{ {a}; }}")),
                (
                    "lib/b.sh".into(),
                    if b.is_empty() {
                        "g(){ :; }".into()
                    } else {
                        format!(r#"fn-run(){{ touch "$X"; touch rel; {b}; }}"#)
                    },
                ),
                (
                    "lib/c.sh".into(),
                    if c.is_empty() {
                        "g(){ :; }".into()
                    } else {
                        // Dynamic dispatch must also isolate different matching names.
                        let name = if call == "fn-run" {
                            "fn-run"
                        } else {
                            "fn-other"
                        };
                        format!("{name}(){{ {c}; }}")
                    },
                ),
            ]);
            let plan = Engine::new()
                .with_resolver(Box::new(MapResolver(files)))
                .analyze(&Subject::Shell {
                    source: format!(
                        r#"X=/keep; source "lib/${{N}}.sh"; {call}; rm -rf "$X"; rm -rf rel"#
                    ),
                    cwd: Some("".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let deletes: Vec<_> = plan
                .effects
                .iter()
                .filter(|effect| effect.operation.0 == "filesystem.delete")
                .collect();
            assert_eq!(deletes.len(), 2);
            let changed = usize::from(a.starts_with("cd "));
            assert!(
                !matches!(deletes[changed].resource, ResourceExpr::Concrete { .. }),
                "{a}, {call}: {:?}",
                deletes[changed]
            );
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == "environment.read"
                        && effinterp_proto::display_resource(&effect.resource) == "env:X")
            );
            if !b.is_empty() {
                let touches: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "filesystem.metadata")
                    .collect();
                assert_eq!(touches.len(), 2);
                assert!(touches.iter().all(|effect| effect.condition.is_some()));
                assert!(
                    touches
                        .iter()
                        .all(|effect| effect.modality == effinterp_proto::Modality::May)
                );
                for path in ["fs:/keep", "fs:rel"] {
                    assert!(
                        touches
                            .iter()
                            .any(|effect| effinterp_proto::display_resource(&effect.resource)
                                == path),
                        "{a}, {call}: {touches:?}"
                    );
                }
            }
        }
    }
    // An unconditional, exact function call still persists its state.
    let plan = Engine::new()
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "lib/a.sh".into(),
            "f(){ X=/a; cd /tmp/a; }".into(),
        )]))))
        .analyze(&Subject::Shell {
            source: r#"X=/keep; source ./lib/a.sh; f; rm -rf "$X"; rm -rf rel"#.into(),
            cwd: Some("".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    for (effect, path) in deletes.iter().zip(["fs:/a", "fs:/tmp/a/rel"]) {
        assert_eq!(effinterp_proto::display_resource(&effect.resource), path);
        assert!(effect.condition.is_none());
    }
}

#[test]
fn source_alternatives_replace_functions_only_on_their_own_paths() {
    // A prior definition cannot run when every source replaces it; when only
    // one source replaces it, the old body belongs to the other alternative.
    for second in ["f(){ touch /alt; }", "g(){ touch /other; }"] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([
                ("lib/a.sh".into(), "f(){ touch /main; }".into()),
                ("lib/b.sh".into(), second.into()),
            ]))))
            .analyze(&Subject::Shell {
                source: r#"f(){ touch /orig; }; untouched(){ touch /untouched; }; source "${R}/lib/${N}.sh"; f; untouched"#.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let untouched: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && effinterp_proto::display_resource(&effect.resource).contains("/untouched")
            })
            .collect();
        assert_eq!(untouched.len(), 1);
        assert!(untouched[0].condition.is_none());
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && !effinterp_proto::display_resource(&effect.resource).contains("/untouched")
            })
            .collect();
        assert_eq!(effects.len(), 2);
        assert!(effects.iter().all(|effect| effect.condition.is_some()));
        assert_ne!(effects[0].condition, effects[1].condition);
        assert_eq!(
            effects
                .iter()
                .filter(
                    |effect| effinterp_proto::display_resource(&effect.resource).contains("/orig")
                )
                .count(),
            usize::from(second.starts_with('g'))
        );
    }
}

#[test]
fn source_search_diagnostics_and_single_candidate_dispatch() {
    let plan = Engine::new()
        .with_resolver(Box::new(MapResolver(HashMap::from([(
            "lib/only.sh".into(), "homebrew-only(){ touch /only; }".into(),
        )]))))
        .analyze(&Subject::Shell {
            source: r#"source "$X"; source "${R}/missing/${N}.sh"; source "${R}/lib/${N}.sh"; "homebrew-${N}""#.into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let boundaries: Vec<_> = plan
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason.as_str() == "unresolved_source")
        .collect();
    assert_eq!(boundaries.len(), 2);
    assert!(
        boundaries.iter().all(|boundary| !boundary
            .detail
            .as_deref()
            .unwrap()
            .contains("max_files"))
    );
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.metadata"
                && effinterp_proto::display_resource(&effect.resource).contains("/only")
                && effect.condition.is_some())
    );
}

#[test]
fn imported_module_functions_see_the_host_environment() {
    let env_helper =
        "export function wipe() { rmSync(process.env.HOME + '/.ssh', {recursive: true}); }";
    for (caller, helper, deleted) in [
        (
            "",
            "export const wipe = () => rmSync(process.env.HOME + '/.ssh', {recursive: true});",
            true,
        ),
        (
            "",
            "export function wipe() { rmSync(`${process.env.HOME}/.ssh`, {recursive: true}); }",
            true,
        ),
        (
            "",
            "import { homedir } from 'os';\nexport function wipe() { rmSync(homedir() + '/.ssh', {recursive: true}); }",
            true,
        ),
        // A program that rewrites the variable keeps the symbolic path,
        // whichever module rewrites it.
        (
            "",
            "process.env.HOME = '/tmp';\nexport function wipe() { rmSync(process.env.HOME + '/.ssh', {recursive: true}); }",
            false,
        ),
        ("process.env.HOME = '/tmp';\n", env_helper, false),
        // Through an intermediate module, which may rewrite the variable
        // before its callee reads it.
        (
            "",
            "import { remove } from './leaf.mjs';\nexport function wipe() { remove(); }",
            true,
        ),
        (
            "",
            "import { remove } from './leaf.mjs';\nexport function wipe() { process.env.HOME = '/tmp'; remove(); }",
            false,
        ),
        (
            "",
            "import { remove } from './leaf.mjs';\nprocess.env.HOME = '/tmp';\nexport function wipe() { remove(); }",
            false,
        ),
        // Writing another variable leaves HOME alone; a write whose variable
        // is unknown may be to HOME.
        (
            "",
            "import { remove } from './leaf.mjs';\nexport function wipe() { process.env.NO_COLOR = '1'; remove(); }",
            true,
        ),
        (
            "",
            "import { remove } from './leaf.mjs';\nexport function wipe() { process.env[process.argv[2]] = '/tmp'; remove(); }",
            false,
        ),
        // An earlier call into another module rewrites it.
        (
            "import { set } from './lib/set.mjs';\nset();\n",
            env_helper,
            false,
        ),
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([
                (
                    "run.mjs".into(),
                    format!("import {{ wipe }} from './lib/h.mjs';\n{caller}wipe();\n"),
                ),
                (
                    "lib/h.mjs".into(),
                    format!("import {{ rmSync }} from 'fs';\n{helper}\n"),
                ),
                (
                    "lib/set.mjs".into(),
                    "export function set() { process.env.HOME = '/tmp'; }\n".into(),
                ),
                (
                    "lib/leaf.mjs".into(),
                    "import { rmSync } from 'fs';\nexport function remove() { rmSync(process.env.HOME + '/.ssh', {recursive: true}); }\n".into(),
                ),
            ]))))
            .analyze(&Subject::Exec {
                argv: vec!["node".into(), "run.mjs".into()],
                cwd: Some(String::new()),
                context: effinterp_proto::HostContext {
                    env: [("HOME".to_string(), "/home/test".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource) == "fs:/home/test/.ssh"
            }),
            deleted,
            "{helper}"
        );
        // Otherwise the path stays unresolved, or keeps the variable and a
        // boundary names it.
        if !deleted {
            let delete = plan
                .effects
                .iter()
                .find(|effect| effect.operation.as_str() == "filesystem.delete")
                .unwrap();
            assert!(
                matches!(
                    delete.resource,
                    effinterp_proto::ResourceExpr::Unresolved { .. }
                ) || plan
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.affected_resource.as_ref() == Some(&delete.resource)),
                "{helper}"
            );
        }
    }
}

#[test]
fn callable_default_and_whole_module_exports_are_followed() {
    let esm = "import wipe from './lib/h.mjs';\nwipe('/w');\n";
    let cjs = "const wipe = require('./lib/h.js');\nwipe('/w');\n";
    let named = "const h = require('./lib/h.js');\nh.wipe('/w');\n";
    // Each case deletes `/w`, leaves a call unresolved, both, or neither.
    for (entry, caller, helper, path, outcome) in [
        (
            "run.mjs",
            esm,
            "export default function wipe(root) { rmSync(root, {recursive: true}); }",
            "lib/h.mjs",
            "delete",
        ),
        (
            "run.mjs",
            esm,
            "export default (root) => rmSync(root, {recursive: true});",
            "lib/h.mjs",
            "delete",
        ),
        (
            "run.mjs",
            esm,
            "function wipe(root) { rmSync(root, {recursive: true}); }\nexport default wipe;",
            "lib/h.mjs",
            "delete",
        ),
        (
            "run.js",
            cjs,
            "module.exports = function (root) { rmSync(root, {recursive: true}); };",
            "lib/h.js",
            "delete",
        ),
        (
            "run.js",
            cjs,
            "function wipe(root) { rmSync(root, {recursive: true}); }\nmodule.exports = wipe;",
            "lib/h.js",
            "delete",
        ),
        // The last whole-module assignment is the callable value.
        (
            "run.js",
            cjs,
            "module.exports = function () {};\nmodule.exports = function (root) { rmSync(root, {recursive: true}); };",
            "lib/h.js",
            "delete",
        ),
        (
            "run.js",
            cjs,
            "module.exports = function (root) { rmSync(root, {recursive: true}); };\nmodule.exports = function () {};",
            "lib/h.js",
            "none",
        ),
        // A replaced callable's nested helpers go with it.
        (
            "run.js",
            cjs,
            "module.exports = function (root) { function remove(root) {} remove(root); };\nmodule.exports = function (root) { function remove(root) { rmSync(root, {recursive: true}); } remove(root); };",
            "lib/h.js",
            "delete",
        ),
        // The callable's own helper, not a same-named one nested in a later
        // function, is the one it calls.
        (
            "run.js",
            cjs,
            "module.exports = function (root) { function remove(root) { rmSync(root, {recursive: true}); } remove(root); };\nfunction unused() { function remove(root) {} }",
            "lib/h.js",
            "delete",
        ),
        (
            "run.js",
            cjs,
            "module.exports = function (root) { function remove(root) {} remove(root); };\nfunction unused() { function remove(root) { rmSync(root, {recursive: true}); } }",
            "lib/h.js",
            "none",
        ),
        // A conditional replacement leaves the callable value unknown until a
        // later assignment settles it; one inside a function never settles.
        (
            "run.js",
            cjs,
            "module.exports = function (root) { rmSync(root, {recursive: true}); };\nif (process.env.SAFE) module.exports = function () {};",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            cjs,
            "if (process.env.SAFE) module.exports = function () {};\nmodule.exports = function (root) { rmSync(root, {recursive: true}); };",
            "lib/h.js",
            "delete",
        ),
        (
            "run.js",
            cjs,
            "function reset() { module.exports = function () {}; }\nmodule.exports = function (root) { rmSync(root, {recursive: true}); };",
            "lib/h.js",
            "unresolved",
        ),
        // `||=` keeps a callable value, so it settles nothing.
        (
            "run.js",
            cjs,
            "module.exports = function () {};\nif (true) module.exports = function (root) { rmSync(root, {recursive: true}); };\nmodule.exports ||= function () {};",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            cjs,
            "module.exports = function (root) { rmSync(root, {recursive: true}); };\nif (true) module.exports = function () {};\nmodule.exports ||= function () {};",
            "lib/h.js",
            "unresolved",
        ),
        // A named export calls its own nested helper, not the whole-module
        // callable's namesake.
        (
            "run.js",
            named,
            "module.exports = function (root) { function remove(root) {} remove(root); };\nfunction wipe(root) { function remove(root) { rmSync(root, {recursive: true}); } remove(root); }\nmodule.exports.wipe = wipe;",
            "lib/h.js",
            "delete",
        ),
        (
            "run.js",
            named,
            "module.exports = function (root) { function remove(root) { rmSync(root, {recursive: true}); } remove(root); };\nfunction wipe(root) { function remove(root) {} remove(root); }\nmodule.exports.wipe = wipe;",
            "lib/h.js",
            "none",
        ),
        // A block's own helper shadows the module's namesake.
        (
            "run.js",
            named,
            "function remove(root) {}\nfunction wipe(root) { 'use strict'; { function remove(root) { rmSync(root, {recursive: true}); } remove(root); } }\nexports.wipe = wipe;",
            "lib/h.js",
            "delete",
        ),
        (
            "run.js",
            named,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root) { 'use strict'; { function remove(root) {} remove(root); } }\nexports.wipe = wipe;",
            "lib/h.js",
            "none",
        ),
        (
            "run.js",
            named,
            "function remove(root) {}\nfunction wipe(root) { { const remove = (root) => { rmSync(root, {recursive: true}); }; remove(root); } }\nexports.wipe = wipe;",
            "lib/h.js",
            "delete",
        ),
        // A parameter shadows the module's namesake; its value is the
        // caller's callback, not a body of this module.
        (
            "run.js",
            "const h = require('./lib/h.js');\nh.wipe('/w', () => {});\n",
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root, remove) { remove(root); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        // A callback passed by name runs the function its reference binds
        // to, never a block-local or nested namesake. `roots.forEach` itself
        // stays unresolved.
        (
            "run.js",
            named,
            "function remove(root) {}\nfunction wipe(root) { 'use strict'; { function remove(root) { rmSync(root, {recursive: true}); } } const roots = [root]; roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            named,
            "function remove(root) {}\nfunction unused() { function remove(root) { rmSync(root, {recursive: true}); } }\nfunction wipe(root) { const roots = [root]; roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            named,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction unused() { function remove(root) {} }\nfunction wipe(root) { const roots = [root]; roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "delete, unresolved",
        ),
        // An alias names the function its own symbol holds, not a
        // block-local namesake's.
        (
            "run.js",
            named,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction safe(root) {}\nfunction wipe(root) { const roots = [root]; const cb = safe; { const cb = remove; } roots.forEach(cb); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        // A callback's formals take only the arguments its call site
        // proves, never the enclosing function's same-named parameter.
        (
            "run.js",
            named,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root) { const roots = ['/tmp/x']; roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            named,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction unused() { function remove(root) {} }\nfunction wipe(root) { const roots = ['/tmp/x']; roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            named,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root) { setTimeout(remove, 0, '/tmp/x'); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        // An iteration callback given the array as its third argument may
        // replace its elements, so the literal proves no later argument.
        (
            "run.js",
            "const h = require('./lib/h.js');\nh.wipe('/tmp/x');\n",
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root) { const roots = ['/w']; roots.forEach((value, index, alias) => { alias[index] = '/tmp/x'; }); roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.js",
            "const h = require('./lib/h.js');\nh.wipe('/tmp/x');\n",
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root) { const roots = ['/w']; roots.forEach((value, index) => {}); roots.forEach(remove); }\nexports.wipe = wipe;",
            "lib/h.js",
            "delete, unresolved",
        ),
        (
            "run.js",
            "const h = require('./lib/h.js');\nh.wipe('/tmp/x');\n",
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction wipe(root) { setTimeout(remove, 0, '/w'); }\nexports.wipe = wipe;",
            "lib/h.js",
            "delete, unresolved",
        ),
        // Two definitions in the same scope leave the helper unknown.
        (
            "run.js",
            cjs,
            "function remove(root) { rmSync(root, {recursive: true}); }\nfunction remove(root) {}\nmodule.exports = function (root) { remove(root); };",
            "lib/h.js",
            "unresolved",
        ),
        // Calling an `import * as` namespace object throws.
        (
            "run.mjs",
            "import * as wipe from './lib/h.mjs';\nwipe('/w');\n",
            "export default function wipe(root) { rmSync(root, {recursive: true}); }",
            "lib/h.mjs",
            "unresolved",
        ),
        // A named export is not the module's callable value.
        (
            "run.js",
            cjs,
            "exports.wipe = function (root) { rmSync(root, {recursive: true}); };",
            "lib/h.js",
            "unresolved",
        ),
        (
            "run.mjs",
            esm,
            "export function wipe(root) { rmSync(root, {recursive: true}); }",
            "lib/h.mjs",
            "unresolved",
        ),
    ] {
        let rm = if path.ends_with(".mjs") {
            "import { rmSync } from 'fs';"
        } else {
            "const { rmSync } = require('fs');"
        };
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([
                (entry.into(), caller.into()),
                (path.into(), format!("{rm}\n{helper}\n")),
            ]))))
            .analyze(&Subject::Exec {
                argv: vec!["node".into(), entry.into()],
                cwd: Some(String::new()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource) == "fs:/w"
            }),
            outcome.contains("delete"),
            "{helper}"
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
            outcome.contains("unresolved"),
            "{helper}"
        );
    }
}

#[test]
fn path_dependencies_are_followed_for_each_script_launch() {
    // Separate processes must each import the shared module with their own argv,
    // even when the same entry script is launched again later in the plan.
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(MapResolver(HashMap::from([
            (
                "two.sh".into(),
                "node c1.js one\nnode c2.js two\nnode c1.js three".into(),
            ),
            ("c1.js".into(), "require('./shared.js');".into()),
            ("c2.js".into(), "require('./shared.js');".into()),
            (
                "shared.js".into(),
                "require('child_process').spawn('git', ['push', process.argv[2]]);".into(),
            ),
        ]))))
        .analyze(&Subject::Shell {
            source: "sh two.sh".into(),
            cwd: Some(String::new()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let imports = plan
        .execution_graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.selected_source_path() == Some("shared.js"))
        .collect::<Vec<_>>();
    assert_eq!(imports.len(), 3);
    for ((index, node), argument) in imports.into_iter().zip(["one", "two", "three"]) {
        assert!(matches!(
            node.input.as_ref().unwrap().content,
            effinterp_proto::ExecutionContent::Observed { .. }
        ));
        assert!(plan.execution_graph.edges.iter().any(|edge| {
            edge.kind == ExecutionEdgeKind::Import
                && edge.to.0 as usize == index
                && edge.from == node.input.as_ref().unwrap().requester
        }));
        assert_eq!(
            node.argv[2],
            ResourceExpr::Literal {
                value: argument.into()
            }
        );
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "process.exec"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::Process { executable, argv, .. }
                } if executable == "git" && argv == &vec![
                    ResourceExpr::Literal { value: "push".into() },
                    ResourceExpr::Literal { value: argument.into() },
                ])
        }), "missing git push {argument}");
    }
}

#[test]
fn path_dependencies_follow_extensions_once_and_inherit_launch_arguments() {
    // A trampoline must reach its effect with the original operand, without
    // re-executing modules in a require cycle or probing bare package names.
    for (interpreter, script, entry, dependency, body) in [
        (
            "node",
            "bin/tool",
            "require('../lib/cli'); require('../lib/cli');",
            "lib/cli.js",
            "require('../bin/tool'); require('commander'); const { spawn } = require('child_process'); spawn('git', ['fetch', process.argv[2]]);",
        ),
        (
            "node",
            "bin/tool",
            "import '../lib/cli';",
            "lib/cli.cjs",
            "require('../bin/tool'); const { spawn } = require('child_process'); spawn('git', ['fetch', process.argv[2]]);",
        ),
        (
            "node",
            "bin/tool",
            "import('../lib/cli');",
            "lib/cli.mjs",
            "import '../bin/tool'; import { spawn } from 'child_process'; spawn('git', ['fetch', process.argv[2]]);",
        ),
        (
            "node",
            "bin/tool",
            "require('../lib/cli');",
            "lib/cli.ts",
            "import '../bin/tool'; import { spawn } from 'child_process'; const branch: string = process.argv[2]; spawn('git', ['fetch', branch]);",
        ),
        (
            "node",
            "bin/tool",
            "import '../lib/cli.mts';",
            "lib/cli.mts",
            "import '../bin/tool'; import { spawn } from 'child_process'; const branch: string = process.argv[2]; spawn('git', ['fetch', branch]);",
        ),
        (
            "node",
            "bin/tool",
            "require('../lib/cli');",
            "lib/cli/index.js",
            "require('../../bin/tool'); const { spawn } = require('child_process'); spawn('git', ['fetch', process.argv[2]]);",
        ),
        (
            "ruby",
            "bin/tool.rb",
            "require_relative '../lib/cli'\nrequire_relative '../lib/cli'",
            "lib/cli.rb",
            "require_relative '../bin/tool'\nspawn('git', 'fetch', ARGV[0])",
        ),
        (
            "ruby",
            "bin/tool.rb",
            "require '../lib/cli'",
            "lib/cli.rb",
            "require_relative '../bin/tool'\nspawn('git', 'fetch', ARGV[0])",
        ),
        (
            "ruby",
            "bin/tool.rb",
            "require_relative 'cli'",
            "bin/cli.rb",
            "require_relative 'tool'\nspawn('git', 'fetch', ARGV[0])",
        ),
    ] {
        for argument in ["x", "\"$TARGET\""] {
            for launch in [
                format!("{interpreter} {script}"),
                format!("./{script}"),
                format!(
                    "{interpreter} {} {script}",
                    if interpreter == "ruby" { "-W0" } else { "--" }
                ),
            ] {
                let plan = Engine::new()
                    .with_causality_detail(true)
                    .with_resolver(Box::new(MapResolver(HashMap::from([
                        (
                            script.to_string(),
                            format!("#!/usr/bin/env {interpreter}\n{entry}"),
                        ),
                        (dependency.to_string(), body.to_string()),
                    ]))))
                    .analyze(&Subject::Shell {
                        source: format!("{launch} {argument}"),
                        cwd: Some(String::new()),
                        context: Default::default(),
                    })
                    .unwrap();
                validate_plan(&plan).unwrap();
                let imports = plan
                    .execution_graph
                    .nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, node)| node.selected_source_path() == Some(dependency))
                    .collect::<Vec<_>>();
                assert_eq!(imports.len(), 1, "{interpreter}: {dependency}");
                let (index, imported) = imports[0];
                assert!(matches!(
                    imported.input.as_ref().unwrap().content,
                    effinterp_proto::ExecutionContent::Observed { .. }
                ));
                assert!(plan.execution_graph.edges.iter().any(|edge| {
                    edge.kind == ExecutionEdgeKind::Import && edge.to.0 as usize == index
                }));
                let argv = plan
                    .effects
                    .iter()
                    .find_map(|effect| match &effect.resource {
                        ResourceExpr::Concrete {
                            identity:
                                effinterp_proto::ResourceIdentity::Process {
                                    executable, argv, ..
                                },
                        } if effect.operation.as_str() == "process.exec" && executable == "git" => {
                            Some(argv)
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("{interpreter}: {dependency}: {:?}", plan.effects));
                assert_eq!(
                    argv[0],
                    ResourceExpr::Literal {
                        value: "fetch".into()
                    }
                );
                assert_eq!(
                    argv[1],
                    if argument == "x" {
                        ResourceExpr::Literal { value: "x".into() }
                    } else {
                        ResourceExpr::Environment {
                            name: "TARGET".into(),
                        }
                    }
                );
                assert_eq!(imported.argv[2], argv[1]);
                assert!(!imported.evidence.is_empty());
                let graph = plan.causality.graph.as_ref().unwrap();
                let read = graph
                    .nodes
                    .iter()
                    .find(|node| {
                        matches!(&node.occurrence,
                effinterp_proto::OccurrenceKind::ResourceInteraction { operation, resource, .. }
                if operation.as_str() == "filesystem.read"
                    && effinterp_proto::display_resource(resource) == format!("fs:{dependency}"))
                    })
                    .unwrap();
                let mut reached = std::collections::BTreeSet::from([read.id.clone()]);
                loop {
                    let before = reached.len();
                    for edge in &graph.edges {
                        if reached.contains(&edge.from) {
                            reached.insert(edge.to.clone());
                        }
                    }
                    if reached.len() == before {
                        break;
                    }
                }
                assert!(graph.nodes.iter().any(|node| reached.contains(&node.id)
                && matches!(&node.occurrence,
                    effinterp_proto::OccurrenceKind::ResourceInteraction { operation, resource, .. }
                    if operation.as_str() == "process.exec" && matches!(resource,
                        ResourceExpr::Concrete { identity: effinterp_proto::ResourceIdentity::Process { executable, .. } }
                        if executable == "git"))), "imported read must reach the effect");

                let denied =
                    plan.execution_graph
                        .nodes
                        .iter()
                        .filter_map(|node| node.input.as_ref())
                        .filter(|input| {
                            matches!(
                        input.content,
                        effinterp_proto::ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::DependencyNotTraversed
                        }
                    )
                        })
                        .collect::<Vec<_>>();
                assert_eq!(denied.len(), usize::from(body.contains("commander")));
            }
        }
    }
}

#[test]
fn launch_argv_does_not_override_source_bindings() {
    // Rebinding the runtime receiver or argv must never manufacture an effect
    // containing the old launch operand.
    for (interpreter, file, source) in [
        (
            "node",
            "main.js",
            "const process = { argv: ['node', 'file', 'changed'] }; require('child_process').spawn('git', ['fetch', process.argv[2]]);",
        ),
        (
            "node",
            "main.js",
            "process.argv[2] = 'changed'; require('child_process').spawn('git', ['fetch', process.argv[2]]);",
        ),
        (
            "node",
            "main.js",
            "function run(process) { require('child_process').spawn('git', ['fetch', process.argv[2]]); } run({argv: []});",
        ),
        (
            "ruby",
            "main.rb",
            "ARGV[0] = 'changed'\nspawn('git', 'fetch', ARGV[0])",
        ),
        (
            "ruby",
            "main.rb",
            "ARGV = ['changed']\nspawn('git', 'fetch', ARGV[0])",
        ),
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([(
                file.to_string(),
                source.to_string(),
            )]))))
            .analyze(&exec(&[interpreter, file, "old-launch-operand"], Some("")))
            .unwrap();
        assert!(
            plan.effects
                .iter()
                .filter(|effect| effect.execution.0 > 0)
                .all(|effect| {
                    !effinterp_proto::display_resource(&effect.resource)
                        .contains("old-launch-operand")
                }),
            "{source}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn split_command_heads_dispatch_sourced_function_alternatives() {
    // Splitting must preserve both sourced function bodies and the external
    // command arm, without emitting a process for a function or builtin.
    let plan = Engine::new()
        .with_resolver(Box::new(MapResolver(HashMap::from([
            ("lib/a.sh".into(), "f(){ touch /a; cat \"$1\"; }".into()),
            ("lib/b.sh".into(), "f(){ touch /b; cat \"$1\"; }".into()),
        ]))))
        .analyze(&Subject::Shell {
            source: r#"source "${ROOT}/lib/${NAME}.sh"; for cmd in "f /input" "rm /removed" ":"; do $cmd; done"#.into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    // The loop list is a fixed sequence of literals and the body always
    // reaches its end, so every command runs: the split heads are established,
    // not conditional. What stays conditional is the source dispatch, which
    // picks one of the two candidate files, so only the effects that come from
    // a sourced function body carry a condition.
    for (operation, path, conditional) in [
        ("filesystem.metadata", "/a", true),
        ("filesystem.metadata", "/b", true),
        ("filesystem.read", "/input", true),
        ("filesystem.delete", "/removed", false),
    ] {
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == operation
                    && effinterp_proto::display_resource(&effect.resource) == format!("fs:{path}")
                    && effect.condition.is_some() == conditional
            }),
            "missing {operation} {path}: {:?}",
            plan.effects
        );
    }
    assert!(!plan.effects.iter().any(|effect| matches!(&effect.resource,
        ResourceExpr::Concrete { identity: effinterp_proto::ResourceIdentity::Process { executable, .. } }
        if executable == "f" || executable == ":")));
}

#[test]
fn pattern_function_dispatch_preserves_unresolved_external_arm() {
    // A wildcard can name an external command even when known functions match.
    for definitions in [
        "source lib/util.sh",
        "util-setup(){ touch /known; }",
        "util-setup(){ touch /known; }; util-other(){ touch /other; }",
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([
                ("lib/util.sh".into(), "util-setup(){ touch /known; }".into()),
                (
                    "dispatch.sh".into(),
                    format!(r#"{definitions}; "util-${{NAME}}"; util-setup"#),
                ),
            ]))))
            .analyze(&Subject::Shell {
                source: "bash dispatch.sh".into(),
                cwd: Some(String::new()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let external: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.as_str() == "process.exec"
                    && matches!(&effect.resource, ResourceExpr::Unresolved { .. })
            })
            .collect();
        assert_eq!(external.len(), 1, "{definitions}");
        let Some(effinterp_proto::Condition::Atom { atom }) = &external[0].condition else {
            panic!("external arm must have a dispatch condition: {external:?}");
        };
        let function_count = if definitions.contains("util-other") {
            2
        } else {
            1
        };
        assert_eq!(atom.origin.kind, effinterp_proto::ConditionKind::Dispatch);
        assert_eq!(atom.arm, function_count);
        assert_eq!(atom.arms, function_count + 1);
        assert!(!atom.exhaustive);
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| { boundary.reason.as_str() == "unresolved_command" })
                .count(),
            1
        );
        let known: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.as_str() == "filesystem.metadata"
                    && effinterp_proto::display_resource(&effect.resource) == "fs:/known"
            })
            .collect();
        assert_eq!(known.len(), 2);
        assert!(known.iter().any(|effect| effect.condition.is_none()));
        assert!(known.iter().any(|effect| matches!(&effect.condition,
            Some(effinterp_proto::Condition::Atom { atom: function })
                if function.origin == atom.origin && function.arm < function_count
                    && function.arms == atom.arms
        )));
    }
}

#[test]
fn source_alternative_termination_requires_every_candidate_to_stop() {
    for (left, right, call, continues) in [
        ("exit 0", "exec true", "", false),
        ("exit 0", "return 0", "", true),
        ("return 0", "return 0", "", true),
        ("f(){ exit 0; }", "f(){ exec true; }", "f;", false),
        ("f(){ exit 0; }", "f(){ return 0; }", "f;", true),
        ("f(){ exit 0; }", "f(){ exec true; }", "\"f${NAME}\";", true),
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(MapResolver(HashMap::from([
                ("lib/a.sh".into(), format!("{left}; touch /candidate-a")),
                ("lib/b.sh".into(), format!("{right}; touch /candidate-b")),
            ]))))
            .analyze(&Subject::Shell {
                source: format!(r#"source "${{ROOT}}/lib/${{CMD}}.sh"; {call} touch /after"#),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let has_path = |path: &str| {
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.metadata"
                    && effinterp_proto::display_resource(&effect.resource) == format!("fs:{path}")
            })
        };
        assert_eq!(has_path("/after"), continues, "{left}; {right}; {call}");
        assert_eq!(has_path("/candidate-a"), !call.is_empty());
        assert_eq!(has_path("/candidate-b"), !call.is_empty());
    }
    // Unmatched values in a conditional assignment can still let the caller continue.
    let plan = Engine::new()
        .with_resolver(Box::new(MapResolver(HashMap::from([
            ("lib/a.sh".into(), "exit 0".into()),
            ("lib/b.sh".into(), "exit 0".into()),
        ]))))
        .analyze(&Subject::Shell {
            source: r#"if test -n "$X"; then LIB="${ROOT}/lib/${CMD}.sh"; fi; source "$LIB"; touch /after"#.into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.metadata"
            && effinterp_proto::display_resource(&effect.resource) == "fs:/after"
    }));
}

#[test]
fn sourced_polyglot_exec_keeps_the_callers_file_origin() {
    let source = "#!/bin/bash\nsource \"${ROOT}/lib/setup.sh\"\n#!/usr/bin/env ruby\nFile.delete('/tmp/polyglot')\n";
    for direct_file in [false, true] {
        let engine = Engine::new().with_resolver(Box::new(MapResolver(HashMap::from([
            ("shim".into(), source.into()),
            (
                "lib/setup.sh".into(),
                "exec \"$RUBY\" -x \"$0\"; touch /dead".into(),
            ),
        ]))));
        let subject = Subject::Shell {
            source: if direct_file { source } else { "bash shim" }.into(),
            cwd: None,
            context: Default::default(),
        };
        let plan = if direct_file {
            engine
                .analyze_file_cwds_with_stats(&subject, None, None, Some("shim"))
                .unwrap()
                .0
        } else {
            engine.analyze(&subject).unwrap()
        };
        validate_plan(&plan).unwrap();
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource) == "fs:/tmp/polyglot"
            }),
            "direct_file={direct_file}: {:?}",
            plan.boundaries
        );
        assert!(
            !plan.effects.iter().any(|effect| {
                effinterp_proto::display_resource(&effect.resource) == "fs:/dead"
            })
        );
    }
}
