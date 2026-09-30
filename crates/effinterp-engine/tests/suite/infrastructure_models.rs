use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{
    AttrValue, KubernetesNamespace, Modality, Plan, RequestAssurance, ResourceExpr,
    ResourceIdentity, Subject, validate_plan,
};
use std::collections::BTreeMap;

struct Sources(BTreeMap<String, String>);
impl SourceResolver for Sources {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.get(request.path.trim_start_matches('/')).map_or(
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |source| SourceResponse::Source(source.as_bytes().to_vec()),
        )
    }
    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let parent = path
            .trim_start_matches('/')
            .rsplit_once('/')
            .map_or("", |(p, _)| p);
        Some(
            self.0
                .keys()
                .filter(|p| p.rsplit_once('/').map_or("", |(p, _)| p) == parent)
                .cloned()
                .collect(),
        )
    }
}
fn analyze(argv: &[&str], sources: &[(&str, &str)]) -> Plan {
    let plan = Engine::new()
        .with_resolver(Box::new(Sources(
            sources
                .iter()
                .map(|(p, s)| (p.to_string(), s.to_string()))
                .collect(),
        )))
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("{argv:?}: {e:?}"));
    plan
}

fn analyze_with_env(argv: &[&str], env: &[(&str, &str)]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/work".into()),
            context: effinterp_proto::HostContext {
                env: env
                    .iter()
                    .map(|(key, value)| ((*key).into(), (*value).into()))
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("{argv:?}: {e:?}"));
    plan
}
fn has(plan: &Plan, op: &str) -> bool {
    plan.effects.iter().any(|e| e.operation.as_str() == op)
}
fn kubernetes<'a>(plan: &'a Plan, op: &str) -> Vec<&'a ResourceIdentity> {
    plan.effects
        .iter()
        .filter(|e| e.operation.as_str() == op)
        .filter_map(|e| match &e.resource {
            ResourceExpr::Concrete {
                identity: id @ ResourceIdentity::KubernetesResource { name, .. },
            } if matches!(name.as_ref(), ResourceExpr::Literal { .. }) => Some(id),
            _ => None,
        })
        .collect()
}
const MANIFEST: &str = include_str!("../fixtures/infrastructure/objects.yaml");

#[test]
fn kubernetes_lifecycle_retains_objects_and_suppresses_dry_run_mutations() {
    let plan = analyze(&["kubectl", "delete", "namespace", "prod"], &[]);
    assert!(
        matches!(kubernetes(&plan, "container.resource.delete")[0], ResourceIdentity::KubernetesResource { kind, namespace: KubernetesNamespace::Cluster, .. } if kind == "Namespace")
    );
    let plan = analyze(&["kubectl", "delete", "namespaces", "--all"], &[]);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.class == effinterp_proto::BoundaryClass::Unresolved
            && boundary.reason == effinterp_proto::BoundaryReason::LIVE_INVENTORY
    }));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "container.resource.delete")
        .expect("plural namespace delete");
    assert_eq!(
        delete.attributes.get("scope"),
        Some(&effinterp_proto::AttrValue::String("namespace".into()))
    );
    assert_eq!(
        delete.attributes.get("selection"),
        Some(&effinterp_proto::AttrValue::String("whole".into()))
    );
    for argv in [
        vec!["kubectl", "delete", "all", "--all"],
        vec!["kubectl", "delete", "all", "--all", "-n", "prod"],
        vec!["kubectl", "delete", "all", "--all", "-A"],
    ] {
        let plan = analyze(&argv, &[]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "container.resource.delete")
            .expect("all-resources delete");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::KubernetesResource {
                    namespace: KubernetesNamespace::Namespaced { namespace },
                    ..
                },
            } if argv.contains(&"-n")
                == matches!(namespace.as_ref(), ResourceExpr::Literal { value } if value == "prod")
        ));
        assert_eq!(
            delete.attributes.get("scope"),
            Some(&AttrValue::String("namespaced".into()))
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| { boundary.reason.as_str() == "kubernetes_target_api" })
        );
    }
    for flag in ["-A", "--all-namespaces"] {
        let plan = analyze(
            &["kubectl", "delete", "services", "--all", flag, "-n", "prod"],
            &[],
        );
        assert!(has(&plan, "container.resource.delete"), "{flag}");
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "container.resource.delete"
                && effect.attributes.get("all") == Some(&AttrValue::Bool(true))
                && effect.attributes.get("all_namespaces") == Some(&AttrValue::Bool(true))
        }));
        assert!(plan.effects.iter().any(|effect| matches!(&effect.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::KubernetesResource {
                namespace: KubernetesNamespace::Namespaced { namespace }, ..
            }} if matches!(namespace.as_ref(), ResourceExpr::Unresolved { .. })
        )));
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
        );
    }
    let plan = analyze(&["kubectl", "-n", "exec", "delete", "pod", "web"], &[]);
    for (flag, kind) in [("--selector", "label"), ("--field-selector", "field")] {
        let selected = analyze(
            &["kubectl", "delete", "jobs", flag, "status.successful=1"],
            &[],
        );
        let delete = selected
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "container.resource.delete")
            .unwrap();
        assert_eq!(
            delete.attributes.get("selector_kind"),
            Some(&AttrValue::String(kind.into()))
        );
        assert!(matches!(&delete.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::KubernetesResource { name, .. }
        } if matches!(name.as_ref(), ResourceExpr::Unresolved { .. })));
    }
    assert_eq!(kubernetes(&plan, "container.resource.delete").len(), 1);
    assert!(!plan.execution_graph.nodes.iter().any(|node| {
        matches!(
            node.realm,
            effinterp_proto::ExecutionRealm::Kubernetes { .. }
        )
    }));
    for (verb, expected) in [("get", "read"), ("delete", "delete")] {
        let plan = analyze(
            &[
                "kubectl",
                "--context=west",
                verb,
                "deployments.apps/api",
                "-n",
                "prod",
                "--server=https://cluster",
            ],
            &[],
        );
        assert_eq!(
            kubernetes(&plan, &format!("container.resource.{expected}")).len(),
            1
        );
    }
    for (verb, create, update, delete) in [
        ("create", true, false, false),
        ("apply", true, true, false),
        ("delete", false, false, true),
    ] {
        let plan = analyze(
            &["kubectl", verb, "-f", "objects.yaml"],
            &[("work/objects.yaml", MANIFEST)],
        );
        for (op, present) in [("create", create), ("update", update), ("delete", delete)] {
            assert_eq!(
                kubernetes(&plan, &format!("container.resource.{op}")).len(),
                if present { 2 } else { 0 }
            );
        }
        assert!(has(&plan, "filesystem.read"));
    }
    for (flags, mutates, network) in [
        (vec!["--dry-run=client"], false, false),
        (vec!["--dry-run", "client"], false, false),
        (vec!["--dry-run=server"], false, true),
        (vec!["--dry-run", "server"], false, false),
        (vec!["--dry-run=none"], true, true),
        (vec!["--dry-run", "none"], false, false),
        (vec!["--dry-run"], false, false),
    ] {
        for before_file in [false, true] {
            let mut argv = vec!["kubectl", "apply"];
            if before_file {
                argv.extend_from_slice(&flags);
            }
            argv.extend_from_slice(&["-f", "objects.yaml"]);
            if !before_file {
                argv.extend_from_slice(&flags);
            }
            let plan = analyze(&argv, &[("work/objects.yaml", MANIFEST)]);
            for operation in ["container.resource.create", "container.resource.update"] {
                assert_eq!(has(&plan, operation), mutates, "{argv:?}");
            }
            assert!(!has(&plan, "container.resource.delete"), "{argv:?}");
            assert_eq!(has(&plan, "network.request"), network, "{argv:?}");
            assert!(!plan.boundaries.is_empty());
        }
    }
    let plan = analyze(
        &["kubectl", "apply", "--prune", "-f", "objects.yaml"],
        &[("work/objects.yaml", MANIFEST)],
    );
    assert!(has(&plan, "container.resource.delete"));
    for (verb, operation) in [
        ("restart", "restart"),
        ("pause", "pause"),
        ("resume", "unpause"),
        ("undo", "rollback"),
        ("status", "read"),
        ("history", "read"),
    ] {
        let plan = analyze(&["kubectl", "rollout", verb, "deployment/api"], &[]);
        assert!(has(&plan, &format!("container.resource.{operation}")));
        assert_eq!(has(&plan, "container.resource.restart"), verb == "restart");
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: format!("kubectl apply -f - <<'MANIFEST'\n{MANIFEST}MANIFEST\n"),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(kubernetes(&plan, "container.resource.create").len(), 2);
    assert!(plan.effects.iter().filter(|e| e.operation.as_str() == "container.resource.create").all(|e|
        e.provenance.iter().any(|r| matches!(&plan.provenance[r.0 as usize].kind, effinterp_proto::ProvenanceKind::SourceInput { path, .. } if path == "stdin"))));
}

#[test]
fn kubernetes_bad_sources_and_arguments_keep_partial_operation_evidence() {
    for source in [
        "kind: [",
        "kind: Pod\nkind: Secret",
        "x: &x [*x]",
        "apiVersion: v1\nkind: Pod\nmetadata: {}",
    ] {
        let plan = analyze(
            &["kubectl", "delete", "-f", "bad.yaml"],
            &[("work/bad.yaml", source)],
        );
        assert!(has(&plan, "container.resource.delete"));
        assert!(kubernetes(&plan, "container.resource.delete").is_empty());
        assert!(!plan.boundaries.is_empty());
    }
    for argv in [
        vec!["kubectl", "delete", "-f", "missing.yaml"],
        vec!["kubectl", "delete", "-f", "-"],
        vec!["kubectl", "delete", "pod", "--unknown", "not-a-name"],
        vec!["kubectl", "delete", "-k", "directory"],
    ] {
        let plan = analyze(&argv, &[]);
        assert_eq!(
            has(&plan, "container.resource.delete"),
            !argv.contains(&"--unknown")
        );
        assert!(kubernetes(&plan, "container.resource.delete").is_empty());
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.class == effinterp_proto::BoundaryClass::Unresolved
                && boundary.reason == effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS
        }));
    }
    // A documented value option left without an argument is rejected while the
    // command line is parsed, so no kubeconfig, request or cluster evidence exists.
    let missing_value = analyze(&["kubectl", "delete", "pod", "--namespace"], &[]);
    assert!(!has(&missing_value, "container.resource.delete"));
    assert!(!has(&missing_value, "network.request"));
    assert!(missing_value.boundaries.is_empty());
    let missing_name = analyze(&["kubectl", "delete", "pod"], &[]);
    assert!(
        missing_name.boundaries.iter().any(|boundary| {
            boundary.reason == effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS
        })
    );
    let unknown_kind = analyze(&["kubectl", "delete", "widgets", "retired"], &[]);
    assert!(unknown_kind.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::CLUSTER_API
            && boundary.domains.iter().any(|domain| domain.0 == "network")
    }));
    assert!(unknown_kind.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "kubernetes_target_api"
            && boundary.domains.len() == 1
            && boundary.domains[0].0 == "container"
    }));
    let plan = analyze(
        &["kubectl", "delete", "-f", "object.json", "-n", "other"],
        &[(
            "work/object.json",
            r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"prod"}}"#,
        )],
    );
    assert!(kubernetes(&plan, "container.resource.delete").is_empty());
    let plan = analyze(
        &["kubectl", "apply", "-f", "list.json"],
        &[(
            "work/list.json",
            r#"{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"one"}},{"apiVersion":"v1","kind":"Secret","metadata":{"name":"two"}}]}"#,
        )],
    );
    assert_eq!(kubernetes(&plan, "container.resource.create").len(), 2);

    let raw = analyze(
        &[
            "kubectl",
            "delete",
            "--raw",
            "/api/v1/namespaces/production",
        ],
        &[],
    );
    assert!(kubernetes(&raw, "container.resource.delete").iter().any(|identity| {
        matches!(identity,
            ResourceIdentity::KubernetesResource { kind, name, namespace: KubernetesNamespace::Cluster, .. }
                if kind == "Namespace"
                    && matches!(name.as_ref(), ResourceExpr::Literal { value } if value == "production"))
    }));
}

#[test]
fn terraform_and_tofu_distinguish_plans_mutations_and_opaque_saved_plans() {
    for tool in ["terraform", "tofu"] {
        for config in [
            include_str!("../fixtures/infrastructure/resources.tf"),
            include_str!("../fixtures/infrastructure/resources.tf.json"),
        ] {
            let file = if config.starts_with('{') {
                "work/main.tf.json"
            } else {
                "work/main.tf"
            };
            for (args, ops) in [
                (vec!["plan"], vec![]),
                (vec!["plan", "-destroy"], vec![]),
                (vec!["apply"], vec!["create", "update", "delete"]),
                (vec!["destroy"], vec!["delete"]),
                (vec!["apply", "-destroy"], vec!["delete"]),
                (vec!["apply", "-refresh-only"], vec![]),
                (vec!["plan", "-refresh-only"], vec![]),
            ] {
                let argv: Vec<_> = std::iter::once(tool).chain(args).collect();
                let plan = analyze(&argv, &[(file, config)]);
                let managed: Vec<_> = plan
                    .effects
                    .iter()
                    .filter_map(|e| match &e.resource {
                        ResourceExpr::Concrete {
                            identity:
                                ResourceIdentity::ManagedInfrastructure {
                                    tool: actual,
                                    address: Some(address),
                                    ..
                                },
                        } => {
                            assert_eq!(actual, tool);
                            assert_eq!(address, "aws_instance.web");
                            Some(e.operation.as_str())
                        }
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::CloudResource { provider, .. },
                        } => {
                            assert_ne!(provider.as_deref(), Some(tool));
                            None
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(managed.len(), ops.len(), "{argv:?} {managed:?}");
                for op in ["create", "update", "delete"] {
                    assert_eq!(
                        has(&plan, &format!("cloud.resource.{op}")),
                        ops.contains(&op),
                        "{argv:?}"
                    );
                }
                assert!(plan.boundaries.iter().any(|boundary| {
                    boundary.class == effinterp_proto::BoundaryClass::Unresolved
                        && boundary.reason == effinterp_proto::BoundaryReason::PROVIDER_IO
                }));
                // The discovered root configuration is the tool's own input, and a
                // consumer that reads access semantics needs the purpose to say so.
                let reads: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.as_str() == "filesystem.read")
                    .collect();
                assert!(!reads.is_empty(), "{argv:?}");
                for read in reads {
                    assert_eq!(
                        read.attributes.get("access_purpose"),
                        Some(&effinterp_proto::AttrValue::String("program_input".into())),
                        "{argv:?} {:?}",
                        read.resource
                    );
                }
            }
        }
        let malformed = analyze(&[tool, "destroy", "-parallelism=invalid"], &[]);
        assert!(malformed.boundaries.iter().any(|boundary| {
            boundary.class == effinterp_proto::BoundaryClass::Unresolved
                && boundary.reason == effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS
        }));
        let missing_root = analyze_with_env(&[tool, "destroy"], &[]);
        assert!(missing_root.boundaries.iter().any(|boundary| {
            boundary.class == effinterp_proto::BoundaryClass::Unresolved
                && boundary.reason == effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS
        }));
        let plan = analyze(&[tool, "plan", "-out", "change.plan"], &[]);
        assert!(has(&plan, "filesystem.write"));
        assert!(!has(&plan, "cloud.resource.delete"));
        let plan = analyze(
            &[tool, "apply", "saved.plan"],
            &[
                ("work/saved.plan", "opaque binary bytes"),
                (
                    "work/main.tf",
                    "resource \"aws_instance\" \"not_in_plan\" {}",
                ),
            ],
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.as_str() == "filesystem.read"
                    && e.attributes.get("access_purpose")
                        == Some(&AttrValue::String("program_input".into())))
        );
        assert!(!has(&plan, "cloud.resource.delete"));
        assert!(!plan.effects.iter().any(|e| matches!(
            &e.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::ManagedInfrastructure { .. }
            }
        )));
    }
}

#[test]
fn destructive_effects_do_not_appear_for_dry_run_or_targeted_iac() {
    for args in [
        vec!["terraform", "destroy", "-target", "aws_instance.web"],
        vec!["terraform", "apply", "-destroy", "-target=module.web"],
        vec!["tofu", "apply", "-destroy", "-exclude", "module.keep"],
        vec![
            "terraform",
            "destroy",
            "-target=module.web[0].aws_instance.api[\"blue\"]",
        ],
    ] {
        let plan = analyze(
            &args,
            &[(
                "work/main.tf",
                "resource \"aws_instance\" \"unselected\" {}",
            )],
        );
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.as_str() == "cloud.resource.delete")
            .collect();
        assert_eq!(deletes.len(), 1, "{args:?}");
        assert_eq!(
            deletes[0].attributes.get("whole_stack"),
            Some(&AttrValue::Bool(false))
        );
        assert!(deletes[0].attributes.contains_key("selectors"));
        assert!(matches!(
            &deletes[0].resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::ManagedInfrastructure { address: None, .. }
            }
        ));
    }
    for args in [
        vec![
            "terraform",
            "apply",
            "-destroy",
            "-replace=aws_instance.web",
        ],
        vec![
            "tofu",
            "destroy",
            "-target=module.web",
            "-exclude=module.keep",
        ],
        vec!["terraform", "destroy", "-target=module"],
        vec!["terraform", "destroy", "-target=aws_instance.web[each.key]"],
        vec!["terraform", "destroy", "-target=aws_instance.web.extra"],
        vec!["terraform", "destroy", "--bogus"],
        vec!["terraform", "destroy", "-minimal-refresh=invalid"],
        vec!["terraform", "destroy", "-minimal-refresh", "-refresh=false"],
        vec!["terraform", "destroy", "-policies"],
        vec!["terraform", "destroy", "-lint=all"],
        vec!["tofu", "destroy", "-minimal-refresh"],
        vec!["tofu", "apply", "-destroy", "-lint"],
        vec!["terraform", "destroy", "-var"],
        vec!["terraform", "destroy", "-parallelism=08"],
        vec!["terraform", "destroy", "-var", "name =value"],
        vec!["tofu", "destroy", "-var", "name =value"],
        vec!["tofu", "apply", "saved.plan"],
    ] {
        let plan = analyze(
            &args,
            &[("work/main.tf", "resource \"aws_instance\" \"web\" {}")],
        );
        assert!(!has(&plan, "cloud.resource.delete"), "{args:?}");
    }
    for args in [
        vec!["terraform", "destroy", "-parallelism=0x4"],
        vec!["terraform", "destroy", "-var", "name=value"],
        vec!["tofu", "destroy", "-var", "name=value"],
    ] {
        let plan = analyze(&args, &[]);
        assert!(has(&plan, "cloud.resource.delete"), "{args:?}");
    }
    for args in [
        vec!["kubectl", "delete", "namespace", "prod", "--dry-run=client"],
        vec!["kubectl", "delete", "pod", "api", "--dry-run=server"],
        vec!["kubectl", "delete", "pod", "api", "--dry-run", "$MODE"],
        vec!["kubectl", "delete", "pod", "api", "--dry-run", "none"],
        vec![
            "kubectl",
            "delete",
            "pod",
            "api",
            "--unknown",
            "--dry-run=none",
        ],
        vec!["kubectl", "delete", "pods", "--all=garbage"],
        vec!["kubectl", "delete", "pod", "api", "--namespace=--help"],
        vec![
            "kubectl",
            "delete",
            "pod",
            "-l",
            "app=one",
            "--selector",
            "app=two",
        ],
    ] {
        let plan = analyze(&args, &[]);
        assert!(!has(&plan, "container.resource.delete"), "{args:?}");
    }
    let plan = analyze(
        &["kubectl", "delete", "namespace", "prod", "--dry-run=none"],
        &[],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "container.resource.delete")
        .expect("active namespace delete");
    assert_eq!(
        delete.attributes.get("mode"),
        Some(&effinterp_proto::AttrValue::String("delete".into()))
    );
    assert_eq!(
        delete.attributes.get("scope"),
        Some(&effinterp_proto::AttrValue::String("namespace".into()))
    );
    assert_eq!(
        delete.attributes.get("selection"),
        Some(&effinterp_proto::AttrValue::String("named".into()))
    );
    // A kind the API server publishes as cluster-scoped carries that scope:
    // removing a definition removes every resource of that kind cluster-wide.
    let plan = analyze(&["kubectl", "delete", "crd", "widgets.example.com"], &[]);
    let definition = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "container.resource.delete")
        .expect("active custom resource definition delete");
    assert_eq!(
        definition.attributes.get("scope"),
        Some(&effinterp_proto::AttrValue::String("cluster".into()))
    );
    assert_eq!(
        delete.attributes.get("active"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(
        delete.attributes.get("dry_run"),
        Some(&effinterp_proto::AttrValue::Bool(false))
    );
    let plan = analyze(
        &[
            "kubectl",
            "delete",
            "pods",
            "-l",
            "app=one",
            "--dry-run=none",
        ],
        &[],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "container.resource.delete")
        .expect("active selector delete");
    assert_eq!(
        delete.attributes.get("selector"),
        Some(&effinterp_proto::AttrValue::String("app=one".into()))
    );
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "kubectl delete pods -l \"$SELECTOR\"".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(!has(&plan, "container.resource.delete"));
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "kubectl \"$FLAG\" delete pod api".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(!has(&plan, "container.resource.delete"));
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "kubectl delete pod api -n \"$NS\"".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(!has(&plan, "container.resource.delete"));
}

#[test]
fn ordinary_apply_delete_is_not_whole_stack_destroy() {
    let plan = analyze(
        &["terraform", "apply"],
        &[("work/main.tf", "resource \"aws_instance\" \"web\" {}")],
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "cloud.resource.delete")
        .expect("apply replacement delete");
    assert_ne!(
        delete.attributes.get("whole_stack"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_ne!(
        delete.attributes.get("mode"),
        Some(&effinterp_proto::AttrValue::String("destroy".into()))
    );
}

#[test]
fn terraform_and_terragrunt_require_a_proven_whole_stack_destroy_request() {
    for argv in [
        vec!["terraform", "destroy"],
        vec!["terraform", "apply", "-destroy"],
        vec!["terraform", "apply", "--destroy", "--auto-approve"],
        vec!["terraform", "destroy", "--"],
        vec!["terraform", "destroy", "--auto-approve"],
        vec!["terraform", "destroy", "-destroy=false"],
        vec!["tofu", "destroy", "-var", "name=value"],
        vec!["tofu", "apply", "--destroy", "--auto-approve"],
        vec!["tofu", "destroy", "-destroy", "-destroy=false"],
        vec!["tofu", "destroy", "-concise", "-consolidate-errors"],
        vec!["tofu", "destroy", "-deprecation=module:none"],
        vec!["tofu", "destroy", "-suppress-forget-errors"],
        vec!["tofu", "destroy", "-consolidate-warnings=false"],
        vec!["tofu", "destroy", "-json-into=out.json"],
        vec!["terraform", "destroy", "-allow-deferral=false"],
        vec!["terraform", "destroy", "-minimal-refresh"],
        vec!["terraform", "destroy", "-policies=policy.hcl"],
        vec!["tofu", "apply", "-destroy", "-lint=all"],
        vec!["terraform", "destroy", "-minimal-refresh=false"],
        vec!["terraform", "destroy", "-policies", "policies"],
        vec![
            "tofu",
            "apply",
            "-destroy",
            "-lint",
            "all,!core:unused-local",
        ],
    ] {
        let plan = analyze(&argv, &[]);
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "cloud.resource.delete")
            .collect();
        assert!(!deletes.is_empty(), "{argv:?}");
        assert!(deletes.iter().all(|effect| {
            effect.request_assurance == RequestAssurance::Exact
                && effect.modality == Modality::May
                && effect.attributes.get("whole_stack") == Some(&AttrValue::Bool(true))
        }));
    }

    let plan = analyze(&["terraform", "apply"], &[]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.request_assurance == RequestAssurance::Conservative
    }));
    for argv in [
        vec!["terraform", "plan", "-destroy"],
        vec!["terraform", "destroy", "-target", "aws_instance.web"],
        vec!["terraform", "destroy", "--bogus"],
        vec!["terraform", "destroy", "-parallelism=08"],
        vec!["terraform", "destroy", "--", "extra"],
        vec!["terraform", "--", "destroy"],
        vec!["terraform", "destroy", "--destroy"],
        vec!["terraform", "destroy", "--no-color"],
        vec!["terraform", "destroy", "-allow-deferral"],
        vec!["tofu", "destroy", "--concise"],
        vec!["tofu", "destroy", "--consolidate-errors"],
        vec!["tofu", "destroy", "--consolidate-warnings=false"],
        vec!["tofu", "destroy", "--deprecation=module:none"],
        vec!["tofu", "destroy", "-concise=false"],
        vec!["tofu", "destroy", "-json", "-json-into=out.json"],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{argv:?}"
        );
    }

    let policy = analyze(&["terraform", "destroy", "-policies=policy.hcl"], &[]);
    assert!(policy.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && effinterp_proto::display_resource(&effect.resource) == "fs:/work/policy.hcl"
            && effect.attributes.get("access_purpose")
                == Some(&AttrValue::String("program_input".into()))
    }));

    let plan = analyze(&["tofu", "destroy", "-json-into=out.json"], &[]);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.write"
                && e.attributes.get("disclosure") == Some(&AttrValue::String("contents".into())))
    );

    let plan = analyze(&["tofu", "destroy", "--bogus", "-json-into=out.json"], &[]);
    assert!(!has(&plan, "filesystem.write"));

    for argv in [
        ["tofu", "destroy", "-json-into=out.json", "--bogus"],
        ["tofu", "destroy", "-json", "-json-into=out.json"],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(has(&plan, "filesystem.write"), "{argv:?}");
    }

    let plan = analyze(
        &["tofu", "apply", "-destroy=true", "-var-file", "dev.tfvars"],
        &[("work/dev.tfvars", "name = \"prod\"")],
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.request_assurance == RequestAssurance::Exact
    }));

    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "terraform destroy".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.request_assurance == RequestAssurance::Exact
    }));

    for argv in [
        vec!["terragrunt", "destroy"],
        vec!["terragrunt", "run", "destroy"],
        vec!["terragrunt", "run", "--", "destroy", "-auto-approve"],
        vec!["terragrunt", "--terragrunt-working-dir", "unit", "destroy"],
    ] {
        let plan = analyze(&argv, &[]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "cloud.resource.delete")
            .unwrap_or_else(|| panic!("missing delete for {argv:?}"));
        assert_eq!(delete.request_assurance, RequestAssurance::Exact);
        assert_eq!(
            delete.attributes.get("whole_stack"),
            Some(&AttrValue::Bool(true))
        );
    }

    let selected = analyze(
        &["terragrunt", "destroy", "--terragrunt-working-dir=unit"],
        &[],
    );
    assert!(selected.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::ManagedInfrastructure {
                        configuration_root,
                        ..
                    }
                } if **configuration_root == effinterp_proto::filesystem_path(
                    "/work/unit",
                    None,
                    effinterp_proto::PathPlatform::Posix,
                )
            )
    }));

    for argv in [
        vec!["terragrunt", "run-all", "destroy"],
        vec!["terragrunt", "run", "--all", "destroy"],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "cloud.resource.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::ManagedInfrastructure {
                            configuration_root,
                            ..
                        }
                    } if matches!(
                        configuration_root.as_ref(),
                        ResourceExpr::Pattern {
                            pattern: effinterp_proto::ResourcePattern::FsPath { glob }
                        } if glob == "/work/**"
                    )
                )
        }));
    }

    let targeted = analyze(&["terragrunt", "destroy", "-target=aws_instance.web"], &[]);
    assert!(targeted.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("whole_stack") == Some(&AttrValue::Bool(false))
            && effect.attributes.contains_key("selectors")
    }));

    let unknown = analyze(
        &["terragrunt", "destroy", "--terragrunt-future-option"],
        &[],
    );
    assert!(!has(&unknown, "cloud.resource.delete"));
    assert!(unknown.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("Terragrunt option"))
    }));
}

#[test]
fn pulumi_exact_assurance_tracks_literal_destroy_selection_controls() {
    for argv in [
        vec![
            "pulumi",
            "-v3",
            "destroy",
            "-sdev",
            "-p4",
            "-mmessage",
            "-cfoo=bar",
            "-r=false",
        ],
        vec!["pulumi", "destroy", "--config", "key=value", "--refresh"],
        vec!["pulumi", "destroy", "--yes"],
        vec!["pulumi", "down", "-yf"],
        vec!["pulumi", "destroy", "--ignore-protect"],
        vec!["pulumi", "destroy", "--ignore-protect=false"],
        vec!["pulumi", "destroy", "--exclude-protected=false"],
        vec!["pulumi", "destroy", "--preview-only=false"],
        vec!["pulumi", "--version", "--version=false", "destroy"],
        vec!["pulumi", "destroy", "--copilot"],
        vec!["pulumi", "destroy", "--otel-traces=file:///tmp/traces.json"],
        vec!["pulumi", "destroy", "--tracing-header=value"],
        vec!["pulumi", "destroy", "--memprofilerate=0x10"],
        vec!["pulumi", "destroy", "--memprofilerate=1_000"],
        vec!["pulumi", "destroy", "--verbose=2147483648"],
        vec!["pulumi", "destroy", "--verbose=-0"],
        vec!["pulumi", "destroy", "--exec-kind=auto.inline"],
        vec!["pulumi", "destroy", "--exec-agent=automation-api"],
        vec!["pulumi", "destroy", "--client=127.0.0.1:1234"],
        vec!["pulumi", "destroy", "--output=json", "--output=default"],
        vec![
            "pulumi",
            "destroy",
            "--override-env=dev=prod",
            "--override-env=qa=stage",
        ],
        vec!["pulumi", "-Qv3", "destroy", "-yp4", "-ysdev"],
    ] {
        let plan = analyze(&argv, &[]);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "cloud.resource.delete")
            .unwrap_or_else(|| panic!("missing delete for {argv:?}"));
        assert_eq!(
            delete.request_assurance,
            RequestAssurance::Exact,
            "{argv:?}"
        );
        assert_eq!(delete.modality, Modality::May, "{argv:?}");
        assert_eq!(
            delete.attributes.get("whole_stack"),
            Some(&AttrValue::Bool(true)),
            "{argv:?}"
        );
        assert!(matches!(
            delete.resource,
            ResourceExpr::Unresolved { ref family } if family.0 == "cloud"
        ));
    }

    for argv in [
        vec!["pulumi", "destroy", "--exclude-protected"],
        vec!["pulumi", "destroy", "--exclude", "urn:skip"],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected",
            "--exclude",
            "urn:skip",
        ],
        vec![
            "pulumi",
            "destroy",
            "--ignore-protect",
            "--exclude",
            "urn:skip",
        ],
        vec!["pulumi", "destroy", "--target", "urn:only"],
        vec![
            "pulumi",
            "destroy",
            "--target",
            "urn:only",
            "--exclude-protected=false",
        ],
    ] {
        let plan = analyze(&argv, &[]);
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "cloud.resource.delete")
            .collect();
        assert!(!deletes.is_empty(), "{argv:?}");
        assert!(
            deletes.iter().all(|effect| {
                effect.request_assurance == RequestAssurance::Exact
                    && effect.modality == Modality::May
                    && effect.attributes.get("whole_stack") == Some(&AttrValue::Bool(false))
            }),
            "{argv:?}"
        );
    }

    for (flag, attribute) in [("--target", "target"), ("--exclude", "exclude")] {
        let plan = analyze(
            &["pulumi", "destroy", flag, "urn:first", flag, "urn:second"],
            &[],
        );
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "cloud.resource.delete")
            .collect();
        assert_eq!(deletes.len(), 2, "{flag}");
        for (effect, value) in deletes.into_iter().zip(["urn:first", "urn:second"]) {
            assert_eq!(effect.request_assurance, RequestAssurance::Exact);
            assert_eq!(
                effect.attributes.get(attribute),
                Some(&AttrValue::String(value.into()))
            );
        }
    }

    let plan = analyze(
        &[
            "pulumi",
            "destroy",
            "--target",
            "urn:first",
            "-t",
            "urn:second",
        ],
        &[],
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "cloud.resource.delete")
            .count(),
        2
    );
    assert!(plan.effects.iter().all(|effect| {
        effect.operation.as_str() != "cloud.resource.delete"
            || effect.request_assurance == RequestAssurance::Exact
    }));

    let protected = analyze(&["pulumi", "destroy", "--exclude-protected"], &[]);
    let delete = protected
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "cloud.resource.delete")
        .expect("unprotected destroy request");
    assert_eq!(
        delete.attributes.get("exclude_protected"),
        Some(&AttrValue::Bool(true))
    );

    for argv in [
        vec!["pulumi", "destroy", "--preview-only"],
        vec!["pulumi", "destroy", "--help"],
        vec!["pulumi", "destroy", "--unknown"],
        vec!["pulumi", "destroy", "--yes=bogus"],
        vec!["pulumi", "destroy", "--target="],
        vec!["pulumi", "destroy", "--exclude="],
        vec!["pulumi", "destroy", "extra"],
        vec![
            "pulumi",
            "destroy",
            "--target",
            "urn:only",
            "--exclude",
            "urn:skip",
        ],
        vec![
            "pulumi",
            "destroy",
            "--target",
            "urn:only",
            "--exclude-protected",
        ],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected",
            "--ignore-protect",
        ],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected=false",
            "--ignore-protect=false",
        ],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected=false",
            "--ignore-protect",
        ],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected",
            "--ignore-protect=false",
        ],
        vec![
            "pulumi", "destroy", "--target", "urn:only", "-x", "urn:skip",
        ],
        vec![
            "pulumi",
            "destroy",
            "-t",
            "urn:only",
            "--exclude",
            "urn:skip",
        ],
        vec!["pulumi", "destroy", "-t", "urn:only", "-x", "urn:skip"],
        vec!["pulumi", "destroy", "--parallel=garbage"],
        vec!["pulumi", "destroy", "--parallel=-1"],
        vec!["pulumi", "destroy", "--parallel=2147483648"],
        vec!["pulumi", "destroy", "--memprofilerate=08"],
        vec!["pulumi", "destroy", "--verbose=08"],
        vec!["pulumi", "destroy", "--verbose=9223372036854775808"],
        vec!["pulumi", "destroy", "--color=invalid"],
        vec!["pulumi", "destroy", "--refresh=invalid"],
        vec!["pulumi", "destroy", "-r", "false"],
        vec!["pulumi", "destroy", "-c"],
        vec!["pulumi", "destroy", "--suppress-permalink=invalid"],
        vec!["pulumi", "--version", "destroy"],
        vec!["pulumi", "--version=false", "--version", "destroy"],
        vec!["pulumi", "destroy", "--otel-traces"],
        vec!["pulumi", "destroy", "--tracing-header"],
        vec!["pulumi", "destroy", "--exec-kind"],
        vec!["pulumi", "destroy", "--exec-agent"],
        vec!["pulumi", "destroy", "--client"],
        vec!["pulumi", "destroy", "--output=invalid"],
        vec!["pulumi", "destroy", "--output=default", "--output=invalid"],
        vec!["pulumi", "destroy", "--output=invalid", "--output=json"],
        vec!["pulumi", "destroy", "--json", "--output=default"],
        vec!["pulumi", "destroy", "--override-env=dev"],
        vec![
            "pulumi",
            "destroy",
            "--override-env=dev=prod",
            "--override-env=qa",
        ],
        vec![
            "pulumi",
            "destroy",
            "--override-env=dev",
            "--override-env=qa=stage",
        ],
        vec!["pulumi", "destroy", "--override-env==prod"],
        vec!["pulumi", "destroy", "--override-env=dev="],
        vec!["pulumi", "-vgarbage", "destroy"],
        vec!["pulumi", "destroy", "-pgarbage"],
        vec!["pulumi", "destroy", "-p0"],
        vec!["pulumi", "destroy", "-p2147483648"],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(!has(&plan, "cloud.resource.delete"), "{argv:?}");
        assert!(!plan.boundaries.is_empty(), "{argv:?}");
    }

    for source in [
        "pulumi destroy --target \"$TARGET\"",
        "pulumi destroy --message \"$MESSAGE\"",
        "pulumi destroy --stack \"$STACK\"",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(has(&plan, "cloud.resource.delete"), "{source}");
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{source}"
        );
        // A selector this pass cannot read leaves the stack it destroys
        // unestablished, so the destroy is not stated as a whole one.
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.attributes.get("whole_stack") == Some(&AttrValue::Bool(true))
            }),
            "{source}"
        );
    }
}

#[test]
fn terraform_cli_argument_environment_requires_safe_literal_grammar() {
    let absent = analyze_with_env(&["terraform", "destroy"], &[]);
    for name in ["TF_CLI_ARGS", "TF_CLI_ARGS_destroy"] {
        assert!(absent.effects.iter().any(|effect| {
            effect.operation.as_str() == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name: actual }
                } if actual == name)
        }));
    }
    let plan = analyze_with_env(
        &["terraform", "destroy"],
        &[("TF_CLI_ARGS_destroy", "-refresh=false")],
    );
    assert!(has(&plan, "cloud.resource.delete"));
    let plan = analyze_with_env(
        &["terraform", "destroy"],
        &[("TF_CLI_ARGS_destroy", "-bogus")],
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("whole_stack") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));
    let plan = analyze_with_env(
        &["terraform", "destroy"],
        &[("TF_CLI_ARGS_destroy", "'unterminated")],
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("active") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));
    let plan = analyze_with_env(
        &["terraform", "destroy"],
        &[("TF_CLI_ARGS_destroy", "\"\"")],
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("active") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));
    let plan = analyze_with_env(
        &["terraform", "destroy"],
        &[("TF_CLI_ARGS", "-auto-approve -parallelism=2")],
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("whole_stack") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));
    for value in [";", "2>/tmp/log", "2foo>/tmp/log", "\"2\">/tmp/log"] {
        let plan = analyze_with_env(&["terraform", "destroy"], &[("TF_CLI_ARGS", value)]);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{value:?}"
        );
    }
    for value in ["-backup `foo bar`", "-backup=))"] {
        let plan = analyze_with_env(&["terraform", "destroy"], &[("TF_CLI_ARGS", value)]);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{value:?}"
        );
    }
    let plan = analyze_with_env(
        &["terraform", "apply"],
        &[("TF_CLI_ARGS_apply", "--destroy --auto-approve")],
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.request_assurance == RequestAssurance::Exact
    }));
    for value in [
        "2</tmp/log",
        "foo>/tmp/log",
        "`echo -n`",
        "$(echo -n)",
        "\u{b}",
    ] {
        let plan = analyze_with_env(&["terraform", "destroy"], &[("TF_CLI_ARGS", value)]);
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{value:?}"
        );
    }
    let plan = analyze_with_env(
        &["terraform", "apply"],
        &[
            ("TF_CLI_ARGS", "-destroy=false"),
            ("TF_CLI_ARGS_apply", "-destroy"),
        ],
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("whole_stack") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));
    let plan = analyze_with_env(
        &["terraform", "apply"],
        &[
            ("TF_CLI_ARGS", "-destroy"),
            ("TF_CLI_ARGS_apply", "-destroy=false"),
        ],
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "cloud.resource.delete"
            && effect.attributes.get("whole_stack") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));

    for (index, context) in [
        Default::default(),
        effinterp_proto::HostContext {
            env_unset: ["OPTIONS".into()].into_iter().collect(),
            ..Default::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: "TF_CLI_ARGS_destroy=\"$OPTIONS\" terraform destroy".into(),
                cwd: Some("/work".into()),
                context,
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            }),
            "{index}: {:?}",
            plan.boundaries
        );
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "cloud.resource.delete"
                && effect.attributes.get("whole_stack")
                    == Some(&effinterp_proto::AttrValue::Bool(true))
        }));
    }
}

#[test]
fn terraform_separated_chdir_is_not_certified() {
    // A -chdir without a directory, a second -chdir left in front of the
    // subcommand, and a version flag each stop terraform before it reads
    // configuration or starts a provider, so no cloud request or provider
    // boundary may survive.
    for argv in [
        vec!["terraform", "-chdir", "/tmp/config", "destroy"],
        vec!["terraform", "-chdir=one", "-chdir=two", "destroy"],
        vec!["terraform", "destroy", "-var", "-v"],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str().starts_with("cloud.")),
            "{argv:?}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::PROVIDER_IO),
            "{argv:?}"
        );
    }
    // The last -chdir=DIR still selects the configuration root it names.
    let plan = analyze(&["terraform", "-chdir=environments/dev", "destroy"], &[]);
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "cloud.resource.delete")
    );
}

#[test]
fn symbolic_positional_namespace_name_does_not_certify_namespace_scope() {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "kubectl delete namespace \"$TARGET\" --dry-run=none".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "container.resource.delete")
        .expect("symbolic namespace request remains represented");
    assert_eq!(
        delete.attributes.get("scope"),
        Some(&effinterp_proto::AttrValue::String("unknown".into()))
    );
    assert_eq!(
        delete.attributes.get("active"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn symbolic_modes_cannot_prove_mutations_suppressed() {
    for source in [
        "kubectl delete \"$TYPE\" web",
        "kubectl delete \"$TYPE\" web api",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(has(&plan, "container.resource.delete"));
        assert!(!plan.boundaries.is_empty());
    }
    for (source, operation) in [
        (
            "kubectl apply -f missing.yaml --dry-run=\"$MODE\"",
            "container.resource.update",
        ),
        (
            "terraform apply -refresh-only=\"$MODE\"",
            "cloud.resource.update",
        ),
        (
            "aws ec2 stop-instances --instance-ids i-one --dry-run=\"$MODE\"",
            "cloud.resource.stop",
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(has(&plan, operation), "{source}");
        assert!(!plan.boundaries.is_empty());
    }
    for mode in ["$MODE", "bogus"] {
        for (command, operations, named_targets) in [
            (
                format!("kubectl delete pod api --dry-run={mode}"),
                vec![],
                0,
            ),
            (
                format!("kubectl delete --dry-run={mode} pod api"),
                vec![],
                0,
            ),
            (
                format!("kubectl apply --dry-run={mode} -f objects.yaml"),
                vec!["container.resource.create", "container.resource.update"],
                2,
            ),
            (
                format!("kubectl delete pod api --unknown --dry-run={mode}"),
                vec![],
                0,
            ),
        ] {
            let plan = Engine::new()
                .with_resolver(Box::new(Sources(BTreeMap::from([(
                    "work/objects.yaml".into(),
                    MANIFEST.into(),
                )]))))
                .analyze(&Subject::Shell {
                    source: command.clone(),
                    cwd: Some("/work".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            for operation in operations {
                assert!(has(&plan, operation), "{command}");
                assert_eq!(
                    kubernetes(&plan, operation).len(),
                    named_targets,
                    "{command}"
                );
            }
            assert!(has(&plan, "network.request"), "{command}");
            assert!(
                plan.boundaries.iter().any(|b| b.reason
                    == effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS
                    && b.domains.iter().any(|d| d.0 == "network")),
                "{command}"
            );
        }
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "kubectl delete deployment/\"$NAME\" -n prod".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(plan.effects.iter().any(|e| matches!(&e.resource,ResourceExpr::Concrete { identity:ResourceIdentity::KubernetesResource { kind, name, .. }} if kind == "Deployment" && !matches!(name.as_ref(), ResourceExpr::Literal { .. }))));
}

#[test]
fn terraform_option_values_follow_the_cli_grammar() {
    // Go durations, flag-package booleans with the last occurrence winning,
    // and the exact words stripped before option parsing.
    for argv in [
        vec!["terraform", "destroy", "-lock-timeout=1h30m"],
        vec!["terraform", "destroy", "-lock-timeout", "1.5s"],
        vec!["terraform", "destroy", "-lock-timeout=0"],
        vec!["terraform", "destroy", "-no-color", "-compact-warnings"],
        vec![
            "terraform",
            "destroy",
            "-allow-deferral",
            "-allow-deferral=false",
        ],
        vec!["tofu", "apply", "-destroy=true", "-auto-approve=true"],
        vec!["terraform", "destroy", "-auto-approve=false"],
        vec![
            "tofu",
            "destroy",
            "-show-sensitive",
            "-deprecation=module:none",
        ],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
                    && effect.attributes.get("whole_stack") == Some(&AttrValue::Bool(true))
            }),
            "{argv:?}"
        );
    }
    for argv in [
        vec!["terraform", "destroy", "-lock-timeout=1h30"],
        vec!["terraform", "destroy", "-lock-timeout=1.2.3s"],
        vec![
            "terraform",
            "destroy",
            "-allow-deferral=false",
            "-allow-deferral",
        ],
        vec!["terraform", "destroy", "-auto-approve=maybe"],
        vec!["tofu", "destroy", "-compact-warnings=false"],
        vec!["terraform", "destroy", "-show-sensitive"],
    ] {
        let plan = analyze(&argv, &[]);
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "cloud.resource.delete"
                    && effect.request_assurance == RequestAssurance::Exact
            }),
            "{argv:?}"
        );
    }
}

#[test]
fn pulumi_parallel_accepts_go_base_prefixed_integers() {
    // pflag parses `--parallel` with base-0 `strconv.ParseInt`.
    for (value, parsed) in [
        ("0x4", true),
        ("0x_4", true),
        ("0o7", true),
        ("4", true),
        ("0x__4", false),
        ("08", false),
        ("0", false),
    ] {
        let parallel = format!("--parallel={value}");
        let plan = analyze(&["pulumi", "destroy", &parallel], &[]);
        assert_eq!(has(&plan, "cloud.resource.delete"), parsed, "{value}");
    }
}

fn delete_scopes(plan: &Plan) -> Vec<&AttrValue> {
    plan.effects
        .iter()
        .filter(|e| e.operation.as_str() == "container.resource.delete")
        .filter_map(|e| e.attributes.get("scope"))
        .collect()
}

#[test]
fn kubectl_short_option_clusters_and_global_options_reach_the_delete() {
    // pflag splits `-nplatform`, `-v6` and `-oname` into option and value;
    // connection, identity and output options leave the request intact.
    for argv in [
        vec![
            "kubectl",
            "-nplatform",
            "-v6",
            "delete",
            "namespace",
            "production",
            "-oname",
        ],
        vec![
            "kubectl",
            "delete",
            "namespace",
            "production",
            "--now",
            "--timeout=30s",
        ],
        vec![
            "kubectl",
            "--cluster",
            "production",
            "--token",
            "token",
            "--as",
            "operator",
            "--as-group",
            "admins",
            "--as-uid",
            "1000",
            "--as-user-extra",
            "scope=release",
            "--profile",
            "none",
            "--profile-output",
            "/tmp/profile",
            "--v=6",
            "delete",
            "namespace",
            "production",
            "--interactive=false",
        ],
    ] {
        let plan = analyze(&argv, &[]);
        assert_eq!(
            kubernetes(&plan, "container.resource.delete").len(),
            1,
            "{argv:?}"
        );
        assert!(
            delete_scopes(&plan)
                .iter()
                .all(|scope| **scope == AttrValue::String("namespace".into())),
            "{argv:?}"
        );
    }
    let plan = analyze(&["kubectl", "-nplatform", "delete", "pod", "api"], &[]);
    assert!(matches!(
        kubernetes(&plan, "container.resource.delete")[..],
        [ResourceIdentity::KubernetesResource { namespace: KubernetesNamespace::Namespaced { namespace }, .. }]
            if **namespace == ResourceExpr::Literal { value: "platform".into() }
    ));
    // `-A`, `-i` and `-l` share one word; the selector takes the rest.
    let plan = analyze(&["kubectl", "delete", "pods", "-Ailapp=web"], &[]);
    let delete = plan
        .effects
        .iter()
        .find(|e| e.operation.as_str() == "container.resource.delete")
        .unwrap();
    assert_eq!(
        delete.attributes.get("selector"),
        Some(&AttrValue::String("app=web".into()))
    );
    assert_eq!(
        delete.attributes.get("all_namespaces"),
        Some(&AttrValue::Bool(true))
    );
    // A selector option with no value and an unknown shorthand stop the parse.
    for argv in [
        vec!["kubectl", "delete", "pods", "-Ail"],
        vec!["kubectl", "delete", "pods", "-Qlapp=web"],
    ] {
        assert!(
            !has(&analyze(&argv, &[]), "container.resource.delete"),
            "{argv:?}"
        );
    }
}

#[test]
fn kubectl_kind_lists_and_selected_namespaces_are_namespace_deletions() {
    // `TYPE1,TYPE2 NAME...` names each type once per name, and aliases of one
    // kind collapse to the same objects.
    let plan = analyze(
        &["kubectl", "delete", "namespace,ns", "production", "preview"],
        &[],
    );
    assert_eq!(kubernetes(&plan, "container.resource.delete").len(), 2);
    let plan = analyze(&["kubectl", "delete", "pod,service", "baz", "foo"], &[]);
    assert_eq!(kubernetes(&plan, "container.resource.delete").len(), 4);
    // A selected namespace set deletes whole namespaces.
    let plan = analyze(
        &["kubectl", "delete", "ns", "-l", "environment=preview"],
        &[],
    );
    assert_eq!(
        delete_scopes(&plan),
        [&AttrValue::String("namespace".into())]
    );
}
