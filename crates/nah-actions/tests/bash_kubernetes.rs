mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use support::{bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn kubernetes_codes(source: &str) -> Vec<SemanticCode> {
    stream(source)
        .effects()
        .iter()
        .filter_map(|effect| match effect.kind() {
            EffectKind::SystemState { operation }
                if operation == &SemanticCode::INFRA_K8S_NAMESPACE_DELETE
                    || operation == &SemanticCode::INFRA_K8S_CLUSTER_RESOURCE_DELETE
                    || operation == &SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE =>
            {
                Some(operation.clone())
            }
            _ => None,
        })
        .collect()
}

fn has_code(source: &str, code: &SemanticCode) -> bool {
    kubernetes_codes(source).contains(code)
}

#[test]
fn namespace_deletion_forms_and_aliases_are_recognized() {
    for source in [
        "kubectl delete namespace production",
        "kubectl delete namespaces --all",
        "kubectl delete ns -l environment=preview",
        "kubectl delete namespace/production",
        "kubectl delete namespace,ns production preview",
    ] {
        assert!(
            has_code(source, &SemanticCode::INFRA_K8S_NAMESPACE_DELETE),
            "{source}"
        );
        assert_eq!(stream(source).coverage(), Coverage::Full, "{source}");
    }
}

#[test]
fn reviewed_cluster_resource_aliases_are_recognized_for_named_and_bulk_deletes() {
    for resource in [
        "node",
        "nodes",
        "no",
        "persistentvolume",
        "persistentvolumes",
        "pv",
        "customresourcedefinition",
        "customresourcedefinitions",
        "crd",
        "crds",
        "clusterrole",
        "clusterroles",
        "clusterrolebinding",
        "clusterrolebindings",
    ] {
        for source in [
            format!("kubectl delete {resource} selected"),
            format!("kubectl delete {resource}/selected"),
            format!("kubectl delete {resource} --all"),
        ] {
            assert!(
                has_code(&source, &SemanticCode::INFRA_K8S_CLUSTER_RESOURCE_DELETE),
                "{source}"
            );
            assert_eq!(stream(&source).coverage(), Coverage::Full, "{source}");
        }
    }
}

#[test]
fn reviewed_namespaced_aliases_are_recognized_only_for_bulk_selection() {
    for resource in [
        "all",
        "pod",
        "pods",
        "po",
        "deployment",
        "deployments",
        "deploy",
        "statefulset",
        "statefulsets",
        "sts",
        "daemonset",
        "daemonsets",
        "ds",
        "replicaset",
        "replicasets",
        "rs",
        "job",
        "jobs",
        "cronjob",
        "cronjobs",
        "cj",
        "service",
        "services",
        "svc",
        "configmap",
        "configmaps",
        "cm",
        "secret",
        "secrets",
        "persistentvolumeclaim",
        "persistentvolumeclaims",
        "pvc",
        "ingress",
        "ingresses",
        "ing",
        "role",
        "roles",
        "rolebinding",
        "rolebindings",
        "serviceaccount",
        "serviceaccounts",
        "sa",
    ] {
        let source = format!("kubectl delete {resource} --all");
        assert!(
            has_code(&source, &SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE),
            "{source}"
        );
        assert_eq!(stream(&source).coverage(), Coverage::Full, "{source}");
    }

    for source in [
        "kubectl delete pods -l app=web",
        "kubectl delete deployment --selector=app=web",
        "kubectl delete jobs --field-selector status.successful=1",
        "kubectl delete service -A --all",
        "kubectl delete pods -Ailapp=web",
    ] {
        assert!(
            has_code(source, &SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE),
            "{source}"
        );
        assert_eq!(stream(source).coverage(), Coverage::Full, "{source}");
    }
}

#[test]
fn named_application_deletes_and_unrelated_commands_are_full_delegates() {
    for source in [
        "kubectl delete pod api",
        "kubectl delete deployment/web",
        "kubectl delete pod,service api worker",
        "kubectl get pods --all-namespaces",
        "kubectl apply -f deployment.yaml",
        "kubectl version",
        "kubectl options",
        "kubectl --help",
        "kubectl delete pods --help",
        "kubectl delete pods --help=false --all=false api",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(kubernetes_codes(source).is_empty(), "{source}");
    }
}

#[test]
fn inherited_connection_and_delete_options_do_not_make_deletion_safer() {
    for source in [
        "kubectl --context=production --cluster production --server https://cluster.example --kubeconfig /tmp/config --certificate-authority /tmp/ca --client-certificate /tmp/cert --client-key /tmp/key --token token --as operator --as-group admins --as-uid 1000 --as-user-extra scope=release --profile none --profile-output /tmp/profile --request-timeout 5s --namespace platform --v=6 delete namespace production --output name --force --grace-period 0 --cascade=foreground --wait=false --interactive=false",
        "kubectl delete --namespace platform --context production --cluster production --server=https://cluster.example --kubeconfig=/tmp/config --token=token namespace production",
        "kubectl -nplatform -v6 delete namespace production -oname",
        "kubectl delete namespace production --now --ignore-not-found=false --timeout=30s",
    ] {
        assert!(
            has_code(source, &SemanticCode::INFRA_K8S_NAMESPACE_DELETE),
            "{source}"
        );
        assert_eq!(stream(source).coverage(), Coverage::Full, "{source}");
    }
    assert!(has_code(
        "KUBECONFIG=/tmp/config kubectl delete namespace production",
        &SemanticCode::INFRA_K8S_NAMESPACE_DELETE
    ));
}

#[test]
fn client_and_server_dry_runs_do_not_emit_deletion_evidence() {
    for source in [
        "kubectl delete namespace production --dry-run=client",
        "kubectl delete nodes --all --dry-run=server",
        "kubectl delete pods -l app=web --dry-run=client",
    ] {
        assert_eq!(stream(source).coverage(), Coverage::Full, "{source}");
        assert!(kubernetes_codes(source).is_empty(), "{source}");
    }
    assert!(has_code(
        "kubectl delete namespace production --dry-run=none",
        &SemanticCode::INFRA_K8S_NAMESPACE_DELETE
    ));
}

#[test]
fn mixed_resource_kinds_keep_proven_codes_and_partial_coverage() {
    let source = "kubectl delete namespace,node,pods,widgets -l app=retired";
    let stream = stream(source);
    assert_eq!(stream.coverage(), Coverage::Partial);
    let codes = kubernetes_codes(source);
    for expected in [
        SemanticCode::INFRA_K8S_NAMESPACE_DELETE,
        SemanticCode::INFRA_K8S_CLUSTER_RESOURCE_DELETE,
        SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE,
    ] {
        assert!(codes.contains(&expected), "missing {}", expected.as_str());
    }
}

#[test]
fn external_dynamic_unknown_and_malformed_selections_are_partial_without_evidence() {
    for source in [
        "kubectl delete -f deployment.yaml",
        "kubectl delete --filename=-",
        "kubectl delete -R -f manifests",
        "kubectl delete -k overlays/prod",
        "kubectl delete --raw /api/v1/namespaces/production",
        "kubectl delete namespace \"$TARGET\"",
        "kubectl delete \"$TYPE\" production",
        "kubectl delete widgets retired",
        "kubectl delete pods",
        "kubectl delete",
        "kubectl delete pods --selector",
        "kubectl delete namespace production --unknown-selection=value",
        "kubectl delete namespace production --dry-run",
        "kubectl delete namespace production --dry-run=unchanged",
        "kubectl delete namespace production --all=maybe",
        "kubectl delete namespace production --all",
        "kubectl delete pod/api --all",
        "kubectl delete pods --all --selector app=web",
        "PATH=/tmp kubectl delete namespace production",
        "env PATH=/tmp kubectl delete namespace production",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(kubernetes_codes(source).is_empty(), "{source}");
    }
}

#[test]
fn wrappers_and_standard_paths_preserve_kubectl_identity() {
    for source in [
        "sudo kubectl delete namespace production",
        "timeout 5 kubectl delete pv data",
        "env kubectl delete pods --all",
        "command kubectl delete nodes worker",
        "/bin/kubectl delete namespace production",
        "/sbin/kubectl delete nodes worker",
        "/usr/bin/kubectl delete pods --all",
        "/usr/sbin/kubectl delete pv data",
        "PATH=/tmp /usr/bin/kubectl delete namespace production",
    ] {
        assert!(!kubernetes_codes(source).is_empty(), "{source}");
    }
}

#[test]
fn arbitrary_kubectl_lookalikes_and_other_kubernetes_clis_stay_outside() {
    for source in [
        "/tmp/kubectl delete namespace production",
        "./kubectl delete namespace production",
        "/usr/local/bin/kubectl delete namespace production",
        "oc delete namespace production",
        "kubeadm reset",
        "helm uninstall release",
        "kind delete cluster",
        "k3d cluster delete dev",
        "minikube delete",
    ] {
        assert!(kubernetes_codes(source).is_empty(), "{source}");
    }
}
