//! Realm identity is lossless and realm selectors can target every
//! disambiguating field. Two realms that differ in any namespace-disambiguating
//! field (runtime, name, namespace, pod, container, host_root, endpoint) are
//! distinct contexts and must never be conflated by dedup or filtering.
//!
//! Two dimensions are exercised here:
//! - The reach(, None) pipeline, for realms a frontend actually emits today
//!   (container runtime/name). The public `ReachHit.realm` string is exactly
//!   the dedup key, so it observes `realm_key` losslessness directly.
//! - `RealmFilter::matches` against hand-built realms, for Kubernetes
//!   namespace/container, chroot host_root, and remote endpoints — realms no
//!   frontend emits yet, so their identity cannot travel through the pipeline.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_proto::ExecutionRealm;
use effinterp_repo::{IndexLimits, RealmFilter, Selector, build_index, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn count(root: &Path, selector: &str) -> usize {
    let idx = build_index(root, IndexLimits::default());
    reach(&idx, &Selector::parse(selector).unwrap(), None)
        .payload
        .as_reach()
        .unwrap()
        .matches
        .len()
}

fn realms(root: &Path, selector: &str) -> Vec<String> {
    let idx = build_index(root, IndexLimits::default());
    let mut r: Vec<String> = reach(&idx, &Selector::parse(selector).unwrap(), None)
        .payload
        .into_reach()
        .unwrap()
        .matches
        .into_iter()
        .map(|h| match h.fact.realm {
            ExecutionRealm::Host => "host".to_string(),
            ExecutionRealm::Container { runtime, name } => {
                format!("container/{runtime}/{name}")
            }
            ExecutionRealm::Kubernetes {
                namespace,
                pod,
                container,
            } => format!(
                "kubernetes/{}/{pod}/{}",
                namespace.unwrap_or_default(),
                container.unwrap_or_default()
            ),
            ExecutionRealm::Chroot { host_root } => {
                format!("chroot/{}", host_root.unwrap_or_default())
            }
            ExecutionRealm::Remote { endpoint } => format!("remote/{endpoint}"),
        })
        .collect();
    r.sort();
    r.dedup();
    r
}

fn filter(selector: &str) -> RealmFilter {
    Selector::parse(selector).unwrap().realm
}

// --- realm_key losslessness (observed via the reach pipeline) ----------------

#[test]
fn container_runtime_is_part_of_realm_identity() {
    // Two entrypoints touch the same global table from same-named containers
    // under different runtimes. Their realms must not collapse.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "realm-id-runtime",
        &[
            (
                "docker.sh",
                "#!/bin/sh\ndocker exec pg psql -c 'UPDATE public.users SET x=1'\n",
            ),
            (
                "podman.sh",
                "#!/bin/sh\npodman exec pg psql -c 'UPDATE public.users SET x=1'\n",
            ),
        ],
    );
    // The reach `realm` field is the dedup key; distinct runtimes stay distinct.
    assert_eq!(
        realms(&root, "any-realm/db:public.users"),
        vec![
            "container/docker/pg".to_string(),
            "container/podman/pg".to_string()
        ],
    );
}

// --- runtime-qualified container selectors -----------------------------------

#[test]
fn runtime_qualified_container_selector() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "realm-id-docker",
        &[(
            "run.sh",
            "#!/bin/sh\ndocker exec pg psql -c 'UPDATE public.users SET x=1'\n",
        )],
    );
    // Runtime-qualified and matching runtime.
    assert_eq!(count(&root, "container:docker:pg/db:public.users"), 1);
    // Bare name still matches regardless of runtime.
    assert_eq!(count(&root, "container:pg/db:public.users"), 1);
    // Wrong runtime excludes it.
    assert_eq!(count(&root, "container:podman:pg/db:public.users"), 0);
}

// --- remote selector (matches against a hand-built Remote realm) -------------

#[test]
fn remote_selector_matches_remote_and_excludes_host() {
    let f = filter("remote:host.example/fs:/x");
    assert_eq!(
        f,
        RealmFilter::Remote {
            endpoint: "host.example".to_string()
        }
    );
    assert!(f.matches(&ExecutionRealm::Remote {
        endpoint: "host.example".to_string()
    }));
    assert!(!f.matches(&ExecutionRealm::Remote {
        endpoint: "other.example".to_string()
    }));
    assert!(!f.matches(&ExecutionRealm::Host));
}

// --- Kubernetes namespace / container disambiguation -------------------------

fn k8s(namespace: Option<&str>, pod: &str, container: Option<&str>) -> ExecutionRealm {
    ExecutionRealm::Kubernetes {
        namespace: namespace.map(str::to_string),
        pod: pod.to_string(),
        container: container.map(str::to_string),
    }
}

#[test]
fn pod_namespace_disambiguates() {
    // Namespace-qualified selector distinguishes two pods that differ ONLY in
    // namespace, and must not conflate them.
    let f = filter("pod:prod:web/fs:/data");
    assert!(f.matches(&k8s(Some("prod"), "web", None)));
    assert!(!f.matches(&k8s(Some("staging"), "web", None)));

    // A bare pod selector ignores namespace and container: both match.
    let bare = filter("pod:web/fs:/data");
    assert!(bare.matches(&k8s(Some("prod"), "web", None)));
    assert!(bare.matches(&k8s(Some("staging"), "web", None)));
    assert!(bare.matches(&k8s(None, "web", Some("sidecar"))));
}

#[test]
fn pod_container_disambiguates() {
    let f = filter("pod:prod:web:app/fs:/data");
    assert_eq!(
        f,
        RealmFilter::Pod {
            namespace: Some("prod".to_string()),
            pod: "web".to_string(),
            container: Some("app".to_string()),
        }
    );
    assert!(f.matches(&k8s(Some("prod"), "web", Some("app"))));
    // Same namespace and pod but a different container is a different context.
    assert!(!f.matches(&k8s(Some("prod"), "web", Some("sidecar"))));
    // A missing container cannot satisfy a container-qualified selector.
    assert!(!f.matches(&k8s(Some("prod"), "web", None)));
}

// --- chroot host_root disambiguation -----------------------------------------

#[test]
fn chroot_selector_matches_any_chroot() {
    let f = filter("chroot/fs:/etc/passwd");
    assert_eq!(f, RealmFilter::Chroot);
    assert!(f.matches(&ExecutionRealm::Chroot { host_root: None }));
    assert!(f.matches(&ExecutionRealm::Chroot {
        host_root: Some("/jail".to_string())
    }));
    assert!(!f.matches(&ExecutionRealm::Host));
}

// --- existing forms still behave ---------------------------------------------

#[test]
fn existing_forms_unchanged() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "realm-id-existing",
        &[
            (
                "host.sh",
                "#!/bin/sh\nrm /etc/passwd\ndocker exec web sh -c 'rm /etc/nginx.conf'\n",
            ),
            (
                "db.sh",
                "#!/bin/sh\ndocker exec pg psql -c 'UPDATE public.users SET x=1'\n",
            ),
        ],
    );
    // host/fs is host-only.
    assert_eq!(count(&root, "host/fs:/etc/passwd"), 1);
    // container:<name>/fs targets the container path.
    assert_eq!(count(&root, "container:web/fs:/etc/nginx.conf"), 1);
    // any-realm and unqualified db both span realms.
    assert_eq!(count(&root, "any-realm/db:public.users"), 1);
    assert_eq!(count(&root, "db:public.users"), 1);
    // Unqualified fs stays host-only (excludes the container write).
    assert_eq!(count(&root, "fs:/etc/nginx.conf"), 0);
}

#[test]
fn realm_filter_wildcards_do_not_turn_missing_requested_fields_into_hits() {
    use effinterp_proto::{Match, MatchReason};
    let selector = Selector::parse("container:c/fs:/tmp").unwrap();
    for runtime in ["docker", "podman"] {
        assert!(matches!(
            selector.realm.evaluate(&ExecutionRealm::Container {
                runtime: runtime.into(),
                name: "c".into()
            }),
            Match::Satisfied { .. }
        ));
    }
    let pod = ExecutionRealm::Kubernetes {
        namespace: None,
        pod: "worker".into(),
        container: None,
    };
    assert!(matches!(
        Selector::parse("pod:worker/fs:/tmp")
            .unwrap()
            .realm
            .evaluate(&pod),
        Match::Satisfied { .. }
    ));
    assert_eq!(
        Selector::parse("pod:production:worker/fs:/tmp")
            .unwrap()
            .realm
            .evaluate(&pod),
        Match::Indeterminate {
            reason: MatchReason::UnderqualifiedRealm
        }
    );
    assert_eq!(
        Selector::parse("pod:production:other/fs:/tmp")
            .unwrap()
            .realm
            .evaluate(&pod),
        Match::NotSatisfied
    );
}
