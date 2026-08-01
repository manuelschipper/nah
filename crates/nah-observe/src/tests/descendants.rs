use super::support::{init_repo, request, value};
use crate::fulfill;
use nah_proto::ctx::{AbsolutePath, Platform, SchemaVersion};
use nah_proto::observation::{
    ObservationQuery, ObservationRequest, ObservationValue, Observed, PathKind, PathObservation,
    SymlinkTraversal,
};
use std::fs;

#[test]
fn descendants_are_observed_only_when_requested_and_depth_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::create_dir_all(repo.join("src/nested")).unwrap();
    fs::write(repo.join("src/nested/server.key"), "secret").unwrap();

    let ordinary = fulfill(&request(&repo, &[("path", "src")])).unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: ordinary },
    } = value(&ordinary, "path")
    else {
        panic!("path observation");
    };
    assert!(ordinary.descendants().is_none());

    let inspected = fulfill(&descendant_request(&repo, "src", SymlinkTraversal::None)).unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: inspected },
    } = value(&inspected, "path")
    else {
        panic!("path observation");
    };
    let descendants = inspected.descendants().unwrap();
    assert!(descendants.complete());
    assert!(descendants.paths().iter().any(|path| {
        path.as_str()
            == repo
                .join("src/nested/server.key")
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
    }));

    let mut directory = repo.join("deep");
    fs::create_dir(&directory).unwrap();
    for depth in 0..=nah_proto::observation::MAX_DESCENDANT_DEPTH {
        directory.push(format!("d{depth}"));
        fs::create_dir(&directory).unwrap();
    }
    let bounded = fulfill(&descendant_request(&repo, "deep", SymlinkTraversal::None)).unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: bounded },
    } = value(&bounded, "path")
    else {
        panic!("path observation");
    };
    assert!(!bounded.descendants().unwrap().complete());
}

#[cfg(unix)]
#[test]
fn symlink_targets_are_followed_only_when_requested() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let outside = temp.path().join("outside");
    init_repo(&repo);
    fs::create_dir(repo.join("src")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("id_rsa"), "secret").unwrap();
    symlink(&outside, repo.join("src/vendor")).unwrap();

    for (traversal, sees_target) in [
        (SymlinkTraversal::None, false),
        (SymlinkTraversal::Root, false),
        (SymlinkTraversal::All, true),
    ] {
        let observation = fulfill(&descendant_request(&repo, "src", traversal)).unwrap();
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, "path")
        else {
            panic!("path observation");
        };
        assert_eq!(
            path.descendants().unwrap().paths().iter().any(|path| {
                path.as_str()
                    == outside
                        .join("id_rsa")
                        .canonicalize()
                        .unwrap()
                        .to_str()
                        .unwrap()
            }),
            sees_target
        );
    }

    symlink(&outside, repo.join("root-link")).unwrap();
    for traversal in [SymlinkTraversal::Root, SymlinkTraversal::All] {
        let observation = fulfill(&descendant_request(&repo, "root-link", traversal)).unwrap();
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, "path")
        else {
            panic!("path observation");
        };
        assert!(
            path.descendants()
                .unwrap()
                .paths()
                .iter()
                .any(|path| path.as_str().ends_with("/outside/id_rsa"))
        );
    }
}

#[cfg(unix)]
#[test]
fn hardlinks_make_snapshots_incomplete_and_metadata_names_do_not_look_secret() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::create_dir(repo.join("src")).unwrap();
    fs::create_dir(repo.join("src/.env")).unwrap();
    fs::write(repo.join("outside-key"), "secret").unwrap();
    fs::hard_link(repo.join("outside-key"), repo.join("src/blob")).unwrap();
    symlink("ordinary", repo.join("src/id_rsa")).unwrap();

    let observation = fulfill(&descendant_request(&repo, "src", SymlinkTraversal::None)).unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: path },
    } = value(&observation, "path")
    else {
        panic!("path observation");
    };
    let descendants = path.descendants().unwrap();
    assert!(!descendants.complete());
    assert!(
        descendants
            .paths()
            .iter()
            .any(|path| path.as_str().ends_with("/src/blob"))
    );
    assert!(descendants.paths().iter().all(
        |path| !path.as_str().ends_with("/src/id_rsa") && !path.as_str().ends_with("/src/.env")
    ));
}

#[cfg(unix)]
#[test]
fn descendant_budget_charges_roots_and_is_shared_across_walks() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let observed = |path: &std::path::Path| {
        PathObservation::new(
            AbsolutePath::new(Platform::Linux, path.to_str().unwrap()).unwrap(),
            None,
            PathKind::Directory,
        )
    };
    let mut budget = crate::descendants::Budget::limited(1);
    assert!(
        crate::descendants::observe(&observed(&first), SymlinkTraversal::None, &mut budget)
            .complete()
    );
    assert!(
        !crate::descendants::observe(&observed(&second), SymlinkTraversal::None, &mut budget)
            .complete()
    );
}

#[test]
fn descendant_path_bytes_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("directory");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("long-file-name"), "").unwrap();
    let observed = PathObservation::new(
        AbsolutePath::new(Platform::Linux, directory.to_str().unwrap()).unwrap(),
        None,
        PathKind::Directory,
    );
    let mut budget = crate::descendants::Budget::limited_path_bytes(1);
    let descendants = crate::descendants::observe(&observed, SymlinkTraversal::None, &mut budget);
    assert!(!descendants.complete());
    assert!(descendants.paths().is_empty());
}

#[test]
fn duplicate_descendant_queries_reuse_one_scan() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::create_dir(repo.join("many")).unwrap();
    for index in 0..2 {
        fs::write(repo.join("many").join(format!("file-{index}")), "").unwrap();
    }
    let mut queries = request(&repo, &[]).queries().to_vec();
    for key in ["first", "second"] {
        queries.push(ObservationQuery::Path {
            key: key.into(),
            requested: "many".into(),
            cwd_key: "cwd".into(),
            inspect_descendants: true,
            symlink_traversal: SymlinkTraversal::None,
        });
    }
    let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
    let observation =
        crate::fulfill_with_descendant_budget(&request, crate::descendants::Budget::limited(3))
            .unwrap();
    for key in ["first", "second"] {
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, key)
        else {
            panic!("path observation");
        };
        assert!(path.descendants().unwrap().complete());
        assert_eq!(path.descendants().unwrap().paths().len(), 2);
    }
}

#[cfg(unix)]
#[test]
fn followed_file_symlinks_record_visible_and_canonical_names() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let outside = temp.path().join("outside");
    init_repo(&repo);
    fs::create_dir(repo.join("src")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("blob"), "secret").unwrap();
    symlink(outside.join("blob"), repo.join("src/id_rsa")).unwrap();

    let observation = fulfill(&descendant_request(&repo, "src", SymlinkTraversal::All)).unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: path },
    } = value(&observation, "path")
    else {
        panic!("path observation");
    };
    let paths = path.descendants().unwrap().paths();
    assert!(
        paths
            .iter()
            .any(|path| path.as_str().ends_with("/src/id_rsa"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.as_str().ends_with("/outside/blob"))
    );
}

fn descendant_request(
    cwd: &std::path::Path,
    requested: &str,
    symlink_traversal: SymlinkTraversal,
) -> ObservationRequest {
    let base = request(cwd, &[]);
    let mut queries = base.queries().to_vec();
    queries.push(ObservationQuery::Path {
        key: "path".into(),
        requested: requested.into(),
        cwd_key: "cwd".into(),
        inspect_descendants: true,
        symlink_traversal,
    });
    ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap()
}
