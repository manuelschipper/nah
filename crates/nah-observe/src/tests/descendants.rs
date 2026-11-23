use super::support::{absolute, canonical, init_repo, request, value};
use crate::fulfill_observation_request;
use nah_proto::ctx::AbsolutePath;
#[cfg(unix)]
use nah_proto::ctx::Platform;
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    DescendantObservation, ObservationFailure, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathKind, PathObservation, SymlinkTraversal,
};
use std::fs;
use std::time::{Duration, Instant};

#[test]
fn descendants_are_observed_only_when_requested_and_depth_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::create_dir_all(repo.join("src/nested")).unwrap();
    fs::write(repo.join("src/nested/server.key"), "secret").unwrap();

    let ordinary = fulfill_observation_request(&request(&repo, &[("path", "src")])).unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: ordinary },
    } = value(&ordinary, "path")
    else {
        panic!("path observation");
    };
    assert!(ordinary.descendants().is_none());

    let inspected =
        fulfill_observation_request(&descendant_request(&repo, "src", SymlinkTraversal::None))
            .unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: inspected },
    } = value(&inspected, "path")
    else {
        panic!("path observation");
    };
    let descendants = inspected.descendants().unwrap();
    assert!(descendants.complete());
    assert!(
        descendants
            .paths()
            .iter()
            .any(|path| { path.as_str() == canonical(&repo.join("src/nested/server.key")) })
    );

    let mut directory = repo.join("deep");
    fs::create_dir(&directory).unwrap();
    for depth in 0..=nah_proto::observation::MAX_DESCENDANT_DEPTH {
        directory.push(format!("d{depth}"));
        fs::create_dir(&directory).unwrap();
    }
    let bounded =
        fulfill_observation_request(&descendant_request(&repo, "deep", SymlinkTraversal::None))
            .unwrap();
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

    fs::create_dir(repo.join("tidy")).unwrap();
    fs::create_dir(repo.join("tidy/empty")).unwrap();
    fs::write(repo.join("tidy/file"), "x").unwrap();
    for (traversal, sees_target) in [
        (SymlinkTraversal::None, false),
        (SymlinkTraversal::Root, false),
        (SymlinkTraversal::All, true),
    ] {
        let observation =
            fulfill_observation_request(&descendant_request(&repo, "src", traversal)).unwrap();
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, "path")
        else {
            panic!("path observation");
        };
        // An unfollowed link is an entry the snapshot does not list, and
        // one its links do not name.
        assert_eq!(path.descendants().unwrap().unlisted_entries(), !sees_target);
        assert_eq!(path.descendants().unwrap().names_every_link(), sees_target);
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
        // A followed link is named with the directory it leads to.
        let followed = path
            .descendants()
            .unwrap()
            .links()
            .iter()
            .any(|(visible, target)| {
                visible.as_str().ends_with("/src/vendor")
                    && target.as_str() == outside.canonicalize().unwrap().to_str().unwrap()
            });
        assert_eq!(followed, sees_target);
    }

    // So is an empty directory beneath the root.
    let observation =
        fulfill_observation_request(&descendant_request(&repo, "tidy", SymlinkTraversal::None))
            .unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: path },
    } = value(&observation, "path")
    else {
        panic!("path observation");
    };
    assert!(path.descendants().unwrap().complete());
    assert!(path.descendants().unwrap().unlisted_entries());
    // It leads nowhere, so the snapshot still names every link.
    assert!(path.descendants().unwrap().names_every_link());

    // So are a special file and the entries of an unreadable directory.
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(repo.join("special")).unwrap();
    fs::write(repo.join("special/file"), "x").unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(repo.join("special/pipe"))
        .status()
        .expect("mkfifo");
    assert!(status.success());
    fs::create_dir_all(repo.join("sealed/locked")).unwrap();
    fs::write(repo.join("sealed/locked/file"), "x").unwrap();
    fs::set_permissions(
        repo.join("sealed/locked"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    // Root reads the directory regardless of its mode.
    let sealed = unsafe { libc::geteuid() } != 0;
    for (root, omits) in [("special", true), ("sealed", sealed)] {
        let observation =
            fulfill_observation_request(&descendant_request(&repo, root, SymlinkTraversal::None))
                .unwrap();
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, "path")
        else {
            panic!("path observation");
        };
        assert_eq!(path.descendants().unwrap().unlisted_entries(), omits);
    }
    fs::set_permissions(
        repo.join("sealed/locked"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // A second link to the same directory lists its entries under its own
    // spelling too.
    symlink(&outside, repo.join("src/second")).unwrap();
    let observation =
        fulfill_observation_request(&descendant_request(&repo, "src", SymlinkTraversal::All))
            .unwrap();
    let ObservationValue::Path {
        observed: Observed::Ok { value: path },
    } = value(&observation, "path")
    else {
        panic!("path observation");
    };
    let descendants = path.descendants().unwrap();
    assert!(descendants.complete());
    for alias in ["/src/vendor/id_rsa", "/src/second/id_rsa"] {
        assert!(
            descendants
                .paths()
                .iter()
                .any(|path| path.as_str().ends_with(alias))
        );
    }
    fs::remove_file(repo.join("src/second")).unwrap();

    symlink(&outside, repo.join("root-link")).unwrap();
    for traversal in [SymlinkTraversal::Root, SymlinkTraversal::All] {
        let observation =
            fulfill_observation_request(&descendant_request(&repo, "root-link", traversal))
                .unwrap();
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

    let observation =
        fulfill_observation_request(&descendant_request(&repo, "src", SymlinkTraversal::None))
            .unwrap();
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
    let mut budget = crate::descendants::DescendantBudget::limited(1);
    assert!(
        crate::descendants::observe_descendants(
            &observed(&first),
            SymlinkTraversal::None,
            None,
            &crate::ignored_entries::Listings::new(),
            &mut budget,
            &crate::descendants::Cutoff::new(None, Duration::ZERO, Duration::ZERO),
        )
        .complete()
    );
    assert!(
        !crate::descendants::observe_descendants(
            &observed(&second),
            SymlinkTraversal::None,
            None,
            &crate::ignored_entries::Listings::new(),
            &mut budget,
            &crate::descendants::Cutoff::new(None, Duration::ZERO, Duration::ZERO),
        )
        .complete()
    );
}

#[test]
fn descendant_path_bytes_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("directory");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("long-file-name"), "").unwrap();
    let observed = PathObservation::new(absolute(&directory), None, PathKind::Directory);
    let mut budget = crate::descendants::DescendantBudget::limited_path_bytes(1);
    let descendants = crate::descendants::observe_descendants(
        &observed,
        SymlinkTraversal::None,
        None,
        &crate::ignored_entries::Listings::new(),
        &mut budget,
        &crate::descendants::Cutoff::new(None, Duration::ZERO, Duration::ZERO),
    );
    assert!(!descendants.complete());
    assert!(descendants.paths().is_empty());
    assert!(descendants.unlisted_entries());
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
            skip_ignored: false,
        });
    }
    let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
    let observation = crate::fulfill_with_descendant_budget(
        &request,
        crate::descendants::DescendantBudget::limited(3),
    )
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

/// A search that leaves out ignored directories spends no budget inside
/// them, and names each one it skipped so the reader can confirm the search
/// leaves it out. A delete of the same directory asked beside it walks
/// everything, the secret in the ignored directory included.
#[test]
fn only_a_walk_for_an_ignoring_search_skips_ignored_directories() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::write(repo.join(".gitignore"), "target/\n").unwrap();
    fs::create_dir_all(repo.join("target/debug")).unwrap();
    fs::write(repo.join("target/debug/.env"), "TOKEN=1").unwrap();
    // Both walks reuse the listings the ignored-entries walk read below the
    // root, and must still reach what lies in them.
    fs::create_dir_all(repo.join("src/config")).unwrap();
    fs::write(repo.join("src/config/.env"), "TOKEN=1").unwrap();
    let requested = repo.to_str().unwrap();
    let mut queries = request(&repo, &[]).queries().to_vec();
    for (key, skip_ignored) in [("search", true), ("delete", false)] {
        queries.push(ObservationQuery::Path {
            key: key.into(),
            requested: requested.into(),
            cwd_key: "cwd".into(),
            inspect_descendants: true,
            symlink_traversal: SymlinkTraversal::None,
            skip_ignored,
        });
    }
    let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
    let observation = fulfill_observation_request(&request).unwrap();
    let descendants = |key| {
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, key)
        else {
            panic!("path observation");
        };
        path.descendants().unwrap().clone()
    };
    // Observed Windows paths use backslashes.
    let secret = |paths: &[AbsolutePath], name: &str| {
        paths
            .iter()
            .any(|path| path.as_str().replace('\\', "/").ends_with(name))
    };

    let search = descendants("search");
    assert!(!secret(search.paths(), "/target/debug/.env"));
    assert!(secret(search.paths(), "/src/config/.env"));
    assert_eq!(
        search
            .ignored_directories()
            .iter()
            .map(|directory| directory.as_str())
            .collect::<Vec<_>>(),
        [canonical(&repo.join("target"))]
    );
    assert!(search.complete_beside_ignored() && !search.complete());
    let delete = descendants("delete");
    assert!(secret(delete.paths(), "/target/debug/.env"));
    assert!(secret(delete.paths(), "/src/config/.env"));
    assert!(delete.ignored_directories().is_empty());
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

    let observation =
        fulfill_observation_request(&descendant_request(&repo, "src", SymlinkTraversal::All))
            .unwrap();
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

/// An expired decision still observes the path, skips its walk, and gives
/// no ignored entries. Both walks can finish with time left.
#[test]
fn a_walk_stops_at_the_decision_deadline() {
    let temp = tempfile::tempdir().unwrap();
    for directory in 0..4 {
        let directory = temp.path().join("tree").join(format!("d{directory}"));
        fs::create_dir_all(&directory).unwrap();
        for file in 0..100 {
            fs::write(directory.join(format!("f{file}")), "").unwrap();
        }
    }
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::write(repo.join(".gitignore"), ".env\n").unwrap();
    fs::write(repo.join(".env"), "TOKEN=1").unwrap();
    let mut queries = descendant_request(temp.path(), "tree", SymlinkTraversal::None)
        .queries()
        .to_vec();
    queries.push(ObservationQuery::IgnoredEntries {
        key: "ignored".into(),
        requested: repo.to_str().unwrap().into(),
        cwd_key: "cwd".into(),
    });
    let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
    // Exercise the walk's cutoff without racing the outer worker timeout.
    let observe = |deadline| {
        let observation = crate::fulfill_at_cost(&request, deadline, crate::ASSEMBLY_COST).unwrap();
        let ObservationValue::Path {
            observed: Observed::Ok { value: path },
        } = value(&observation, "path")
        else {
            panic!("path observation");
        };
        let ObservationValue::IgnoredEntries { observed: ignored } = value(&observation, "ignored")
        else {
            panic!("ignored entries observation");
        };
        (path.descendants().unwrap().clone(), ignored.clone())
    };

    let (expired, ignored) = observe(Instant::now());
    assert!(!expired.complete());
    assert!(expired.paths().is_empty());
    assert!(expired.unlisted_entries());
    assert!(matches!(
        ignored,
        Observed::Error {
            error: ObservationFailure::Unavailable
        }
    ));
    let (unhurried, ignored) = observe(Instant::now() + Duration::from_secs(60));
    assert!(unhurried.complete());
    assert_eq!(unhurried.paths().len(), 400);
    assert!(matches!(
        ignored,
        Observed::Ok { value } if value.entries().iter().any(|entry| entry.path() == ".env")
    ));
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
        skip_ignored: false,
    });
    ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap()
}

/// A directory whose read fails partway through, after the walk took some
/// of its entries, is listed incomplete rather than as all it holds.
#[cfg(target_os = "macos")]
#[test]
fn a_directory_read_that_fails_partway_is_listed_incomplete() {
    let temp = tempfile::tempdir().unwrap();
    let directory = fs::canonicalize(temp.path()).unwrap().join("directory");
    fs::create_dir(&directory).unwrap();
    // More entries than one bulk call returns, and than the walk's budget.
    for index in 0..600 {
        fs::write(directory.join(format!("{index:0>200}")), "").unwrap();
    }
    crate::directory_entries::bulk::failing::fail_every_second_call(&directory);
    let observed = PathObservation::new(absolute(&directory), None, PathKind::Directory);
    let descendants = crate::descendants::observe_descendants(
        &observed,
        SymlinkTraversal::None,
        None,
        &crate::ignored_entries::Listings::new(),
        &mut crate::descendants::DescendantBudget::limited(500),
        &crate::descendants::Cutoff::new(None, Duration::ZERO, Duration::ZERO),
    );
    assert!(!descendants.complete());
    assert!(descendants.unlisted_entries());
}

/// A dataless File Provider folder, whose open would ask its provider to
/// fetch it, is neither opened nor entered: the walk lists what lies beside
/// it and leaves the snapshot incomplete.
#[cfg(target_os = "macos")]
#[test]
fn a_walk_neither_opens_nor_enters_a_dataless_folder() {
    let temp = tempfile::tempdir().unwrap();
    let tree = fs::canonicalize(temp.path()).unwrap().join("tree");
    fs::create_dir_all(tree.join("cloud")).unwrap();
    fs::write(tree.join("cloud/report"), "").unwrap();
    fs::write(tree.join("local"), "").unwrap();
    crate::io_paths::simulated::make_dataless(&tree.join("cloud"));
    let walk = |root: &std::path::Path| {
        crate::descendants::observe_descendants(
            &PathObservation::new(absolute(root), None, PathKind::Directory),
            SymlinkTraversal::None,
            None,
            &crate::ignored_entries::Listings::new(),
            &mut crate::descendants::DescendantBudget::default(),
            &crate::descendants::Cutoff::new(None, Duration::ZERO, Duration::ZERO),
        )
    };

    let descendants = walk(&tree);
    assert_eq!(
        descendants.paths(),
        [absolute(&tree.join("local"))].as_slice()
    );
    assert!(!descendants.complete());
    assert!(descendants.unlisted_entries());
    // Walked from the folder itself, the walk does not open it either.
    let descendants = walk(&tree.join("cloud"));
    assert!(descendants.paths().is_empty());
    assert!(!descendants.complete());
}

/// A directory whose open the kernel holds, as it holds one of a File
/// Provider folder whose provider does not answer, costs a read no more
/// than it can wait, and a walk without a deadline no more than the
/// longest wait for an open; while the open is still held, the directory
/// is refused at once, and once it returns it is read again.
#[cfg(target_os = "macos")]
#[test]
fn a_held_directory_open_is_waited_for_no_longer_than_a_read_can_wait() {
    use crate::directory_entries::bulk::{OPEN_WAIT, simulated};
    use crate::directory_entries::read_directory;
    use std::io::ErrorKind;
    use std::sync::atomic::AtomicUsize;

    let temp = tempfile::tempdir().unwrap();
    let tree = fs::canonicalize(temp.path()).unwrap().join("tree");
    fs::create_dir_all(tree.join("held")).unwrap();
    fs::write(tree.join("held/report"), "").unwrap();
    fs::write(tree.join("local"), "").unwrap();
    let held = tree.join("held");
    let read = |until: Instant| {
        read_directory(&held, &AtomicUsize::new(usize::MAX), &|| false, Some(until))
    };

    let open = simulated::hold_next_open(&held);
    let started = Instant::now();
    let deadline = started + OPEN_WAIT / 2;
    assert_eq!(read(deadline).err().unwrap().kind(), ErrorKind::TimedOut);
    assert!(open.entered.try_recv().expect("open entered") < deadline);
    assert!(started.elapsed() < OPEN_WAIT);
    // Another open would succeed now: the stall is only for the first call.
    let refused = Instant::now();
    let retry = read(refused + Duration::from_secs(60));
    assert!(refused.elapsed() < OPEN_WAIT);
    assert_eq!(retry.err().unwrap().kind(), ErrorKind::TimedOut);
    drop(open);

    let recovery = Instant::now() + Duration::from_secs(10);
    let answered = loop {
        match read(recovery) {
            Ok(listed) => break listed,
            Err(error) => assert_eq!(error.kind(), ErrorKind::TimedOut),
        }
        assert!(Instant::now() < recovery, "directory did not reopen");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(answered.whole);
    assert_eq!(answered.entries.len(), 1);
    assert_eq!(answered.entries[0].as_ref().unwrap().name, "report");

    let open = simulated::hold_next_open(&held);
    let walked = Instant::now();
    let descendants = crate::descendants::observe_descendants(
        &PathObservation::new(absolute(&tree), None, PathKind::Directory),
        SymlinkTraversal::None,
        None,
        &crate::ignored_entries::Listings::new(),
        &mut crate::descendants::DescendantBudget::default(),
        &crate::descendants::Cutoff::new(None, Duration::ZERO, Duration::ZERO),
    );
    open.entered.try_recv().expect("walk entered the open");
    assert!(walked.elapsed() < 3 * OPEN_WAIT);
    assert_eq!(
        descendants.paths(),
        [absolute(&tree.join("local"))].as_slice()
    );
    assert!(!descendants.complete());
}

/// A decision's observation held past its deadline by a filesystem call that
/// does not return, here the listing of a directory once open, answers just
/// past the deadline as if nothing could be observed, and the call is
/// abandoned to the thread making it.
#[cfg(target_os = "macos")]
#[test]
fn an_observation_held_past_its_deadline_answers_as_unobserved() {
    let temp = tempfile::tempdir().unwrap();
    let tree = fs::canonicalize(temp.path()).unwrap().join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("report"), "").unwrap();
    let listing = crate::directory_entries::bulk::simulated::hold_next_listing(&tree);
    let request = descendant_request(temp.path(), "tree", SymlinkTraversal::None);

    let deadline = Instant::now() + Duration::from_secs(120);
    let observation =
        crate::bounded::simulated::expire_after_entry(deadline, listing.entered, || {
            crate::DecisionObservation::until(deadline)
                .fulfill(&request)
                .unwrap()
        });
    assert!(matches!(
        value(&observation, "path"),
        ObservationValue::Path {
            observed: Observed::Error {
                error: ObservationFailure::Unavailable
            }
        }
    ));
    drop(listing.release);
}

/// An observation holds no more than the time left before its deadline can
/// assemble: each walk stops once the paths it lists would not fit, a copy
/// of a snapshot that would not fit is left unlisted, and a tree is
/// answered without a walk while the facts, or the trees still owed an
/// answer, or releasing the listings its walks keep, would not fit. Every
/// path is observed before anything is cut
/// short, so neither a path queried without a walk nor one that cannot be
/// walked holds back a walk, or the discovery of the request's roots, that
/// the time left covers; and queries of one tree share its answer. What
/// fits is observed whole. Assembly here costs whole seconds, so the bound
/// holds whatever the host's speed.
#[test]
fn an_observation_holds_what_it_can_assemble_by_its_deadline() {
    let temp = tempfile::tempdir().unwrap();
    init_repo(temp.path());
    for (directory, files) in [("small", 20), ("flat", 400)] {
        let directory = temp.path().join(directory);
        fs::create_dir(&directory).unwrap();
        for file in 0..files {
            fs::write(directory.join(format!("f{file}")), "").unwrap();
        }
    }
    for directory in 0..70 {
        fs::create_dir(temp.path().join(format!("empty{directory:02}"))).unwrap();
    }
    for (directory, subdirectories) in [("ignoring25", 25), ("ignoring40", 40)] {
        for subdirectory in 0..subdirectories {
            fs::create_dir_all(
                temp.path()
                    .join(directory)
                    .join(format!("d{subdirectory:02}")),
            )
            .unwrap();
        }
    }
    // Ten minutes left, and a fact, a path, a tree or a walk costs ten
    // seconds.
    let unit = Duration::from_secs(10);
    let left = Duration::from_secs(600);
    let free = crate::AssemblyCost {
        per_fact: Duration::ZERO,
        per_path: Duration::ZERO,
        per_kept: Duration::ZERO,
        per_tree: Duration::ZERO,
        per_walk: Duration::ZERO,
    };
    let per_path = crate::AssemblyCost {
        per_path: unit,
        ..free
    };
    let per_tree = crate::AssemblyCost {
        per_tree: unit,
        ..free
    };
    let named = |prefix: &str, count: usize, requested: &dyn Fn(usize) -> String| {
        (0..count)
            .map(|index| (format!("{prefix}{index:02}"), requested(index)))
            .collect::<Vec<_>>()
    };
    // The observation of `walked` paths, queried for their descendants,
    // beside `plain` ones, queried without.
    let observe = |walked: &[(String, String)], plain: &[(String, String)], cost| {
        let base = request(temp.path(), &[]);
        let mut queries = base.queries().to_vec();
        for (paths, inspect_descendants) in [(walked, true), (plain, false)] {
            queries.extend(paths.iter().map(|(key, requested)| ObservationQuery::Path {
                key: key.clone(),
                requested: requested.clone(),
                cwd_key: "cwd".into(),
                inspect_descendants,
                symlink_traversal: SymlinkTraversal::None,
                skip_ignored: false,
            }));
        }
        let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
        crate::fulfill_at_cost(&request, std::time::Instant::now() + left, cost).unwrap()
    };
    let snapshot = |observation: &nah_proto::observation::Observation, key: &str| {
        let ObservationValue::Path {
            observed: Observed::Ok { value },
        } = value(observation, key)
        else {
            panic!("path observation");
        };
        value.descendants().unwrap().clone()
    };
    let snapshots = |walked: &[(String, String)], cost| {
        let observation = observe(walked, &[], cost);
        walked
            .iter()
            .map(|(key, _)| snapshot(&observation, key))
            .collect::<Vec<_>>()
    };
    let complete = |snapshots: Vec<DescendantObservation>| {
        snapshots
            .iter()
            .map(DescendantObservation::complete)
            .collect::<Vec<_>>()
    };

    let [fits] = &snapshots(&named("q", 1, &|_| "small".into()), per_path)[..] else {
        unreachable!()
    };
    assert!(fits.complete());
    assert_eq!(fits.paths().len(), 20);

    let [cut] = &snapshots(&named("q", 1, &|_| "flat".into()), per_path)[..] else {
        unreachable!()
    };
    assert!(!cut.complete());
    assert!(cut.unlisted_entries());
    assert!(cut.paths().len() <= 60);

    // A second copy of the small snapshot fits; a third would not.
    let copies = snapshots(&named("q", 3, &|_| "small".into()), per_path);
    assert!(copies[..2].iter().all(DescendantObservation::complete));
    assert!(!copies[2].complete() && copies[2].paths().is_empty());

    // While more than sixty other trees are owed an answer, each is answered
    // without a walk; the rest are walked.
    let answered = snapshots(
        &named("q", 70, &|index| format!("empty{index:02}")),
        per_tree,
    );
    assert_eq!(
        complete(answered),
        [vec![false; 10], vec![true; 60]].concat()
    );
    // Queries of one tree owe its answer once.
    let shared = snapshots(&named("q", 70, &|_| "small".into()), per_tree);
    assert_eq!(complete(shared), vec![true; 70]);
    // Neither paths queried without a walk nor descendant queries of a
    // path that cannot be walked owe a tree's answer.
    let beside = |plain| {
        let mut walked = named("q", 1, &|_| "small".into());
        // A name with a control character is refused before any filesystem
        // call on every host. A path below a regular file would not do:
        // Unix refuses it as not a directory, but Windows reports it missing.
        walked.extend(named("r", 69, &|index| format!("unwalkable\u{7}{index:02}")));
        observe(&walked, plain, per_tree)
    };
    assert!(snapshot(&beside(&[]), "q00").complete());
    let observation = beside(&named("s", 69, &|index| format!("empty{index:02}")));
    assert!(snapshot(&observation, "q00").complete());
    // Nor do they hold back the discovery of the request's roots.
    let ObservationValue::Roots {
        observed: Observed::Ok { value: roots },
    } = value(&observation, "roots")
    else {
        panic!("discovered roots");
    };
    assert!(!roots.is_empty());

    // A walk that skips ignored entries reads its tree once to find them
    // and keeps what it read for the walk that lists the tree. The listings
    // it keeps are owed: twenty-six directories and twenty-five entries
    // leave ninety seconds, too few to start a walk that costs a hundred.
    // A tree of forty entries is more than the first walk can keep.
    let ignoring = |directory: &str, cost| {
        let requested = canonical(&temp.path().join(directory));
        let base = request(temp.path(), &[]);
        let mut queries = base.queries().to_vec();
        queries.push(ObservationQuery::Path {
            key: "q00".into(),
            requested: requested.clone(),
            cwd_key: "cwd".into(),
            inspect_descendants: true,
            symlink_traversal: SymlinkTraversal::None,
            skip_ignored: true,
        });
        queries.push(ObservationQuery::IgnoredEntries {
            key: "ignored".into(),
            requested,
            cwd_key: "cwd".into(),
        });
        let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
        let observation =
            crate::fulfill_at_cost(&request, std::time::Instant::now() + left, cost).unwrap();
        let ObservationValue::IgnoredEntries { observed } = value(&observation, "ignored") else {
            panic!("ignored entries observation");
        };
        (
            snapshot(&observation, "q00").complete(),
            matches!(observed, Observed::Ok { .. }),
        )
    };
    let per_kept = crate::AssemblyCost {
        per_kept: unit,
        ..free
    };
    assert_eq!(ignoring("ignoring25", per_kept), (true, true));
    assert_eq!(
        ignoring(
            "ignoring25",
            crate::AssemblyCost {
                per_walk: Duration::from_secs(100),
                ..per_kept
            }
        ),
        (false, true)
    );
    assert_eq!(ignoring("ignoring40", per_kept), (true, false));
    // A directory two spellings reach is kept once: after the second
    // walk the twenty-six directories and twenty-five entries owe half the
    // time left, so a walk costing a hundred seconds still starts.
    let twice = {
        let spelled = canonical(&temp.path().join("ignoring25"));
        let base = request(temp.path(), &[]);
        let mut queries = base.queries().to_vec();
        for (key, requested) in [("a", spelled.clone()), ("b", format!("{spelled}/."))] {
            queries.push(ObservationQuery::IgnoredEntries {
                key: key.into(),
                requested,
                cwd_key: "cwd".into(),
            });
        }
        queries.push(ObservationQuery::Path {
            key: "q00".into(),
            requested: spelled,
            cwd_key: "cwd".into(),
            inspect_descendants: true,
            symlink_traversal: SymlinkTraversal::None,
            skip_ignored: true,
        });
        let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
        crate::fulfill_at_cost(
            &request,
            std::time::Instant::now() + left,
            crate::AssemblyCost {
                per_kept: Duration::from_secs(5),
                per_walk: Duration::from_secs(100),
                ..free
            },
        )
        .unwrap()
    };
    for key in ["a", "b"] {
        assert!(matches!(
            value(&twice, key),
            ObservationValue::IgnoredEntries {
                observed: Observed::Ok { .. }
            }
        ));
    }
    assert!(snapshot(&twice, "q00").complete());

    // Seventy-three facts, answered or not, are more than the time left can
    // assemble, so no walk starts.
    let assembled = snapshots(
        &named("q", 70, &|index| format!("empty{index:02}")),
        crate::AssemblyCost {
            per_fact: unit,
            ..free
        },
    );
    assert_eq!(complete(assembled), vec![false; 70]);

    // Nor does a walk start that the time left cannot start and stop.
    let [unstarted] = &snapshots(
        &named("q", 1, &|_| "small".into()),
        crate::AssemblyCost {
            per_walk: left,
            ..free
        },
    )[..] else {
        unreachable!()
    };
    assert!(!unstarted.complete() && unstarted.paths().is_empty());
}
