use super::support::{init_repo, request, value};
use crate::fulfill;
#[cfg(unix)]
use nah_proto::observation::PathKind;
use nah_proto::observation::{ObservationFailure, ObservationValue, Observed};
use std::fs;

#[test]
fn multiply_linked_files_fail_observation_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::hard_link(repo.join("tracked"), repo.join("alias")).expect("hardlink");

    #[cfg(unix)]
    std::os::unix::fs::symlink(repo.join("alias"), repo.join("linked-alias"))
        .expect("symlink to hardlink");

    let requested: &[&str] = if cfg!(unix) {
        &["alias", "linked-alias"]
    } else {
        &["alias"]
    };
    for requested in requested {
        let observation = fulfill(&request(&repo, &[("path", requested)])).expect("observation");
        assert!(matches!(
            value(&observation, "path"),
            ObservationValue::Path {
                observed: Observed::Error {
                    error: ObservationFailure::Unavailable
                }
            }
        ));
    }
}

#[cfg(unix)]
#[test]
fn missing_path_realpath_resolves_existing_symlink_parent_and_kind_uses_lstat() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    let outside = temp.path().join("outside");
    init_repo(&repo);
    fs::create_dir(&outside).expect("outside");
    let canonical_repo = repo.canonicalize().expect("canonical repo");
    let canonical_outside = outside.canonicalize().expect("canonical outside");
    symlink(&outside, repo.join("link")).expect("parent symlink");
    symlink(repo.join("tracked"), repo.join("final-link")).expect("final symlink");
    symlink(outside.join("new-target"), repo.join("dangling-link"))
        .expect("dangling final symlink");
    symlink(outside.join("missing-dir"), repo.join("dangling-parent"))
        .expect("dangling absolute parent symlink");
    symlink(
        "../outside/missing-relative",
        repo.join("relative-dangling-parent"),
    )
    .expect("dangling relative parent symlink");

    let observation = fulfill(&request(
        &repo,
        &[
            ("missing", "link/new/file"),
            ("symlink", "final-link"),
            ("dangling", "dangling-link"),
            ("dangling-child", "dangling-parent/file"),
            ("relative-dangling-child", "relative-dangling-parent/file"),
        ],
    ))
    .expect("observation");

    let ObservationValue::Path {
        observed: Observed::Ok { value: missing },
    } = value(&observation, "missing")
    else {
        panic!("expected path");
    };
    assert_eq!(missing.kind(), PathKind::Missing);
    assert_eq!(
        missing.resolved().as_str(),
        canonical_outside.join("new/file").to_str().unwrap()
    );
    assert_eq!(
        missing.realpath().unwrap().as_str(),
        canonical_outside.join("new/file").to_str().unwrap()
    );

    let ObservationValue::Path {
        observed: Observed::Ok { value: link },
    } = value(&observation, "symlink")
    else {
        panic!("expected symlink path");
    };
    assert_eq!(link.kind(), PathKind::Symlink);
    assert_eq!(
        link.realpath().unwrap().as_str(),
        canonical_repo.join("tracked").to_str().unwrap()
    );

    let ObservationValue::Path {
        observed: Observed::Ok { value: dangling },
    } = value(&observation, "dangling")
    else {
        panic!("expected dangling symlink path");
    };
    assert_eq!(dangling.kind(), PathKind::Symlink);
    assert_eq!(
        dangling.realpath().unwrap().as_str(),
        canonical_outside.join("new-target").to_str().unwrap()
    );

    for (key, target) in [
        ("dangling-child", canonical_outside.join("missing-dir/file")),
        (
            "relative-dangling-child",
            canonical_outside.join("missing-relative/file"),
        ),
    ] {
        let ObservationValue::Path {
            observed: Observed::Ok { value: child },
        } = value(&observation, key)
        else {
            panic!("expected dangling parent child path");
        };
        assert_eq!(child.kind(), PathKind::Missing);
        assert_eq!(child.resolved().as_str(), target.to_str().unwrap());
        assert_eq!(child.realpath().unwrap().as_str(), target.to_str().unwrap());
    }
}

#[cfg(unix)]
#[test]
fn symlink_to_fifo_records_the_followed_target_kind() {
    use std::os::unix::fs::{FileTypeExt, symlink};

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    let fifo = repo.join("relay");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    assert!(fs::metadata(&fifo).unwrap().file_type().is_fifo());
    symlink("relay", repo.join("link")).expect("fifo symlink");

    let observation =
        fulfill(&request(&repo, &[("fifo", "relay"), ("link", "link")])).expect("observation");
    let ObservationValue::Path {
        observed: Observed::Ok { value: fifo },
    } = value(&observation, "fifo")
    else {
        panic!("expected fifo path");
    };
    assert_eq!(fifo.kind(), PathKind::Fifo);
    assert_eq!(fifo.target_kind(), None);

    let ObservationValue::Path {
        observed: Observed::Ok { value: link },
    } = value(&observation, "link")
    else {
        panic!("expected symlink path");
    };
    assert_eq!(link.kind(), PathKind::Symlink);
    assert_eq!(link.target_kind(), Some(PathKind::Fifo));
}
