use super::support::{init_repo, request};
use crate::fulfill;
use nah_proto::observation::ProjectGuardDeclaration;
use std::fs;

#[test]
fn project_guard_declaration_has_distinct_absent_present_malformed_and_read_failure_states() {
    let temp = tempfile::tempdir().expect("tempdir");

    let absent = temp.path().join("absent");
    init_repo(&absent);
    let observed = fulfill(&request(&absent, &[])).expect("absent observation");
    assert_eq!(
        observed.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::Absent
    );

    let present = temp.path().join("present");
    init_repo(&present);
    fs::create_dir(present.join(".nah")).unwrap();
    fs::write(
        present.join(".nah/project.toml"),
        "enable-guards = [\"secrets-env\", \"git-hard-reset\"]\n",
    )
    .unwrap();
    let observed = fulfill(&request(&present, &[])).expect("present observation");
    assert_eq!(
        observed.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::Present {
            names: vec!["git-hard-reset".into(), "secrets-env".into()]
        }
    );

    let malformed = temp.path().join("malformed");
    init_repo(&malformed);
    fs::create_dir(malformed.join(".nah")).unwrap();
    fs::write(
        malformed.join(".nah/project.toml"),
        "guards = [\"secrets-env\"]\n",
    )
    .unwrap();
    let observed = fulfill(&request(&malformed, &[])).expect("malformed observation");
    assert_eq!(
        observed.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::Malformed
    );

    let unreadable = temp.path().join("unreadable");
    init_repo(&unreadable);
    fs::create_dir_all(unreadable.join(".nah/project.toml")).unwrap();
    let observed = fulfill(&request(&unreadable, &[])).expect("read failure observation");
    assert_eq!(
        observed.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::ReadFailure
    );

    let oversized = temp.path().join("oversized");
    init_repo(&oversized);
    fs::create_dir(oversized.join(".nah")).unwrap();
    fs::write(
        oversized.join(".nah/project.toml"),
        vec![b'x'; 16 * 1024 + 1],
    )
    .unwrap();
    let observed = fulfill(&request(&oversized, &[])).expect("oversized observation");
    assert_eq!(
        observed.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::ReadFailure
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked = temp.path().join("linked");
        init_repo(&linked);
        fs::create_dir(linked.join(".nah")).unwrap();
        symlink(
            linked.join("missing-guards"),
            linked.join(".nah/project.toml"),
        )
        .unwrap();
        let observed = fulfill(&request(&linked, &[])).expect("linked observation");
        assert_eq!(
            observed.project_guard_declaration().unwrap(),
            &ProjectGuardDeclaration::ReadFailure
        );
    }
}
