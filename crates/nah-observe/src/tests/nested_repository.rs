use super::support::request;
use crate::descendants::DescendantBudget;
use crate::nested_repository::observe_nested_repository;
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    NestedRepositoryObservation, ObservationFailure, ObservationQuery, ObservationRequest,
    ObservationValue, Observed,
};
use std::fs;
use std::path::Path;

/// What the search below `directory` answers, drawing on `budget`.
fn search(
    directory: &Path,
    budget: &mut DescendantBudget,
) -> Observed<NestedRepositoryObservation> {
    let cwd = super::support::absolute(directory.parent().unwrap());
    observe_nested_repository(
        &crate::observe_path(&cwd, directory.to_str().unwrap()),
        budget,
        None,
    )
}

const FOUND: Observed<NestedRepositoryObservation> = Observed::Ok {
    value: NestedRepositoryObservation::Found,
};
const ABSENT: Observed<NestedRepositoryObservation> = Observed::Ok {
    value: NestedRepositoryObservation::Absent,
};
const UNAVAILABLE: Observed<NestedRepositoryObservation> = Observed::Error {
    error: ObservationFailure::Unavailable,
};

/// A `.git` directory or file at any depth, past the descendant walk's
/// depth limit too, and in any letter case, is found,
/// as Git opens `.GIT` for `.git` on a case-insensitive filesystem; a tree
/// without one is
/// absent only once every entry was listed, and a search its budget cuts
/// short is unavailable, never absent.
#[test]
fn a_nested_marker_is_found_and_absence_needs_the_whole_tree() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let group = root.join("group");
    fs::create_dir_all(group.join("a/b/repo/.git")).unwrap();
    let linked = root.join("linked");
    fs::create_dir_all(linked.join("vendor/lib")).unwrap();
    fs::write(linked.join("vendor/lib/.git"), "gitdir: /elsewhere\n").unwrap();
    let deep = root.join("deep");
    let mut repository = deep.clone();
    for level in 0..=nah_proto::observation::MAX_DESCENDANT_DEPTH {
        repository.push(level.to_string());
    }
    fs::create_dir_all(repository.join(".git")).unwrap();
    let upper = root.join("upper");
    fs::create_dir_all(upper.join("repo/.GIT")).unwrap();
    let plain = root.join("plain");
    fs::create_dir_all(plain.join("notes")).unwrap();
    for index in 0..8 {
        fs::write(plain.join(format!("notes/{index}")), "").unwrap();
    }

    assert_eq!(search(&group, &mut DescendantBudget::default()), FOUND);
    assert_eq!(search(&linked, &mut DescendantBudget::default()), FOUND);
    assert_eq!(search(&upper, &mut DescendantBudget::default()), FOUND);
    assert_eq!(search(&deep, &mut DescendantBudget::default()), FOUND);
    let mut budget = DescendantBudget::default();
    assert_eq!(search(&plain, &mut budget), ABSENT);
    assert_eq!(budget.entries, DescendantBudget::default().entries - 9);
    assert_eq!(
        search(&plain, &mut DescendantBudget::limited(4)),
        UNAVAILABLE
    );
    // A file target holds nothing below it.
    assert_eq!(
        search(&plain.join("notes/0"), &mut DescendantBudget::default()),
        ABSENT
    );

    let mut queries = request(&root, &[]).queries().to_vec();
    queries.push(ObservationQuery::NestedRepository {
        key: "nested".into(),
        requested: "group".into(),
        cwd_key: "cwd".into(),
    });
    let request = ObservationRequest::new(SchemaVersion::V1, "request", queries).unwrap();
    let observation = crate::fulfill_observation_request(&request).unwrap();
    assert!(observation.facts().iter().any(|fact| matches!(
        fact.value(),
        ObservationValue::NestedRepository { observed } if *observed == FOUND
    )));
}

/// A link is not followed: deleting it leaves the repository it leads to.
/// A link given as the target itself is unavailable, since `rm -r link/`
/// empties what it leads to.
#[cfg(unix)]
#[test]
fn links_below_the_target_are_not_followed() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir_all(root.join("repo/.git")).unwrap();
    fs::create_dir(root.join("tree")).unwrap();
    std::os::unix::fs::symlink(root.join("repo"), root.join("tree/repo")).unwrap();
    std::os::unix::fs::symlink(root.join("repo"), root.join("link")).unwrap();

    assert_eq!(
        search(&root.join("tree"), &mut DescendantBudget::default()),
        ABSENT
    );
    assert_eq!(
        search(&root.join("link"), &mut DescendantBudget::default()),
        UNAVAILABLE
    );
}

/// A dataless File Provider folder is neither opened nor counted as holding
/// no repository.
#[cfg(target_os = "macos")]
#[test]
fn a_dataless_folder_leaves_the_search_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    let tree = fs::canonicalize(temp.path()).unwrap().join("tree");
    fs::create_dir_all(tree.join("cloud/repo/.git")).unwrap();
    crate::io_paths::simulated::make_dataless(&tree.join("cloud"));

    assert_eq!(search(&tree, &mut DescendantBudget::default()), UNAVAILABLE);
}
