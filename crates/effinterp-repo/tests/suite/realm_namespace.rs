//! Execution origin (realm) is a separate query dimension from resource
//! namespace. A globally-identified resource (a database table) is the same
//! resource wherever execution originates, so an unqualified query spans realms;
//! a realm-relative resource (a filesystem path) defaults to the host realm.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn matches(root: &Path, selector: &str) -> usize {
    let idx = build_index(root, IndexLimits::default());
    reach(&idx, &ResourceSelector::parse(selector).unwrap(), None)
        .payload
        .as_reach()
        .unwrap()
        .matches
        .len()
}

#[test]
fn unqualified_database_query_spans_realms() {
    // The UPDATE executes inside the postgres container (Container realm), but
    // the table identity public.users is global.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "realm-db",
        &[(
            "run.sh",
            "#!/bin/sh\ndocker exec postgres psql -c 'UPDATE public.users SET active=true'\n",
        )],
    );
    assert_eq!(
        matches(&root, "db:public.users"),
        1,
        "unqualified db query finds the container-origin table write"
    );
    assert_eq!(
        matches(&root, "any-realm/db:public.users"),
        1,
        "explicit any-realm also finds it"
    );
    assert_eq!(
        matches(&root, "host/db:public.users"),
        0,
        "explicit host-origin excludes the container-origin write"
    );
}

#[test]
fn unqualified_filesystem_query_defaults_to_host() {
    // A filesystem path is realm-relative: an unqualified fs query is host-only
    // and must not match a write that occurs inside a container.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "realm-fs",
        &[(
            "run.sh",
            "#!/bin/sh\ndocker exec web sh -c 'rm /etc/nginx.conf'\n",
        )],
    );
    assert_eq!(
        matches(&root, "fs:/etc/nginx.conf"),
        0,
        "unqualified fs query is host-only, excludes the container path"
    );
    assert_eq!(
        matches(&root, "container:web/fs:/etc/nginx.conf"),
        1,
        "the container-qualified fs query finds it"
    );
}
