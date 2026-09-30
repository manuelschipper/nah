//! The domain universe is defined once (effinterp_proto::DOMAINS) and every widening
//! path consumes it, so an unresolved cross-module call marks opacity for every
//! registered domain — cloud and messaging included, not only the original set.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

#[test]
fn unresolved_cross_module_call_weakens_every_domain() {
    // app.py calls a function from an external package that is not in the repo,
    // so composition cannot see through it and must widen every domain.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "domuniv",
        &[(
            "app.py",
            "#!/usr/bin/env python\nfrom vendor.pkg import frob\nfrob(\"/x\")\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx
        .composition("app.py")
        .expect("app.py composes an unresolved-call boundary");
    let widened: std::collections::BTreeSet<&str> = comp
        .boundaries
        .iter()
        .flat_map(|b| b.domains.iter().map(|s| s.as_str()))
        .collect();
    for domain in effinterp_proto::DOMAINS {
        assert!(
            widened.contains(domain),
            "unresolved call must weaken domain {domain}; widened={widened:?}"
        );
    }
}

#[test]
fn a_known_external_call_weakens_only_the_domains_it_reaches() {
    // `sqlite3` is exactly identified, so the composed boundary names the
    // database it opens and the file backing it — nothing else.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "domuniv-scoped",
        &[(
            "app.py",
            "#!/usr/bin/env python\nimport sqlite3\nsqlite3.connect(\"app.db\")\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx
        .composition("app.py")
        .expect("app.py composes an external boundary");
    let widened: std::collections::BTreeSet<&str> = comp
        .boundaries
        .iter()
        .flat_map(|b| b.domains.iter().map(|s| s.as_str()))
        .collect();
    assert_eq!(
        widened,
        std::collections::BTreeSet::from(["database", "filesystem"])
    );
}

#[test]
fn a_same_named_local_module_does_not_inherit_the_stdlib_classification() {
    // The repo defines its own `sqlite3`, so the import resolves in-repo and
    // the curated stdlib classification never applies.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "domuniv-shadowed",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport socket\nsocket.socket()\n",
            ),
            ("socket.py", "def socket():\n    return object()\n"),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app.py")
        .expect("app.py is analyzed")
        .payload
        .into_effects()
        .unwrap();
    let external: Vec<_> = report
        .boundaries
        .iter()
        .filter(|b| b.reason == "external_unmodeled")
        .collect();
    assert!(
        external.is_empty(),
        "a local module is not an external surface: {external:?}"
    );
    let unresolved = report
        .boundaries
        .iter()
        .find(|b| b.reason == "unresolved_call")
        .expect("the frontend stays loud until composition resolves the local call");
    assert_eq!(
        unresolved
            .domains
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        effinterp_proto::DOMAINS
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
}
