//! Cross-file composition and the incremental index, exercised end to end
//! through `build_index` and `apply_changes`. The incremental tests assert the
//! correctness oracle: after any change event, the index is byte-equivalent to
//! a clean rebuild of the final on-disk state.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{
    IndexLimits, RepoChange, Selector, apply_changes, build_index, effective_surface, effects_of,
    reach,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

const APP_PY: &str = "#!/usr/bin/env python\nfrom util import wipe\ndef run():\n    wipe(\"/var/cache/app\", name)\nrun()\n";
const UTIL_PY: &str =
    "import os, shutil\ndef wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))\n";

#[test]
fn cross_file_repo_builds_and_registers_sources() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-build",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let idx = build_index(&root, IndexLimits::default());

    // Both source files are analyzed inputs (bound into the fingerprint).
    let paths: Vec<&str> = idx.dependency_manifest.source_paths().collect();
    assert!(paths.contains(&"app.py"), "app.py in manifest");
    assert!(paths.contains(&"util.py"), "util.py in manifest");
    // Both are in the source registry.
    assert!(idx.registry.files.contains_key("util.py"));
    assert!(idx.registry.files.contains_key("app.py"));
}

#[test]
fn headline_reverse_query_traces_across_files() {
    // app.py's run() calls util.wipe("/var/cache/app", name); the reverse query
    // for that path must find app.py THROUGH the cross-file call.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-headline",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);

    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .indeterminate
        .iter()
        .filter_map(|row| match row {
            effinterp_proto::Indeterminate::Effect {
                fact,
                matched:
                    effinterp_proto::Match::Indeterminate {
                        reason: effinterp_proto::MatchReason::Unbound { .. },
                    },
                ..
            } => Some(fact),
            _ => None,
        })
        .find(|fact| fact.entrypoint == "app.py" && fact.operation.0 == "filesystem.delete")
        .expect("cross-file delete retains unresolved name");
    assert!(
        hit.provenance_roots.iter().any(|root| {
            report
                .provenance
                .nodes
                .iter()
                .any(|node| &node.id == root && node.occurrence.origin == "util.py")
        }),
        "fact provenance crosses into util.py"
    );
}

/// The common entrypoint shape: an imported function called at MODULE TOP
/// LEVEL (not inside a def). Composition must root on the module's own
/// top-level calls, not only defined functions.
const UNCALLED_APP_PY: &str = "from util import wipe\n\ndef never_called():\n    wipe(\"/important\")\n\nif __name__ == \"__main__\":\n    print(\"safe\")\n";
const UNCALLED_UTIL_PY: &str = "import os\n\ndef wipe(p):\n    os.remove(p)\n";

/// An uncalled function's cross-file effect stays off the entrypoint's
/// execution surface.
#[test]
fn execution_surface_excludes_uncalled_cross_file_delete() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "uncalled-exec",
        &[("app.py", UNCALLED_APP_PY), ("util.py", UNCALLED_UTIL_PY)],
    );
    let idx = build_index(&root, IndexLimits::default());

    // The execution surface of app.py must not carry never_called's delete.
    let surface = effective_surface(&idx, "app.py").expect("app.py has an execution surface");
    assert!(
        !surface
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"),
        "execution surface must exclude an uncalled function's delete: {:?}",
        surface.effects
    );

    // And the reverse query over /important finds no delete either.
    let report = reach(&idx, &Selector::parse("fs:/important").unwrap(), None);
    assert!(
        !report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.operation.as_str() == "filesystem.delete"),
        "reach must not attribute the uncalled delete to any entrypoint"
    );
}

#[test]
fn top_level_call_traces_across_files() {
    const APP_TOP: &str =
        "#!/usr/bin/env python\nfrom util import wipe\nwipe(\"/var/cache/app\", name)\n";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-toplevel",
        &[("app.py", APP_TOP), ("util.py", UTIL_PY)],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .indeterminate
        .iter()
        .filter_map(|row| match row {
            effinterp_proto::Indeterminate::Effect {
                fact,
                matched:
                    effinterp_proto::Match::Indeterminate {
                        reason: effinterp_proto::MatchReason::Unbound { .. },
                    },
                ..
            } => Some(fact),
            _ => None,
        })
        .find(|fact| fact.entrypoint == "app.py" && fact.operation.0 == "filesystem.delete")
        .expect("top-level call composes cross-file");
    assert!(hit.provenance_roots.iter().any(|root| {
        report
            .provenance
            .nodes
            .iter()
            .any(|node| &node.id == root && node.occurrence.origin == "util.py")
    }));
}

#[test]
fn function_memo_replay_does_not_repeat_module_execution() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-memo-module-execution",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport driver\ndriver.go()\n",
            ),
            (
                "driver.py",
                "def go():\n    from helper import work\n    work()\n    work()\n",
            ),
            (
                "helper.py",
                "import os, shutil\nos.remove('/toplevel')\ndef work():\n    os.remove('/work')\n    shutil.copy('/source', '/destination')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("app.py").unwrap();
    for (resource, expected) in [("/toplevel", 1), ("/work", 2)] {
        let occurrences = composition
            .occurrence_effects
            .iter()
            .filter(|occurrence| {
                let effect = &composition.effects[occurrence.effect].effect;
                effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::canonical_json(&effect.resource).contains(resource)
            })
            .count();
        assert_eq!(occurrences, expected, "{resource}");
    }
    assert_eq!(composition.transfers.len(), 2);
    let mut endpoints = std::collections::BTreeSet::new();
    for binding in &composition.transfers {
        for (slot, operation) in [
            (binding.source, "filesystem.read"),
            (binding.destination, "filesystem.write"),
        ] {
            assert!(endpoints.insert(slot));
            let occurrence = &composition.occurrence_effects[slot as usize];
            assert_eq!(
                composition.effects[occurrence.effect].effect.operation.0,
                operation
            );
        }
    }
}

#[test]
fn resolved_repository_calls_clear_only_matching_frontend_boundaries() {
    for (tag, entrypoint, files, module) in [
        (
            "xmod-clears-python-boundary",
            "app.py",
            vec![
                (
                    "app.py",
                    "#!/usr/bin/env python\nfrom util import wipe\nwipe('/resolved-python')\n",
                ),
                (
                    "util.py",
                    "import os\ndef wipe(path):\n    os.remove(path)\n",
                ),
            ],
            "util",
        ),
        (
            "xmod-clears-js-boundary",
            "app.js",
            vec![
                (
                    "app.js",
                    "#!/usr/bin/env node\nconst { wipe } = require('./util');\nwipe('/resolved-js');\n",
                ),
                (
                    "util.js",
                    "const fs = require('fs');\nfunction wipe(path) { fs.rmSync(path); }\nmodule.exports = { wipe };\n",
                ),
            ],
            "./util",
        ),
    ] {
        let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, &files);
        let index = build_index(&root, IndexLimits::default());
        let callee = index
            .find(entrypoint)
            .and_then(|entrypoint| entrypoint.plan())
            .and_then(|plan| {
                plan.boundaries
                    .iter()
                    .find(|boundary| boundary.reason == "unresolved_call")
                    .and_then(|boundary| boundary.callee.as_ref())
            })
            .expect("frontend boundary carries callee identity");
        assert_eq!(callee.module, module);
        assert_eq!(callee.symbol, "wipe");
        let report = effects_of(&index, entrypoint)
            .expect("entrypoint analyzed")
            .payload
            .into_effects()
            .unwrap();

        assert!(
            report
                .boundaries
                .iter()
                .all(|boundary| boundary.reason != "unresolved_call"),
            "resolved boundaries for {entrypoint}: {:?}",
            report.boundaries
        );
        assert_eq!(
            report.coverage.get("filesystem").map(|claim| claim.level),
            Some(if entrypoint.ends_with(".py") {
                effinterp_proto::CoverageLevel::Partial
            } else {
                effinterp_proto::CoverageLevel::Full
            }),
            "coverage and boundaries for {entrypoint}: {:?}",
            report.boundaries
        );
        if entrypoint.ends_with(".py") {
            assert!(
                report
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason == "frontend_partial"
                        && boundary.domains.contains(&"filesystem".to_string()))
            );
        }
    }
}

#[test]
fn unresolved_repository_calls_keep_frontend_boundaries() {
    for (tag, entrypoint, files, module) in [
        (
            "xmod-keeps-python-boundary",
            "app.py",
            vec![(
                "app.py",
                "#!/usr/bin/env python\nfrom missing import wipe\nwipe('/unresolved-python')\n",
            )],
            "missing",
        ),
        (
            "xmod-keeps-js-boundary",
            "app.js",
            vec![(
                "app.js",
                "#!/usr/bin/env node\nconst { wipe } = require('./missing');\nwipe('/unresolved-js');\n",
            )],
            "./missing",
        ),
    ] {
        let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, &files);
        let index = build_index(&root, IndexLimits::default());
        let callee = index
            .find(entrypoint)
            .and_then(|entrypoint| entrypoint.plan())
            .and_then(|plan| {
                plan.boundaries
                    .iter()
                    .find(|boundary| boundary.reason == "unresolved_call")
                    .and_then(|boundary| boundary.callee.as_ref())
            })
            .expect("frontend boundary carries callee identity");
        assert_eq!(callee.module, module);
        assert_eq!(callee.symbol, "wipe");
        let report = effects_of(&index, entrypoint)
            .expect("entrypoint analyzed")
            .payload
            .into_effects()
            .unwrap();

        assert!(
            report
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_call"),
            "unresolved boundaries for {entrypoint}: {:?}",
            report.boundaries
        );
        assert_eq!(
            report.coverage.get("filesystem").map(|claim| claim.level),
            Some(effinterp_proto::CoverageLevel::Partial)
        );
    }
}

#[test]
fn ambiguous_repository_call_keeps_frontend_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-keeps-ambiguous-boundary",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe('/ambiguous')\n",
            ),
            (
                "api.py",
                "if FLAG:\n    from left import wipe\nelse:\n    from right import wipe\n",
            ),
            ("left.py", "def wipe(path): pass\n"),
            ("right.py", "def wipe(path): pass\n"),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "app.py")
        .expect("entrypoint analyzed")
        .payload
        .into_effects()
        .unwrap();

    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "reexport_ambiguous")
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_call")
    );
    assert_eq!(
        report.coverage.get("filesystem").map(|claim| claim.level),
        Some(effinterp_proto::CoverageLevel::Partial)
    );
}

#[test]
fn rust_std_receiver_methods_keep_outer_and_element_dispatch_evidence() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-rust-inert-methods",
        &[
            ("main.rs", "mod worker;\nfn main() { worker::run(); }\n"),
            (
                "worker.rs",
                "pub struct Input;\nimpl Input { fn len(&self) { std::fs::remove_file(\"/wrong-element-len\"); } fn wipe(&self, path: &str) { std::fs::remove_file(path); } }\nfn inspect_vec(values: Vec<Input>) { values.len(); for value in values { value.wipe(\"/xmod-rust-vec\"); } }\nfn inspect_slice(values: &[Input]) { values.len(); for value in values { value.wipe(\"/xmod-rust-slice\"); } }\nfn inspect_option(value: Option<Input>) { value.unwrap().wipe(\"/xmod-rust-option\"); }\nfn inspect_strings(values: Vec<String>) { values.len(); }\npub fn run() { inspect_vec(Vec::new()); inspect_slice(&[]); inspect_option(Some(Input)); inspect_strings(Vec::new()); }\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "main.rs")
        .expect("main.rs analyzed")
        .payload
        .into_effects()
        .unwrap();

    let resources: Vec<_> = report
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    for expected in [
        "fs:/xmod-rust-option",
        "fs:/xmod-rust-slice",
        "fs:/xmod-rust-vec",
    ] {
        assert!(
            resources.contains(&expected.to_string()),
            "effects: {resources:?}"
        );
    }
    assert!(!resources.contains(&"fs:/wrong-element-len".to_string()));
    assert!(
        report.boundaries.iter().all(|boundary| {
            boundary
                .detail
                .as_deref()
                .is_none_or(|detail| !detail.starts_with("len "))
        }),
        "accepted Vec, slice, and Vec<String> len calls stay quiet: {:?}",
        report.boundaries
    );
}

#[test]
fn rust_opaque_iterator_methods_keep_unresolved_boundaries() {
    for (case, body) in [
        ("bound", "let wiper = make(); wiper.last();"),
        ("direct", "make().last();"),
    ] {
        let source = format!(
            "pub struct Wiper;\nimpl Iterator for Wiper {{\n    type Item = ();\n    fn next(&mut self) -> Option<Self::Item> {{ std::fs::remove_file(\"/xmod-rust-iterator-last\"); None }}\n}}\nfn make() -> Wiper {{ Wiper }}\npub fn run() {{ {body} }}\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("xmod-rust-iterator-last-{case}"),
            &[
                ("main.rs", "mod iterator;\nfn main() { iterator::run(); }\n"),
                ("iterator.rs", &source),
            ],
        );
        let report = effects_of(&build_index(&root, IndexLimits::default()), "main.rs")
            .expect("main.rs analyzed")
            .payload
            .into_effects()
            .unwrap();

        assert!(
            report.boundaries.iter().any(|boundary| {
                boundary.reason == "unresolved_call"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.starts_with("last "))
            }),
            "{case} receiver boundaries: {:?}",
            report.boundaries
        );
    }
}

#[test]
fn rust_unclassified_std_and_third_party_receivers_stay_loud() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-rust-unclassified-receivers",
        &[
            ("main.rs", "mod worker;\nfn main() { worker::run(); }\n"),
            (
                "worker.rs",
                "use third_party::Vec as ExternalVec;\npub struct Input;\nfn std_receiver(values: Vec<Input>) { values.capacity(); }\nfn external_receiver(values: ExternalVec<Input>) { values.len(); }\npub fn run() { std_receiver(Vec::new()); external_receiver(external()); }\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "main.rs")
        .expect("main.rs analyzed")
        .payload
        .into_effects()
        .unwrap();

    assert!(report.boundaries.iter().any(|boundary| {
        boundary.reason == "unresolved_call"
            && boundary.detail.as_deref().is_some_and(|detail| {
                detail.contains("capacity") && detail.contains("std::vec::Vec")
            })
    }));
    assert!(report.boundaries.iter().any(|boundary| {
        boundary.reason == "unresolved_call"
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("len") && detail.contains("third_party::Vec"))
    }));
}

#[test]
fn rust_repository_trait_method_wins_before_inert_classification() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-rust-timezone-trait",
        &[
            ("main.rs", "mod zone;\nfn main() { zone::run(); }\n"),
            (
                "zone.rs",
                "trait Shift { fn with_timezone(&self, zone: &str); }\npub struct TimeZone;\nimpl Shift for TimeZone { fn with_timezone(&self, _zone: &str) { std::fs::remove_file(\"/xmod-rust-timezone\"); } }\npub fn run() { let zone: TimeZone = TimeZone; zone.with_timezone(\"UTC\"); }\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "main.rs")
        .expect("main.rs analyzed")
        .payload
        .into_effects()
        .unwrap();

    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource)
                == "fs:/xmod-rust-timezone"
    }));
}

fn composed_resource(
    tag: &str,
    entrypoint: &str,
    files: &[(&str, &str)],
    operation: &str,
) -> String {
    let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, files);
    let index = build_index(&root, IndexLimits::default());
    let resource = effects_of(&index, entrypoint)
        .unwrap_or_else(|| panic!("no effect surface for {entrypoint} in {tag}"))
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| effect.operation.0 == operation)
        .unwrap_or_else(|| panic!("no {operation} effect for {entrypoint}"))
        .resource
        .clone();
    effinterp_proto::display_resource(&resource)
}

#[test]
fn python_keyword_only_parameters_do_not_bind_cross_file_positionals() {
    let resource = composed_resource(
        "xmod-python-keyword-only-positionals",
        "app.py",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import emit\nemit('/etc/shadow')\n",
            ),
            (
                "lib.py",
                "def emit(*paths, target='/tmp/target.log'):\n    open(target, 'w').write('x')\n",
            ),
        ],
        "filesystem.write",
    );
    assert_eq!(resource, "<target>");
}

#[test]
fn filesystem_arguments_keep_identity_across_function_and_file_boundaries() {
    for (case, operand) in [
        ("relative", "data/x.txt"),
        ("url-like", "s3://bucket/key.txt"),
    ] {
        let python_single = format!(
            "#!/usr/bin/env python\nimport os\ndef wipe(p):\n    os.remove(p)\nwipe('{operand}')\n"
        );
        let python_app =
            format!("#!/usr/bin/env python\nfrom lib import wipe\nwipe('{operand}')\n");
        let python_cross = composed_resource(
            &format!("xmod-value-python-cross-{case}"),
            "app.py",
            &[
                ("app.py", &python_app),
                ("lib.py", "import os\ndef wipe(p):\n    os.remove(p)\n"),
            ],
            "filesystem.delete",
        );
        assert_eq!(
            python_cross,
            composed_resource(
                &format!("xmod-value-python-single-{case}"),
                "app.py",
                &[("app.py", &python_single)],
                "filesystem.delete",
            ),
            "Python resource identity changed across a file boundary for {operand}"
        );

        let js_single = format!(
            "import {{ rmSync }} from 'fs'\nfunction wipe(p) {{ rmSync(p) }}\nwipe('{operand}')\n"
        );
        let js_app = format!("import {{ wipe }} from './lib.js'\nwipe('{operand}')\n");
        let js_cross = composed_resource(
            &format!("xmod-value-js-cross-{case}"),
            "app.js",
            &[
                ("app.js", &js_app),
                (
                    "lib.js",
                    "import { rmSync } from 'fs'\nexport function wipe(p) { rmSync(p) }\n",
                ),
            ],
            "filesystem.delete",
        );
        assert_eq!(
            js_cross,
            composed_resource(
                &format!("xmod-value-js-single-{case}"),
                "app.js",
                &[("app.js", &js_single)],
                "filesystem.delete",
            ),
            "JavaScript resource identity changed across a file boundary for {operand}"
        );

        for resource in [python_cross, js_cross] {
            assert!(
                resource.starts_with("join(<cwd>, fs:"),
                "a cwd-relative filesystem operand must stay visibly symbolic: {resource}"
            );
        }
    }
}

#[test]
fn network_concatenation_is_typed_after_cross_file_substitution() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-network-concatenation",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom client import fetch_parts, fetch_url\nbase = 'https://api.example'\nfetch_parts(base, token)\nfetch_url('https://api.example/' + token)\n",
            ),
            (
                "client.py",
                "import requests\ndef fetch_parts(base, token):\n    requests.get(base + '/v1/' + token)\ndef fetch_url(url):\n    requests.get(url)\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects: Vec<_> = index
        .composition("app.py")
        .expect("app.py composition")
        .effects
        .iter()
        .filter(|effect| effect.effect.operation.0 == "network.request")
        .collect();
    assert_eq!(effects.len(), 2);
    assert!(effects.iter().all(|effect| matches!(
        &effect.effect.resource,
        effinterp_proto::ResourceExpr::Join { parts }
            if matches!(
                parts.first(),
                Some(effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme,
                        ..
                    }
                }) if host == "api.example" && scheme.as_deref() == Some("https")
            )
    )));
}

#[test]
fn filesystem_concatenation_preserves_environment_after_cross_file_substitution() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-filesystem-concatenation",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport os\nfrom cleanup import wipe_plus, wipe_fstring\nwipe_plus(os.environ['HOME'])\nwipe_fstring(os.environ['HOME'])\n",
            ),
            (
                "cleanup.py",
                "import os\ndef wipe_plus(base):\n    os.remove(base + '/.cache/x')\ndef wipe_fstring(base):\n    os.remove(f'{base}/.cache/y')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects: Vec<_> = index
        .composition("app.py")
        .expect("app.py composition")
        .effects
        .iter()
        .filter(|effect| effect.effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(effects.len(), 2);
    assert!(effects.iter().all(|effect| matches!(
        &effect.effect.resource,
        effinterp_proto::ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                effinterp_proto::ResourceExpr::Environment { name },
                effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                }
            ] if name == "HOME" && path.starts_with("/.cache/"))
    )));
}

fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// A canonical dump of every entrypoint's effective surface (direct + composed
/// effects), for comparing an incrementally-updated index to a clean rebuild.
fn surface_dump(idx: &effinterp_repo::RepoIndex) -> Vec<(String, Vec<String>)> {
    let mut ids: Vec<String> = idx
        .entrypoints
        .iter()
        .map(|e| e.entrypoint.id.clone())
        .collect();
    ids.sort();
    ids.into_iter()
        .map(|id| {
            let effects = effinterp_repo::effects_of(idx, &id)
                .map(|r| {
                    let mut rows: Vec<String> = r
                        .payload
                        .as_effects()
                        .unwrap()
                        .effects
                        .iter()
                        .map(|e| {
                            format!(
                                "{} {}",
                                e.operation.0,
                                effinterp_proto::display_resource(&e.resource)
                            )
                        })
                        .collect();
                    rows.sort();
                    rows
                })
                .unwrap_or_default();
            (id, effects)
        })
        .collect()
}

/// The correctness oracle: after any incremental event, the index must be
/// byte-equivalent to a clean rebuild of the final on-disk state — same
/// fingerprint and same effective surface for every entrypoint.
fn assert_equivalent_to_rebuild(incremental: &effinterp_repo::RepoIndex, root: &Path) {
    let rebuilt = build_index(root, IndexLimits::default());
    assert_eq!(
        incremental.fingerprint, rebuilt.fingerprint,
        "fingerprint mismatch vs clean rebuild"
    );
    assert_eq!(
        surface_dump(incremental),
        surface_dump(&rebuilt),
        "effective surface mismatch vs clean rebuild"
    );
}

#[test]
fn incremental_unchanged_file_is_a_noop() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-noop",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    let before = idx.fingerprint.clone();
    // A modify event for identical content leaves the fingerprint unchanged.
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("util.py".into())],
    );
    assert_eq!(
        idx.fingerprint, before,
        "identical content: fingerprint stable"
    );
    assert_equivalent_to_rebuild(&idx, &root);
}

#[test]
fn incremental_matches_clean_rebuild_for_every_event() {
    // Modify a dependency.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-modify",
        &[("app.py", APP_PY), ("util.py", UTIL_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    write_file(
        &root,
        "util.py",
        "import shutil\ndef wipe(root, t):\n    shutil.rmtree(root)\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("util.py".into())],
    );
    assert_equivalent_to_rebuild(&idx, &root);

    // Add a brand-new entrypoint file.
    write_file(
        &root,
        "extra.py",
        "#!/usr/bin/env python\nimport os\nos.remove(\"/tmp/z\")\n",
    );
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("extra.py".into())],
    );
    assert_equivalent_to_rebuild(&idx, &root);

    // Delete a file.
    std::fs::remove_file(root.join("extra.py")).unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Deleted("extra.py".into())],
    );
    assert_equivalent_to_rebuild(&idx, &root);

    // Rename util.py -> helpers.py (delete + add); app.py's import breaks, so
    // its cross-file delete becomes an unresolved boundary — the rebuild must
    // agree.
    std::fs::rename(root.join("util.py"), root.join("helpers.py")).unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[
            RepoChange::Deleted("util.py".into()),
            RepoChange::Added("helpers.py".into()),
        ],
    );
    assert_equivalent_to_rebuild(&idx, &root);
}

#[test]
fn incremental_new_file_resolves_a_previously_external_call() {
    // app.py imports util.wipe, but util.py does not exist yet -> external.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-resolve",
        &[("app.py", APP_PY)],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    // No cross-file delete yet.
    assert!(
        !surface_dump(&idx)
            .iter()
            .any(|(_, fx)| fx.iter().any(|s| s.contains("filesystem.delete"))),
        "no cross-file delete before util.py exists"
    );
    let unresolved = effects_of(&idx, "app.py")
        .expect("app.py analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        unresolved
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_call"),
        "boundaries: {:?}",
        unresolved.boundaries
    );
    // Adding util.py resolves the call.
    write_file(&root, "util.py", UTIL_PY);
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("util.py".into())],
    );
    assert_equivalent_to_rebuild(&idx, &root);
    assert!(
        surface_dump(&idx)
            .iter()
            .any(|(_, fx)| fx.iter().any(|s| s.contains("filesystem.delete"))),
        "cross-file delete appears once util.py resolves the call"
    );
    let report = effects_of(&idx, "app.py")
        .expect("app.py analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_call")
    );
    assert_eq!(
        report.coverage.get("filesystem").map(|claim| claim.level),
        Some(effinterp_proto::CoverageLevel::Partial)
    );
}

#[test]
fn resolving_one_call_preserves_other_gaps_and_nonfull_claims() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-coverage-contributors",
        &[
            (
                "app.js",
                "#!/usr/bin/env node\nimport { wipe, missing } from './util.js';\nwipe('/known');\nmissing();\n",
            ),
            (
                "pure.js",
                "#!/usr/bin/env node\nimport { noop } from './util.js';\nnoop();\n",
            ),
            (
                "util.js",
                "import fs from 'fs';\nexport function wipe(path) { fs.rmSync(path); }\nexport function noop() { return 1; }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let pure = effective_surface(&index, "pure.js").unwrap();
    assert!(pure.effects.is_empty(), "{pure:?}");
    assert_eq!(
        pure.coverage.get("filesystem"),
        Some(&effinterp_proto::CoverageLevel::Full)
    );
    assert!(
        pure.boundaries
            .iter()
            .all(|b| b.reason != "unresolved_call")
    );
    let surface = effective_surface(&index, "app.js").unwrap();
    assert!(surface.effects.iter().any(|e| e.resource == "fs:/known"));
    assert_eq!(
        surface.coverage.get("filesystem"),
        Some(&effinterp_proto::CoverageLevel::Partial)
    );
    assert!(
        surface.boundaries.iter().any(|b| b
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("missing"))
            && b.provenance.iter().any(|p| p.render().contains("app.js"))),
        "{surface:?}"
    );

    // Isolate the evidence boundary: even with the call resolved, a callee's
    // independent non-full or missing claim cannot be promoted by its effect.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xmod-coverage-nonfull",
        &[
            (
                "app.js",
                "#!/usr/bin/env node\nimport { wipe } from './util.js';\nwipe('/known');\n",
            ),
            (
                "util.js",
                "import fs from 'fs';\nexport function wipe(path) { fs.rmSync(path); }\n",
            ),
        ],
    );
    let original = build_index(&root, IndexLimits::default());
    for level in [
        None,
        Some(effinterp_proto::CoverageLevel::Partial),
        Some(effinterp_proto::CoverageLevel::None),
    ] {
        let mut index = original.clone();
        let comp = std::sync::Arc::make_mut(index.composed.get_mut("app.js").unwrap());
        comp.coverage.retain(|(domain, _)| domain != "filesystem");
        if let Some(level) = level {
            comp.coverage.push(("filesystem".into(), level));
        }
        let surface = effinterp_repo::effective_surface(&index, "app.js").unwrap();
        assert_ne!(
            surface.coverage.get("filesystem"),
            Some(&effinterp_proto::CoverageLevel::Full)
        );
        assert!(
            surface
                .boundaries
                .iter()
                .any(|b| b.domains.contains(&"filesystem".to_string())),
            "{surface:?}"
        );
    }
}

#[test]
fn guarded_calls_keep_instances_and_nested_formulas_through_incremental_builds() {
    use effinterp_proto::{ConditionKind, ResourceExpr, ResourceIdentity};
    let app = "#!/usr/bin/env python\nfrom util import wipe\nif outer:\n wipe('/a')\n wipe('/b')\n";
    let util = "import os\ndef wipe(path):\n if inner:\n  os.remove(path)\n";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "guarded-call-instances",
        &[("app.py", app), ("util.py", util)],
    );
    let mut index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "app.py").unwrap();
    let guard = |path| {
        report.payload.as_effects().unwrap().effects.iter().find(|e| e.operation.0 == "filesystem.delete" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)).unwrap().condition.as_ref().unwrap()
    };
    let a = guard("/a");
    let b = guard("/b");
    assert_eq!(a.atoms().len(), 2);
    assert_eq!(b.atoms().len(), 2);
    assert!(
        a.atoms()
            .iter()
            .all(|a| a.origin.kind == ConditionKind::Branch && a.polarity == Some(true))
    );
    assert_ne!(a.identity_key(), b.identity_key());
    assert_eq!(
        a.atoms()
            .iter()
            .map(|a| &a.origin.source_digest)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    std::fs::write(root.join("util.py"), util.replace("inner", "changed")).unwrap();
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("util.py".into())],
    );
    let clean = build_index(&root, IndexLimits::default());
    assert_eq!(
        effinterp_proto::canonical_json(&effects_of(&index, "app.py").unwrap()),
        effinterp_proto::canonical_json(&effects_of(&clean, "app.py").unwrap())
    );
}
