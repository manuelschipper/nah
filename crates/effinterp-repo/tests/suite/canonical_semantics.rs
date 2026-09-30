//! Canonicalization preserves the full effect contract: effects that differ in
//! attributes, condition, or modality are distinct conclusions and must not be
//! silently collapsed by deduplication.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{IndexLimits, build_index, effective_surface};
use effinterp_testkit::repo_fixture::repo_test_fixture;

#[test]
fn imported_exception_contract_survives_cleanup() {
    use effinterp_proto::Modality::{May, MustOnSuccess};
    for (name, body, before, after) in [
        ("returns", "return", MustOnSuccess, MustOnSuccess),
        ("throws", "raise RuntimeError", MustOnSuccess, May),
        ("never", "while True: pass", May, May),
        (
            "throws_before_effect",
            "[][0]\n os.remove('/inside')",
            MustOnSuccess,
            May,
        ),
        (
            "may_throw_before_effect",
            "items[0]\n os.remove('/inside')",
            MustOnSuccess,
            May,
        ),
        (
            "effect_then_throw",
            "os.remove('/inside')\n raise RuntimeError",
            MustOnSuccess,
            May,
        ),
    ] {
        let helper = format!("import os\ndef middle():\n {body}\n");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-exception-{name}"),
            &[
                ("helper.py", &helper),
                (
                    "app.py",
                    "#!/usr/bin/env python3\nfrom worker import run\nrun()\n",
                ),
                (
                    "worker.py",
                    "import os\nfrom helper import middle\ndef run():\n os.remove('/before')\n try:\n  middle()\n  os.remove('/after')\n finally:\n  return\n",
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        for file in index.registry.files.values() {
            for function in &file.summary.functions {
                let flow: effinterp_engine::ControlFlow = serde_json::from_slice(
                    &serde_json::to_vec(&function.summary.control_flow).unwrap(),
                )
                .unwrap();
                let required = flow.requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
                assert_eq!(
                    required,
                    function.summary.control_flow.requirements(
                        &mut |_| false,
                        &mut |_| None,
                        &mut |_, _| true,
                    )
                );
                if file.path == "helper.py" && function.name == "middle" {
                    assert_eq!(
                        required.throws,
                        matches!(
                            name,
                            "throws"
                                | "throws_before_effect"
                                | "may_throw_before_effect"
                                | "effect_then_throw"
                        )
                    );
                    assert_eq!(
                        required.succeeds,
                        matches!(name, "returns" | "may_throw_before_effect")
                    );
                }
            }
        }
        {
            let surface = effective_surface(&index, "app.py").unwrap();
            for (path, modality) in
                [("/before", before), ("/after", after)]
                    .into_iter()
                    .chain(match name {
                        "throws_before_effect" | "may_throw_before_effect" => {
                            Some(("/inside", May))
                        }
                        "effect_then_throw" => Some(("/inside", MustOnSuccess)),
                        _ => None,
                    })
            {
                let effects: Vec<_> = surface
                    .effects
                    .iter()
                    .filter(|effect| {
                        effect.operation == "filesystem.delete" && effect.resource.contains(path)
                    })
                    .collect();
                assert_eq!(effects.len(), 1, "{name} {path}: {effects:?}");
                assert_eq!(effects[0].modality, modality, "{name} {path}");
            }
        }
    }
}

#[test]
fn imported_typed_handlers_recompute_on_stored_graphs() {
    use effinterp_proto::Modality::{May, MustOnSuccess};
    for (name, body, handler, after) in [
        (
            "mismatch",
            "raise RuntimeError",
            "except ValueError:\n  pass",
            May,
        ),
        (
            "match",
            "raise RuntimeError",
            "except Exception:\n  pass",
            MustOnSuccess,
        ),
        (
            "unknown_return",
            "os.remove('/inside')",
            "except ValueError:\n  return",
            May,
        ),
    ] {
        let helper = format!("import os\ndef middle():\n {body}\n");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-typed-{name}"),
            &[
                ("helper.py", &helper),
                (
                    "app.py",
                    "#!/usr/bin/env python3\nfrom worker import run\nrun()\n",
                ),
                (
                    "worker.py",
                    &format!(
                        "import os\nfrom helper import middle\ndef run():\n os.remove('/before')\n try:\n  middle()\n {handler}\n os.remove('/after')\n"
                    ),
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        for file in index.registry.files.values() {
            for function in &file.summary.functions {
                let flow: effinterp_engine::ControlFlow = serde_json::from_slice(
                    &serde_json::to_vec(&function.summary.control_flow).unwrap(),
                )
                .unwrap();
                let required = flow.requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
                assert_eq!(
                    required,
                    function.summary.control_flow.requirements(
                        &mut |_| false,
                        &mut |_| None,
                        &mut |_, _| true,
                    )
                );
            }
        }
        let surface = effective_surface(&index, "app.py").unwrap();
        let effects: Vec<_> = surface
            .effects
            .iter()
            .filter(|effect| {
                effect.operation == "filesystem.delete" && effect.resource.contains("/after")
            })
            .collect();
        assert_eq!(effects.len(), 1, "{name}: {effects:?}");
        assert_eq!(effects[0].modality, after, "{name}");
    }
}

#[test]
fn imported_maybe_return_does_not_make_sibling_delete_required() {
    use effinterp_proto::Modality::May;
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-maybe-return-sibling",
        &[
            (
                "helper.py",
                "def middle():\n try:\n  raise x\n except ValueError:\n  return\n",
            ),
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom worker import run\nrun()\n",
            ),
            (
                "worker.py",
                "import os\nfrom helper import middle\ndef run():\n if flag:\n  middle()\n else:\n  os.remove('/out')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&index, "app.py").unwrap();
    let effects: Vec<_> = surface
        .effects
        .iter()
        .filter(|effect| {
            effect.operation == "filesystem.delete" && effect.resource.contains("/out")
        })
        .collect();
    assert_eq!(effects.len(), 1, "{effects:?}");
    assert_eq!(effects[0].modality, May);
}

#[test]
fn imported_shadowed_and_foreign_bindings_do_not_match() {
    use effinterp_proto::Modality::May;
    for (tag, files) in [
        (
            "shadow",
            [
                (
                    "helper.py",
                    "import os\nRuntimeError = 1\ndef middle():\n try:\n  raise RuntimeError\n except Exception:\n  pass\n os.remove('/out')\n",
                ),
                (
                    "app.py",
                    "#!/usr/bin/env python3\nfrom worker import run\nrun()\n",
                ),
                (
                    "worker.py",
                    "from helper import middle\ndef run():\n middle()\n",
                ),
            ],
        ),
        (
            "foreign-e",
            [
                ("helper.py", "class E:\n pass\ndef middle():\n raise E\n"),
                (
                    "app.py",
                    "#!/usr/bin/env python3\nfrom worker import run\nrun()\n",
                ),
                (
                    "worker.py",
                    "import os\nfrom helper import middle\nclass E:\n pass\ndef run():\n try:\n  middle()\n except E:\n  pass\n os.remove('/out')\n",
                ),
            ],
        ),
    ] {
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-bind-{tag}"),
            &files,
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.py").unwrap();
        let effects: Vec<_> = surface
            .effects
            .iter()
            .filter(|effect| {
                effect.operation == "filesystem.delete" && effect.resource.contains("/out")
            })
            .collect();
        assert_eq!(effects.len(), 1, "{tag}: {effects:?}");
        assert_eq!(effects[0].modality, May, "{tag}");
    }
}

#[test]
fn imported_parameter_patterns_preserve_exception_contracts() {
    use effinterp_proto::Modality::{May, MustOnSuccess};
    for (name, pattern) in [("object", "{a}"), ("array", "[a]")] {
        let helper = format!("export function middle({pattern}) {{ return a; }}");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-js-pattern-{name}"),
            &[
                (
                    "app.js",
                    "#!/usr/bin/env node\nimport { run } from './worker.js'; run();",
                ),
                (
                    "worker.js",
                    "import { unlinkSync } from 'node:fs'; import { middle } from './helper.js'; export function run() { unlinkSync('/before'); try { middle(null); unlinkSync('/after'); } finally { return; } }",
                ),
                ("helper.js", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.js").unwrap();
        for (path, modality) in [("/before", MustOnSuccess), ("/after", May)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "{name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "{name} {path}");
        }
    }
}

#[test]
fn differing_attributes_are_not_collapsed() {
    // Two deletes of the same path: one recursive, one not. They are different
    // conclusions and must both survive canonicalization.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-attrs",
        &[("s.sh", "#!/bin/sh\nrm -r /data\nrm /data\n")],
    );
    let idx = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&idx, "s.sh").expect("s.sh has a surface");

    let deletes: Vec<_> = surface
        .effects
        .iter()
        .filter(|e| e.operation.as_str() == "filesystem.delete" && e.resource.contains("/data"))
        .collect();
    assert_eq!(
        deletes.len(),
        2,
        "recursive and non-recursive delete of /data must be distinct rows: {:?}",
        deletes
            .iter()
            .map(|e| (&e.operation, &e.resource, &e.attributes))
            .collect::<Vec<_>>()
    );
    let recursive_count = deletes
        .iter()
        .filter(|e| e.attributes.contains_key("recursive"))
        .count();
    assert_eq!(recursive_count, 1, "exactly one of the two is recursive");
}

#[test]
fn resolved_call_returns_control_necessity_without_vacuous_requirements() {
    use effinterp_proto::Modality::{May, MustOnSuccess};
    for (name, middle, before, after) in [
        ("returns", "return", MustOnSuccess, MustOnSuccess),
        ("opaque", "mystery()", MustOnSuccess, May),
        ("recursive", "middle()", MustOnSuccess, May),
        ("never", "while True: pass", May, May),
    ] {
        let go_middle = match name {
            "returns" => "return",
            "opaque" => "mystery()",
            "recursive" => "Middle()",
            "never" => "for {}",
            _ => unreachable!(),
        };
        let helper = format!(
            "package helper\nimport \"os\"\nfunc Before() {{ os.Remove(\"/before\") }}\nfunc Middle() {{ {go_middle} }}\nfunc After() {{ os.Remove(\"/after\") }}\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-go-call-{name}"),
            &[
                ("go.mod", "module example.com/proof\n\ngo 1.22\n"),
                (
                    "main.go",
                    "package main\nimport \"example.com/proof/helper\"\nfunc main() { helper.Before(); helper.Middle(); helper.After() }\n",
                ),
                ("helper/helper.go", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "main.go").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "Go {name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "Go {name} {path}");
        }
        let helper = format!(
            "import os\ndef before():\n os.remove('/before')\ndef middle():\n {middle}\ndef after():\n os.remove('/after')\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-call-{name}"),
            &[
                (
                    "app.py",
                    "#!/usr/bin/env python3\nfrom helper import before, middle, after\nbefore()\nmiddle()\nafter()\n",
                ),
                ("helper.py", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.py").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "{name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "{name} {path}");
        }
        let middle = if name == "never" {
            "while (true) {}"
        } else {
            middle
        };
        let helper = format!(
            "import {{ unlinkSync }} from 'node:fs';\nexport function before() {{ unlinkSync('/before'); }}\nexport function middle() {{ {middle}; }}\nexport function after() {{ unlinkSync('/after'); }}\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-js-call-{name}"),
            &[
                (
                    "app.js",
                    "#!/usr/bin/env node\nimport { before, middle, after } from './helper.js';\nbefore(); middle(); after();\n",
                ),
                ("helper.js", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.js").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "JS {name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "JS {name} {path}");
        }
        let helper = format!(
            "<?php function before() {{ unlink('/before'); }} function middle() {{ {middle}; }} function after() {{ unlink('/after'); }}"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-php-call-{name}"),
            &[
                (
                    "app.php",
                    "#!/usr/bin/env php\n<?php require 'helper.php'; before(); middle(); after();",
                ),
                ("helper.php", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.php").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "PHP {name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "PHP {name} {path}");
        }
        let helper = format!(
            "import java.nio.file.Files; import java.nio.file.Path; class Helper {{ static void before() throws Exception {{ Files.delete(Path.of(\"/before\")); }} static void middle() {{ {middle}; }} static void after() throws Exception {{ Files.delete(Path.of(\"/after\")); }} }}"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-java-call-{name}"),
            &[
                (
                    "Main.java",
                    "public class Main { public static void main(String[] args) throws Exception { Helper.before(); Helper.middle(); Helper.after(); } }",
                ),
                ("Helper.java", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "Main.java").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "Java {name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "Java {name} {path}");
        }
        let helper = format!(
            "pub fn before() {{ std::fs::remove_file(\"/before\"); }} pub fn middle() {{ {middle}; }} pub fn after() {{ std::fs::remove_file(\"/after\"); }}"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-rust-call-{name}"),
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"proof\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "src/main.rs",
                    "mod helper;\nfn main() { helper::before(); helper::middle(); helper::after(); }\n",
                ),
                ("src/helper.rs", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "src/main.rs").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "Rust {name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "Rust {name} {path}");
        }
        let middle = if name == "never" {
            "while true; end"
        } else {
            middle
        };
        let helper = format!(
            "class Helper\ndef self.before; File.delete('/before'); end\ndef self.middle; {middle}; end\ndef self.after; File.delete('/after'); end\nend"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-ruby-call-{name}"),
            &[
                (
                    "app.rb",
                    "#!/usr/bin/env ruby\nrequire_relative 'helper'\nHelper.before; Helper.middle; Helper.after",
                ),
                ("helper.rb", &helper),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.rb").unwrap();
        for (path, modality) in [("/before", before), ("/after", after)] {
            let effects: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .collect();
            assert_eq!(effects.len(), 1, "Ruby {name} {path}: {effects:?}");
            assert_eq!(effects[0].modality, modality, "Ruby {name} {path}");
        }
    }
    for (prefix, expected) in [("", May), ("await ", MustOnSuccess)] {
        let app = format!(
            "#!/usr/bin/env node\nimport {{ wipe }} from './helper.js';\n{prefix}wipe();\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-js-async-{}", prefix.len()),
            &[
                ("app.js", &app),
                (
                    "helper.js",
                    "import { unlinkSync } from 'node:fs'; export async function wipe() { unlinkSync('/async'); }",
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "app.js").unwrap();
        let effects: Vec<_> = surface
            .effects
            .iter()
            .filter(|effect| {
                effect.operation == "filesystem.delete" && effect.resource.contains("/async")
            })
            .collect();
        assert_eq!(effects.len(), 1, "async effects must survive");
        assert_eq!(effects[0].modality, expected, "{prefix}wipe()");
    }
}

#[test]
fn identical_effects_still_deduplicate() {
    // The same delete twice collapses to a single row (no spurious duplicate).
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-dup",
        &[("s.sh", "#!/bin/sh\nrm /data\nrm /data\n")],
    );
    let idx = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&idx, "s.sh").expect("s.sh has a surface");
    let deletes = surface
        .effects
        .iter()
        .filter(|e| e.operation.as_str() == "filesystem.delete" && e.resource.contains("/data"))
        .count();
    assert_eq!(deletes, 1, "identical deletes collapse to one row");

    // An opaque call can complete the invocation before the second delete.
    // Deduplication must not turn that optional occurrence into a required one.
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-modality",
        &[(
            "app.py",
            "#!/usr/bin/env python3\nimport os\nos.remove('/data')\nmystery()\nos.remove('/data')\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&idx, "app.py").expect("app.py has a surface");
    let deletes: Vec<_> = surface
        .effects
        .iter()
        .filter(|effect| {
            effect.operation.as_str() == "filesystem.delete" && effect.resource.contains("/data")
        })
        .collect();
    assert!(
        deletes
            .iter()
            .any(|effect| effect.modality == effinterp_proto::Modality::May)
    );
    assert!(
        deletes
            .iter()
            .any(|effect| effect.modality == effinterp_proto::Modality::MustOnSuccess)
    );
}

/// The single-file plan cannot discharge an import it could not resolve, so an
/// entrypoint's own effects lose necessity the moment it imports a repository
/// module — while a composed cross-file effect keeps the proof the repository
/// made. Publishing both views leaves one interaction with two modalities and
/// an optional occurrence ahead of a required one. The surface publishes one
/// conclusion per occurrence, and only when the repository covered every plan
/// occurrence of that value: a look-alike on an optional path is never
/// promoted with it.
#[test]
fn repository_necessity_reaches_the_entrypoints_own_occurrences() {
    use effinterp_proto::Modality::{May, MustOnSuccess};
    for (name, body, head, always) in [
        (
            "straight-line",
            "os.remove('/head')\n lib.always('/always')",
            MustOnSuccess,
            MustOnSuccess,
        ),
        (
            "conditional",
            "if flag:\n  os.remove('/head')\n lib.always('/always')",
            May,
            MustOnSuccess,
        ),
        (
            "after-unknown",
            "unknownfn()\n os.remove('/head')\n lib.always('/always')",
            May,
            May,
        ),
        (
            "look-alike-arms",
            "if flag:\n  os.remove('/head')\n os.remove('/head')\n lib.always('/always')",
            May,
            MustOnSuccess,
        ),
    ] {
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("canon-local-necessity-{name}"),
            &[
                ("lib.py", "import os\ndef always(p):\n os.remove(p)\n"),
                (
                    "main.py",
                    &format!(
                        "import os\nimport lib\ndef main():\n {body}\nif __name__ == '__main__':\n main()\n"
                    ),
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "main.py").unwrap();
        for (path, modality) in [("/head", head), ("/always", always)] {
            let modalities: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation == "filesystem.delete" && effect.resource.contains(path)
                })
                .map(|effect| effect.modality)
                .collect();
            assert!(!modalities.is_empty(), "{name} {path}: missing");
            assert!(
                modalities.iter().all(|actual| *actual == modality),
                "{name} {path}: {modalities:?}"
            );
        }
    }
}

/// A callable whose summary never settles cannot carry a proof, but the
/// callables that never reached it are unaffected: freezing the whole module
/// would drop necessity for every function in any file that happens to hold a
/// recursive effectful helper, and would do so with no limit evidence.
#[test]
fn an_unsettled_callable_only_costs_the_callers_that_reached_it() {
    use effinterp_proto::Modality::{May, MustOnSuccess};
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-unsettled-group",
        &[
            (
                "lib.py",
                "import os\ndef always(p):\n os.remove(p)\ndef rec(n, p):\n if n > 0:\n  rec(n - 1, p)\n os.remove(p)\ndef viarec(p):\n rec(2, p)\n",
            ),
            (
                "main.py",
                "import lib\ndef main():\n lib.always('/always')\n lib.viarec('/viarec')\nif __name__ == '__main__':\n main()\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&index, "main.py").unwrap();
    for (path, modality) in [("/always", MustOnSuccess), ("/viarec", May)] {
        let modalities: Vec<_> = surface
            .effects
            .iter()
            .filter(|effect| {
                effect.operation == "filesystem.delete" && effect.resource.contains(path)
            })
            .map(|effect| effect.modality)
            .collect();
        assert!(!modalities.is_empty(), "{path}: missing");
        assert!(
            modalities.iter().all(|actual| *actual == modality),
            "{path}: {modalities:?}"
        );
    }
    assert!(
        surface
            .boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_summary_iterations")),
        "the unsettled fixpoint must leave limit evidence: {:?}",
        surface.boundaries
    );
}
