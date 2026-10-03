//! Real Python import semantics for import-time composition: what an import
//! executes (a module's top level, once per analysis), what it must NOT
//! execute (function bodies, main guards, TYPE_CHECKING blocks, mere
//! definitions), and how `from pkg import name` resolves when `name` is an
//! attribute, a re-export, or a submodule.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::deletes;

/// The deletes on the entry's merged surface, as (resource, origin) pairs.
const WIPE_LIB: &str = "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n";

/// `from pkg import name` where `name` is defined in `pkg/__init__.py` itself.
#[test]
fn from_package_import_attribute_defined_in_init() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-attr",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom pkg import wipe\nwipe(\"/attr\")\n",
            ),
            ("pkg/__init__.py", WIPE_LIB),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/attr") && o == "pkg/__init__.py"),
        "attribute defined in __init__.py composes: {got:?}"
    );
}

/// `from pkg import name` where `pkg/__init__.py` re-exports `name` from a
/// submodule (`from .impl import wipe`).
#[test]
fn from_package_import_reexport_follows_to_definition() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-reexport",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom pkg import wipe\nwipe(\"/reexp\")\n",
            ),
            ("pkg/__init__.py", "from .impl import wipe\n"),
            ("pkg/impl.py", WIPE_LIB),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/reexp") && o == "pkg/impl.py"),
        "re-export through __init__.py composes from the defining file: {got:?}"
    );
}

/// `from pkg import sub` where `sub` is a SUBMODULE: `sub.wipe(...)` must
/// resolve into `pkg/sub.py`.
#[test]
fn from_package_import_submodule_member_resolves() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-submodule",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom pkg import sub\nsub.wipe(\"/subm\")\n",
            ),
            ("pkg/__init__.py", ""),
            ("pkg/sub.py", WIPE_LIB),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/subm") && o == "pkg/sub.py"),
        "submodule member call composes: {got:?}"
    );
}

#[test]
fn imported_function_retracts_resolved_module_member_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-nested-module-member",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom caller import run\nrun()\n",
            ),
            (
                "caller.py",
                "from pkg import mod\ndef run():\n    mod.wipe('/nested-member')\n",
            ),
            ("pkg/__init__.py", ""),
            ("pkg/mod.py", WIPE_LIB),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "app.py")
        .expect("entry analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource)
                .contains("/nested-member")
    }));
    assert!(report.boundaries.iter().all(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_none_or(|detail| !detail.contains("pkg.mod.wipe"))
    }));
    assert_eq!(
        report.coverage.get("filesystem").map(|claim| claim.level),
        Some(effinterp_proto::CoverageLevel::Partial)
    );
}

#[test]
fn imported_function_retracts_resolved_relative_member_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-relative-member-boundary",
        &[
            (
                "httpie/__main__.py",
                "#!/usr/bin/env python\nfrom .ssl_ import main\nmain()\n",
            ),
            ("httpie/__init__.py", ""),
            (
                "httpie/ssl_.py",
                "from .compat import ensure_default_certs_loaded\ndef main():\n    ensure_default_certs_loaded()\n",
            ),
            (
                "httpie/compat.py",
                "import os\ndef ensure_default_certs_loaded():\n    os.unlink('/relative-member')\n",
            ),
        ],
    );
    let report = effects_of(
        &build_index(&root, IndexLimits::default()),
        "httpie/__main__.py",
    )
    .expect("entry analyzed")
    .payload
    .into_effects()
    .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource)
                == "fs:/relative-member"
    }));
    assert!(report.boundaries.iter().all(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_none_or(|detail| !detail.contains(".compat."))
    }));
}

/// A module imported by two files executes its top level once per analysis,
/// not once per import edge: exactly one occurrence in the walk, one effect.
#[test]
fn diamond_import_executes_module_once() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-diamond",
        &[
            ("app.py", "#!/usr/bin/env python\nimport a\nimport b\n"),
            ("a.py", "import shared\n"),
            ("b.py", "import shared\n"),
            (
                "shared.py",
                "from lib import wipe\nwipe(\"/shared-init\")\n",
            ),
            ("lib.py", WIPE_LIB),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx.composition("app.py").expect("app.py composes");
    let hits = comp
        .effects
        .iter()
        .filter(|e| format!("{:?}", e.effect.resource).contains("/shared-init"))
        .count();
    assert_eq!(hits, 1, "shared.py's import-time effect appears once");
    assert_eq!(
        comp.occurrences, 1,
        "the walk itself executed shared.py once, not once per import edge"
    );
}

/// An import cycle terminates and each module's top level contributes once.
#[test]
fn import_cycle_terminates_without_duplicate_expansion() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-cycle",
        &[
            ("app.py", "#!/usr/bin/env python\nimport a\n"),
            (
                "a.py",
                "import b\nfrom lib import wipe\nwipe(\"/a-init\")\n",
            ),
            (
                "b.py",
                "import a\nfrom lib import wipe\nwipe(\"/b-init\")\n",
            ),
            ("lib.py", WIPE_LIB),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx.composition("app.py").expect("app.py composes");
    for res in ["/a-init", "/b-init"] {
        let hits = comp
            .effects
            .iter()
            .filter(|e| format!("{:?}", e.effect.resource).contains(res))
            .count();
        assert_eq!(hits, 1, "{res} composes exactly once through the cycle");
    }
}

/// An import inside a function body executes at call time, not import time:
/// importing the module must not run the deferred module's top level.
#[test]
fn function_body_import_does_not_execute_at_import_time() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-deferred",
        &[
            ("app.py", "#!/usr/bin/env python\nimport mod\n"),
            (
                "mod.py",
                "def lazy():\n    from heavy import boom\n    boom()\n",
            ),
            (
                "heavy.py",
                "from lib import wipe\nwipe(\"/heavy-init\")\ndef boom():\n    pass\n",
            ),
            ("lib.py", WIPE_LIB),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        !got.iter().any(|(r, _)| r.contains("/heavy-init")),
        "a function-local import must not run heavy.py at import time: {got:?}"
    );
}

/// Imports under `if TYPE_CHECKING:` never execute.
#[test]
fn type_checking_import_does_not_execute() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-typechk",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import heavy\n",
            ),
            (
                "heavy.py",
                "from lib import wipe\nwipe(\"/typechk-init\")\n",
            ),
            ("lib.py", WIPE_LIB),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        !got.iter().any(|(r, _)| r.contains("/typechk-init")),
        "a TYPE_CHECKING import must not execute: {got:?}"
    );
}

/// `from m import Cls as C; C()` composes `Cls.__init__` through the alias.
#[test]
fn aliased_constructor_reaches_init() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-aliasctor",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom m import Cls as C\nC()\n",
            ),
            (
                "m.py",
                "import shutil\nclass Cls:\n    def __init__(self):\n        shutil.rmtree(\"/ctor\")\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter().any(|(r, o)| r.contains("/ctor") && o == "m.py"),
        "aliased constructor composes __init__: {got:?}"
    );
}

/// Importing a module that merely DEFINES effectful functions and classes runs
/// nothing; a module whose top level CALLS its own function runs it.
#[test]
fn import_runs_top_level_calls_not_definitions() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-defsonly",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport defs\nimport setup\n",
            ),
            (
                "defs.py",
                "import shutil\ndef nuke():\n    shutil.rmtree(\"/defs\")\nclass K:\n    def m(self):\n        shutil.rmtree(\"/defs-class\")\n",
            ),
            (
                "setup.py",
                "import shutil\ndef init():\n    shutil.rmtree(\"/setup-init\")\ninit()\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        !got.iter()
            .any(|(r, _)| r.contains("/defs") || r.contains("/defs-class")),
        "defined-but-uncalled bodies must not execute at import time: {got:?}"
    );
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/setup-init") && o == "setup.py"),
        "an imported module's own top-level call executes: {got:?}"
    );
}

/// A main guard runs only when the file IS the entrypoint, never on import.
#[test]
fn main_guard_runs_for_entrypoint_not_importers() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-mainguard",
        &[
            ("app.py", "#!/usr/bin/env python\nimport cli\n"),
            (
                "cli.py",
                "#!/usr/bin/env python\nfrom lib import wipe\ndef main():\n    wipe(\"/cli-run\")\nif __name__ == \"__main__\":\n    main()\n",
            ),
            ("lib.py", WIPE_LIB),
        ],
    );
    let importer = deletes(&root, "app.py");
    assert!(
        !importer.iter().any(|(r, _)| r.contains("/cli-run")),
        "importing cli.py must not run its main guard: {importer:?}"
    );
    let entry = deletes(&root, "cli.py");
    assert!(
        entry.iter().any(|(r, _)| r.contains("/cli-run")),
        "running cli.py as the entrypoint reaches its main guard: {entry:?}"
    );
}

/// Calling a method inherited from an imported base is not composed today, but
/// it must stay LOUD (an explicit boundary), never silently effect-free.
#[test]
fn inherited_constructor_from_imported_base_is_not_silent() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-inherit",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom child import Child\nChild()\n",
            ),
            (
                "child.py",
                "from base import Base\nclass Child(Base):\n    pass\n",
            ),
            (
                "base.py",
                "import shutil\nclass Base:\n    def __init__(self):\n        shutil.rmtree(\"/base-init\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app.py")
        .expect("app.py analyzed")
        .payload
        .into_effects()
        .unwrap();
    let composed = report.effects.iter().any(|e| {
        e.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&e.resource).contains("/base-init")
    });
    let loud = report.boundaries.iter().any(|b| {
        b.reason == "unresolved_call" && b.detail.as_deref().is_some_and(|d| d.contains("Child"))
    });
    assert!(
        composed || loud,
        "inherited construction must compose or stay a loud boundary: {:?}",
        report.boundaries
    );
}

#[test]
fn cross_file_decorator_requires_static_identity_evidence() {
    let exact = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-identity-decorator",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helper import wipe\nwipe('/identity')\n",
            ),
            (
                "helper.py",
                "import os\ndef identity(fn): return fn\n@identity\ndef wipe(path): os.remove(path)\n",
            ),
        ],
    );
    assert!(
        deletes(&exact, "app.py")
            .iter()
            .any(|(resource, origin)| resource.contains("/identity") && origin == "helper.py")
    );

    let decorators = [
        ("def identity(fn): return fn", "identity", true),
        (
            "import functools\ndef identity(fn):\n    @functools.wraps(fn)\n    def inner(*args, **kwargs):\n        return fn(*args, **kwargs)\n    return inner",
            "identity",
            true,
        ),
        (
            "import functools\ndef identity(attr):\n    def outer(fn):\n        @functools.wraps(fn)\n        def inner(*args, **kwargs):\n            return fn(*args, **kwargs)\n        return inner\n    return outer",
            "identity(attr='x')",
            true,
        ),
        (
            "def identity(fn): return lambda *args: None",
            "identity",
            false,
        ),
        (
            "import os\ndef identity(fn):\n    def inner(*args, **kwargs):\n        os.mkdir('/extra')\n        return fn(*args, **kwargs)\n    return inner",
            "identity",
            false,
        ),
        (
            "def identity(fn): return fn\ndef suppress(fn): return lambda *args: None",
            "identity\n@suppress",
            false,
        ),
        ("from missing import identity", "identity", false),
        (
            "import os\nif os.getenv('FIRST'):\n    from first import identity\nelse:\n    from second import identity",
            "identity",
            false,
        ),
        ("def identity(fn): return fn", "[identity][0]", false),
    ];
    for (case, (definition, decorator, transparent)) in decorators.iter().enumerate() {
        for entry_file in [true, false] {
            let body = "os.unlink('/direct'); remove('/cross'); bridge()";
            let imports = if decorator.contains("suppress") {
                "identity, suppress"
            } else {
                "identity"
            };
            let decorated = format!(
                "import os\nfrom worker import remove\nfrom wrap import {imports}\ndef bridge(): remove('/local')\n@{decorator}\ndef wipe(): {body}\n"
            );
            let entry = if entry_file {
                format!("#!/usr/bin/env python\n{decorated}\nif __name__ == '__main__': wipe()\n")
            } else {
                "#!/usr/bin/env python\nfrom helper import wipe\nif __name__ == '__main__': wipe()\n".to_string()
            };
            let root = repo_test_fixture(
                Path::new(env!("CARGO_TARGET_TMPDIR")),
                &format!("pyimp-imported-decorator-{case}-{entry_file}"),
                &[
                    ("app.py", &entry),
                    ("helper.py", &decorated),
                    ("wrap.py", definition),
                    (
                        "worker.py",
                        "import os\ndef remove(path): os.unlink(path)\n",
                    ),
                    ("first.py", "def identity(fn): return fn\n"),
                    ("second.py", "def identity(fn): return fn\n"),
                ],
            );
            let index = build_index(&root, IndexLimits::default());
            let report = effects_of(&index, "app.py")
                .unwrap_or_else(|| {
                    panic!(
                        "{case}/{entry_file}: {:?}; entries: {:?}",
                        index.skipped, index.entrypoints
                    )
                })
                .payload
                .into_effects()
                .unwrap();
            assert_eq!(
                report
                    .effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == "filesystem.delete"
                        && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")),
                *transparent,
                "{case}/{entry_file}: {:?}",
                report
            );
            assert_eq!(
                report
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason == "unresolved_decorator"),
                !transparent,
                "{case}/{entry_file}: {:?}",
                report
            );
            let decorator_boundaries: Vec<_> = report
                .boundaries
                .iter()
                .filter(|boundary| boundary.reason == "unresolved_decorator")
                .collect();
            assert_eq!(
                decorator_boundaries.len(),
                if *transparent {
                    0
                } else if decorator.contains("suppress") {
                    2
                } else {
                    1
                },
                "{case}/{entry_file}: {decorator_boundaries:?}"
            );
            if *transparent {
                for resource in ["fs:/direct", "fs:/cross", "fs:/local"] {
                    assert!(
                        report.effects.iter().any(|effect| {
                            effect.operation.as_str() == "filesystem.delete"
                                && effinterp_proto::display_resource_with_scope(&effect.resource)
                                    == resource
                                && effect.assurance.map(|assurance| assurance.as_str())
                                    == Some("exact")
                        }),
                        "{case}/{entry_file}/{resource}: {report:?}"
                    );
                }
                assert_eq!(
                    report.coverage.get("filesystem").map(|claim| claim.level),
                    Some(effinterp_proto::CoverageLevel::Partial),
                    "{case}/{entry_file}"
                );
            } else {
                assert!(
                    report
                        .boundaries
                        .iter()
                        .filter(|boundary| boundary.reason == "unresolved_decorator")
                        .all(|boundary| boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("decorator ")))
                );
            }
        }
    }

    let method = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-imported-method-decorator",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helper import Tool\nTool().wipe()\n",
            ),
            (
                "helper.py",
                "import os\nfrom wrap import identity\nclass Tool:\n    @identity\n    def wipe(self): os.unlink('/method')\n",
            ),
            ("wrap.py", "def identity(fn): return fn\n"),
        ],
    );
    let index = build_index(&method, IndexLimits::default());
    let report = effects_of(&index, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")),
        "{report:?}"
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_decorator"),
        "{report:?}"
    );

    let shared = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-shared-stacked-decorator",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport os\nfrom wrap import identity, suppress\n@identity\ndef good(): os.unlink('/good')\n@identity\n@suppress\ndef bad(): os.unlink('/bad')\ngood()\nbad()\n",
            ),
            (
                "wrap.py",
                "def identity(fn): return fn\ndef suppress(fn): return lambda *args: None\n",
            ),
        ],
    );
    let index = build_index(&shared, IndexLimits::default());
    let report = effects_of(&index, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/good")),
        "{report:?}"
    );
    assert!(
        report
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/bad")),
        "{report:?}"
    );
    let boundaries: Vec<_> = report
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason == "unresolved_decorator")
        .collect();
    assert_eq!(boundaries.len(), 2, "{boundaries:?}");
    assert!(
        boundaries.iter().all(|boundary| boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.ends_with(" on bad"))),
        "{boundaries:?}"
    );

    let replaced = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-replacing-decorator",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helper import wipe\nwipe('/replaced')\n",
            ),
            (
                "helper.py",
                "import os\ndef suppress(fn): return lambda *args: None\n@suppress\ndef wipe(path): os.remove(path)\n",
            ),
        ],
    );
    let index = build_index(&replaced, IndexLimits::default());
    let report = effects_of(&index, "app.py")
        .expect("decorated app")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().all(|effect| {
        effect.operation.as_str() != "filesystem.delete"
            || !effinterp_proto::display_resource_with_scope(&effect.resource).contains("/replaced")
    }));
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_decorator")
    );
}

#[test]
fn imported_parser_factory_dispatches_to_the_constructed_subclass() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-parser-factory",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom definition import parser\nparser.parse_args()\n",
            ),
            (
                "definition.py",
                "from parser import Parser\ndef make(parser_type=Parser):\n    concrete = parser_type()\n    return concrete\nparser = make()\n",
            ),
            (
                "parser.py",
                "import argparse, os\nclass Parser(argparse.ArgumentParser):\n    def parse_args(self):\n        os.environ.get('PARSER_USED')\n        return super().parse_args()\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "app.py")
        .expect("app.py analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "environment.read"
            && effinterp_proto::display_resource_with_scope(&effect.resource)
                .contains("PARSER_USED")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "parser.py"
    }));
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "lifecycle_unbound")
    );
}

#[test]
fn python_module_launch_runs_package_init_and_main_callable_chain() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-module-package",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"python3 -m pkg","direct":"python3 pkg/__main__.py"}}"#,
            ),
            (
                "pkg/__init__.py",
                "import os\nos.environ.get('PACKAGE_STARTED')\n",
            ),
            (
                "pkg/__main__.py",
                "from .cli import main\nif __name__ == '__main__': main()\n",
            ),
            (
                "pkg/cli.py",
                "import os\ndef main(): return _real_main()\ndef _real_main(): os.remove('/module-run')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.run" && edge.launched == "pkg/__main__.py"
    }));
    let report = effects_of(&index, "package.json:scripts.run").expect("module wrapper analyzed");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "environment.read"
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == "pkg/__init__.py"
            })
    );
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == "pkg/cli.py"
            })
    );
    let direct = effects_of(&index, "package.json:scripts.direct").expect("direct script analyzed");
    assert!(
        direct
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| {
                effect.operation.as_str() != "environment.read"
                    || effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        != "pkg/__init__.py"
            })
    );
}

#[test]
fn dotted_python_module_launch_runs_every_package_initializer() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-dotted-module-package",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"python3 -m pkg.sub"}}"#,
            ),
            (
                "pkg/__init__.py",
                "import os\nos.environ.get('OUTER_PACKAGE_STARTED')\n",
            ),
            (
                "pkg/sub/__init__.py",
                "import os\nos.environ.get('INNER_PACKAGE_STARTED')\n",
            ),
            (
                "pkg/sub/__main__.py",
                "import os\nif __name__ == '__main__': os.remove('/nested-module-run')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "package.json:scripts.run")
        .expect("dotted module wrapper analyzed")
        .payload
        .into_effects()
        .unwrap();
    for initializer in ["pkg/__init__.py", "pkg/sub/__init__.py"] {
        assert!(report.effects.iter().any(|effect| {
            effect.operation.as_str() == "environment.read"
                && effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == initializer
        }));
    }
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "pkg/sub/__main__.py"
    }));
}

#[test]
fn python_submodule_launch_runs_package_init_and_keeps_module_identity() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-submodule-launch",
        &[
            (
                "package.json",
                r#"{"scripts":{"module":"python3 -m pkg.tool","direct":"python3 pkg/tool.py"}}"#,
            ),
            (
                "pkg/__init__.py",
                "import os\nos.environ.get('PACKAGE_STARTED')\n",
            ),
            (
                "pkg/tool.py",
                "import os\nfrom helper import work\nwork()\nif __name__ == '__main__': os.remove('/tool-run')\n",
            ),
            (
                "helper.py",
                "import os\ndef work(): os.remove('/module-call')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let module = index
        .launch_edges
        .iter()
        .find(|edge| edge.wrapper == "package.json:scripts.module")
        .expect("module launch discovered");
    let direct = index
        .launch_edges
        .iter()
        .find(|edge| edge.wrapper == "package.json:scripts.direct")
        .expect("direct launch discovered");
    assert_ne!(module.launch_entrypoint, direct.launch_entrypoint);

    let module = effects_of(&index, "package.json:scripts.module")
        .expect("module wrapper analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(module.effects.iter().any(|effect| {
        effect.operation.as_str() == "environment.read"
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "pkg/__init__.py"
    }));
    assert!(module.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "helper.py"
    }));
    let direct = effects_of(&index, "package.json:scripts.direct")
        .expect("direct wrapper analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(direct.effects.iter().all(|effect| {
        effect.operation.as_str() != "environment.read"
            || effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                != "pkg/__init__.py"
    }));
}

#[test]
fn package_directory_precedes_same_named_module_file() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-package-precedence",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom choice import wipe\nwipe()\n",
            ),
            (
                "choice.py",
                "import os\ndef wipe(): os.remove('/module-file')\n",
            ),
            (
                "choice/__init__.py",
                "import os\ndef wipe(): os.remove('/package-dir')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(
        index.registry.files.contains_key("choice/__init__.py"),
        "materialized modules: {:?}",
        index.registry.files.keys().collect::<Vec<_>>()
    );
    let got = effects_of(&index, "app.py")
        .expect("entry analyzed")
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| {
            (
                effinterp_proto::display_resource_with_scope(&effect.resource),
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        got.iter()
            .any(|(resource, origin)| resource.contains("/package-dir")
                && origin == "choice/__init__.py")
    );
    assert!(
        got.iter()
            .all(|(resource, _)| !resource.contains("/module-file"))
    );
}

#[test]
fn plain_reexports_execute_import_time_effects() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-plain-reexports",
        &[
            ("app.py", "#!/usr/bin/env python\nimport pkg\n"),
            (
                "pkg/__init__.py",
                "from .module_a import function_a\nfrom .module_b import function_b\nfrom .module_c import function_c\nfrom .module_d import function_d\nfrom .module_e import function_e\n",
            ),
            (
                "pkg/module_a.py",
                "import os\nos.remove('/import-time-a')\ndef function_a(): pass\n",
            ),
            (
                "pkg/module_b.py",
                "import os\nos.remove('/import-time-b')\ndef function_b(): pass\n",
            ),
            (
                "pkg/module_c.py",
                "import os\nos.remove('/import-time-c')\ndef function_c(): pass\n",
            ),
            (
                "pkg/module_d.py",
                "import os\nos.remove('/import-time-d')\ndef function_d(): pass\n",
            ),
            (
                "pkg/module_e.py",
                "import os\nos.remove('/import-time-e')\ndef function_e(): pass\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "app.py")
        .expect("entry analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert_eq!(
        report
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.delete")
            .count(),
        5
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "dynamic_registration")
    );
}

#[test]
fn large_registration_reexport_stays_a_deterministic_boundary() {
    let mut files = vec![
        (
            "app.py".to_string(),
            "#!/usr/bin/env python\nimport registry\n".to_string(),
        ),
        ("registry.py".to_string(), String::new()),
    ];
    for provider in 0..256 {
        files[1].1.push_str(&format!(
            "from provider_{provider} import Provider{provider}\n"
        ));
        files.push((
            format!("provider_{provider}.py"),
            format!("class Provider{provider}: pass\n"),
        ));
    }
    let borrowed = files
        .iter()
        .map(|(path, content)| (path.as_str(), content.as_str()))
        .collect::<Vec<_>>();
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-registration-boundary",
        &borrowed,
    );
    let first = build_index(&root, IndexLimits::default());
    let second = build_index(&root, IndexLimits::default());
    assert!(first.registry.files.contains_key("registry.py"));
    assert!(
        first
            .registry
            .files
            .keys()
            .all(|path| !path.starts_with("provider_"))
    );
    let boundaries = |index: &effinterp_repo::RepoIndex| {
        effects_of(index, "app.py")
            .expect("entry analyzed")
            .payload
            .into_effects()
            .unwrap()
            .boundaries
            .into_iter()
            .filter(|boundary| boundary.reason == "dynamic_registration")
            .collect::<Vec<_>>()
    };
    assert_eq!(
        serde_json::to_string(&boundaries(&first)).unwrap(),
        serde_json::to_string(&boundaries(&second)).unwrap()
    );
    assert_eq!(boundaries(&first).len(), 1);
}

#[test]
fn absolute_sibling_imports_are_only_resolved_for_script_roots() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-script-roots",
        &[
            (
                "main.py",
                "#!/usr/bin/env python\nfrom pkg.console import make\nmake()\n",
            ),
            ("pkg/__init__.py", ""),
            ("pkg/logging.py", "def unrelated(): pass\n"),
            (
                "pkg/console.py",
                "import logging\ndef make(): logging.basicConfig(filename='/external.log')\n",
            ),
            (
                "scripts/tool.py",
                "import helper\nif __name__ == '__main__': helper.wipe('/sibling')\n",
            ),
            ("scripts/helper.py", WIPE_LIB),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "main.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .boundaries
            .iter()
            .any(|b| b.reason.as_str().starts_with("external_")
                && b.detail
                    .as_deref()
                    .is_some_and(|d| d.contains("logging.basicConfig"))),
        "{:?}",
        report.boundaries
    );
    assert!(report.boundaries.iter().all(|b| {
        !b.detail
            .as_deref()
            .unwrap_or("")
            .contains("not found in pkg/logging.py")
    }));
    assert!(
        effects_of(&index, "scripts/tool.py")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete")
    );
}

#[test]
fn abstractmethod_base_body_is_exact_through_super() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pyimp-abstractmethod-super",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helper import Child\nChild().run()\n",
            ),
            (
                "helper.py",
                "import os\nfrom abc import abstractmethod\nclass Base:\n    @abstractmethod\n    def run(self): os.unlink('/base')\nclass Child(Base):\n    def run(self): super().run()\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")),
        "{report:?}"
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_decorator")
    );
}
