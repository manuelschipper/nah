//! Src-layout ownership, dotted absolute imports, and package re-exports.
//!
//! These are the first broken edges of an empty Python product surface: a
//! console-script / `__main__` import of `pkg.mod:func` when `src/pkg` has no
//! `__init__.py`, a written `import pkg.sub.mod; pkg.sub.mod.fn()` call, and a
//! package `__init__` re-export. Fixtures are synthetic — no product names.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::deletes;

fn env_reads(root: &Path, entry: &str) -> Vec<(String, String)> {
    let idx = build_index(root, IndexLimits::default());
    let report = effects_of(&idx, entry).expect("entry analyzed");
    report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|e| e.operation.as_str() == "environment.read")
        .map(|e| {
            (
                effinterp_proto::display_resource_with_scope(&e.resource),
                e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .clone(),
            )
        })
        .collect()
}

const LOCATIONS: &str = "import os\n\nCONFIG = os.getenv(\"APP_CONFIG_DIR\")\n";
const WIPE: &str = "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n";

/// Console-script `pkg.console.application:main` under a `src/` layout with
/// no `src/pkg/__init__.py`. The entry file's `from pkg.locations import _`
/// must execute locations' import-time env read.
#[test]
fn src_layout_console_script_resolves_without_init() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-console",
        &[
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\n\n[project.scripts]\napp = \"pkg.console.application:main\"\n",
            ),
            (
                "src/pkg/console/application.py",
                "from pkg.locations import CONFIG\n\ndef main():\n    return CONFIG\n",
            ),
            ("src/pkg/locations.py", LOCATIONS),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(
        idx.entrypoints
            .iter()
            .any(|e| e.entrypoint.id == "src/pkg/console/application.py"),
        "console-script spec maps to the src-layout file: {:?}",
        idx.entrypoints
            .iter()
            .map(|e| &e.entrypoint.id)
            .collect::<Vec<_>>()
    );
    let got = env_reads(&root, "src/pkg/console/application.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("APP_CONFIG_DIR") && o == "src/pkg/locations.py"),
        "import-time env read composes from locations: {got:?}"
    );
}

/// `__main__.py` under the same layout: a main-guard
/// `from pkg.console.application import main; main()` must resolve and run
/// the imported module's top level.
#[test]
fn src_layout_main_guard_dotted_import_resolves() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-main",
        &[
            (
                "src/pkg/__main__.py",
                "#!/usr/bin/env python\nif __name__ == \"__main__\":\n    from pkg.console.application import main\n    main()\n",
            ),
            (
                "src/pkg/console/application.py",
                "from pkg.locations import CONFIG\n\ndef main():\n    return CONFIG\n",
            ),
            ("src/pkg/locations.py", LOCATIONS),
        ],
    );
    let got = env_reads(&root, "src/pkg/__main__.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("APP_CONFIG_DIR") && o == "src/pkg/locations.py"),
        "scoped dotted import of application.main runs locations: {got:?}"
    );
}

/// `import pkg.sub.mod; pkg.sub.mod.wipe(...)` — the written callee keeps the
/// full dotted path; composition strips the imported module prefix.
#[test]
fn dotted_absolute_import_composes_under_src_layout() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-dotted",
        &[
            (
                "src/pkg/__main__.py",
                "#!/usr/bin/env python\nimport pkg.sub.mod\npkg.sub.mod.wipe(\"/cache\")\n",
            ),
            ("src/pkg/sub/mod.py", WIPE),
        ],
    );
    let got = deletes(&root, "src/pkg/__main__.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/cache") && o == "src/pkg/sub/mod.py"),
        "dotted absolute import composes the wipe: {got:?}"
    );
}

/// `from pkg import sub; sub.wipe(...)` when `pkg` has no `__init__.py`
/// (a PEP 420 namespace package under `src/`).
#[test]
fn from_namespace_package_import_submodule() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-ns-sub",
        &[
            (
                "src/pkg/__main__.py",
                "#!/usr/bin/env python\nfrom pkg import sub\nsub.wipe(\"/ns\")\n",
            ),
            ("src/pkg/sub.py", WIPE),
        ],
    );
    let got = deletes(&root, "src/pkg/__main__.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/ns") && o == "src/pkg/sub.py"),
        "namespace-package submodule member composes: {got:?}"
    );
}

/// `import pkg; pkg.sub.wipe(...)` when `pkg` itself has no file.
#[test]
fn import_namespace_then_dotted_submodule() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-ns-dot",
        &[
            (
                "src/pkg/__main__.py",
                "#!/usr/bin/env python\nimport pkg\npkg.sub.wipe(\"/nsdot\")\n",
            ),
            ("src/pkg/sub.py", WIPE),
        ],
    );
    let got = deletes(&root, "src/pkg/__main__.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/nsdot") && o == "src/pkg/sub.py"),
        "import of a namespace package still reaches a submodule call: {got:?}"
    );
}

/// `src/pkg/__init__.py` re-exports `wipe` from a sibling module.
#[test]
fn src_layout_init_reexport_composes() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-reexport",
        &[
            (
                "src/app/main.py",
                "#!/usr/bin/env python\nfrom pkg import wipe\nwipe(\"/reexp\")\n",
            ),
            ("src/pkg/__init__.py", "from .impl import wipe\n"),
            ("src/pkg/impl.py", WIPE),
        ],
    );
    let got = deletes(&root, "src/app/main.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/reexp") && o == "src/pkg/impl.py"),
        "src-layout re-export composes from the defining file: {got:?}"
    );
}

/// `App().run()` is a typed dispatch edge: the constructor-chained method
/// reaches `run`'s body.
#[test]
fn constructor_chained_run_composes() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-ctor-run",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"pkg.console.application:main\"\n",
            ),
            (
                "src/pkg/console/application.py",
                "import os\nclass Application:\n    def run(self):\n        os.getenv(\"APP_HOME\")\ndef main():\n    Application().run()\n",
            ),
        ],
    );
    let got = env_reads(&root, "src/pkg/console/application.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("APP_HOME") && o == "src/pkg/console/application.py"),
        "Application().run() reaches run's env read: {got:?}"
    );
}

/// `__main__` imports a dotted callable and the callee binds
/// `code: int = App().run()` on a typed Cleo application — an annotated
/// assignment of a constructor-chained dispatch whose local hook is `_run`.
#[test]
fn annotated_ctor_run_from_main_guard_import() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pysrc-ann-run",
        &[
            (
                "src/pkg/__main__.py",
                "from __future__ import annotations\nimport sys\nif __name__ == \"__main__\":\n    from pkg.console.application import main\n    sys.exit(main())\n",
            ),
            (
                "src/pkg/console/application.py",
                "import os\nfrom cleo.application import Application as BaseApplication\nclass Application(BaseApplication):\n    def _run(self):\n        os.getenv(\"APP_HOME\")\ndef main() -> int:\n    code: int = Application().run()\n    return code\n",
            ),
        ],
    );
    let got = env_reads(&root, "src/pkg/__main__.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("APP_HOME") && o == "src/pkg/console/application.py"),
        "annotated App().run() from imported main reaches _run: {got:?}"
    );
}
