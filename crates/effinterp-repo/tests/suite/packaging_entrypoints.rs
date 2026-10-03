//! Entrypoints declared in packaging metadata: package.json `bin` programs
//! mapped back to their TypeScript sources, and Python console scripts from
//! pyproject/setup.cfg entry points — plus the composition mechanics they
//! exercise (entry functions, import-time module effects, local-sibling call
//! chains).
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::ids;

#[test]
fn bin_target_missing_maps_through_tsconfig_to_source() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "bin-tsconfig",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./build/cli.js"}}"#,
            ),
            (
                "tsconfig.json",
                r#"{"compilerOptions": {"rootDir": "./src", "outDir": "./build"}}"#,
            ),
            (
                "src/cli.ts",
                "import process from 'node:process'\nconst token = process.env.APP_TOKEN\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(ids.contains(&"src/cli.ts".to_string()), "{ids:?}");
    let entry = idx
        .entrypoints
        .iter()
        .find(|entry| entry.entrypoint.id == "src/cli.ts")
        .unwrap();
    assert_eq!(entry.entrypoint.source_file, "src/cli.ts");
    assert_eq!(entry.entrypoint.evidence.file, "package.json");
    let report = effects_of(&idx, "src/cli.ts").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"),
        "the mapped source's env read surfaces: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn node_shebang_typescript_uses_the_typescript_frontend() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "node-shebang-ts",
        &[(
            "src/cli.ts",
            "#!/usr/bin/env node\nimport process from 'node:process'\nresolveDefaults(process.env)\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "src/cli.ts").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "environment.read"),
        "the TypeScript entrypoint keeps its whole-environment read: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn bin_wrapper_with_missing_built_import_maps_by_unique_stem() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "bin-wrapper",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"foo": "bin/foo.mjs"}}"#,
            ),
            (
                "bin/foo.mjs",
                "#!/usr/bin/env node\nimport '../dist/foo.mjs'\n",
            ),
            (
                "src/commands/foo.ts",
                "import process from 'node:process'\nconst v = process.env.FOO_MODE\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(
        ids.contains(&"src/commands/foo.ts".to_string()),
        "the wrapper's missing built import maps to the unique source: {ids:?}"
    );
    // The wrapper's surface unions the launched source's effects.
    let wrapper = effects_of(&idx, "bin/foo.mjs").unwrap();
    assert!(
        wrapper
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"),
        "launch edge unions the source surface into the wrapper: {:?}",
        wrapper.payload.as_effects().unwrap().effects
    );
}

#[test]
fn committed_built_bin_maps_back_to_source() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "bin-committed-build",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": "./dist/tool.js"}"#,
            ),
            ("dist/tool.js", "#!/usr/bin/env node\nrun()\n"),
            (
                "src/tool.ts",
                "import process from 'node:process'\nconst v = process.env.TOOL_HOME\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(
        ids.contains(&"src/tool.ts".to_string()),
        "a committed built artifact maps to its source: {ids:?}"
    );
}

#[test]
fn pyproject_project_scripts_register_console_entrypoint() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-scripts-table",
        &[
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\n\n[project.scripts]\napp = \"app.cli:main\"\n",
            ),
            ("src/app/__init__.py", ""),
            (
                "src/app/cli.py",
                "import os\n\ndef main():\n    os.getenv(\"APP_DEBUG\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(ids.contains(&"src/app/cli.py".to_string()), "{ids:?}");
    // The plan never calls main(); the console-script entry function does.
    let report = effects_of(&idx, "src/app/cli.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("APP_DEBUG")),
        "the entry function's effects surface: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn console_script_reaches_awaitable_instance_network_effect() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-script-awaitable-instance",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"app.cli:main\"\n",
            ),
            ("app/__init__.py", ""),
            (
                "app/cli.py",
                "import asyncio\nfrom .client import connect\nasync def interactive(uri):\n    await connect(uri)\ndef main():\n    asyncio.run(interactive('example.com'))\n",
            ),
            (
                "app/client.py",
                "import asyncio\nclass connect:\n    def __init__(self, uri): self.uri = uri\n    def __await__(self): return self.__await_impl__().__await__()\n    async def __await_impl__(self): await self.open_tcp_connection()\n    async def open_tcp_connection(self):\n        loop = asyncio.get_running_loop()\n        await loop.create_connection(factory)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app/cli.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "network.request"),
        "the console entry reaches the awaitable's TCP connection: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn unpolled_async_call_does_not_surface_its_effect() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-script-unpolled-async",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"app.cli:main\"\n",
            ),
            ("app/__init__.py", ""),
            (
                "app/cli.py",
                "from .client import open_connection\ndef main():\n    open_connection()\n",
            ),
            (
                "app/client.py",
                "import asyncio\nasync def open_connection():\n    loop = asyncio.get_running_loop()\n    await loop.create_connection(factory)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app/cli.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "network.request"),
        "constructing an unpolled coroutine is effectless: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn console_script_reaches_calls_consumed_by_standard_async_pollers() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-script-standard-async-pollers",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"app.cli:main\"\n",
            ),
            ("app/__init__.py", ""),
            (
                "app/cli.py",
                "import asyncio\nfrom asyncio import run_coroutine_threadsafe\nfrom .client import read\nasync def schedule():\n    await asyncio.create_task(read('/created'))\n    await asyncio.ensure_future(read('/ensured'))\n    task = read('/bound')\n    await task\n    tasks = [read('/stored-a'), read('/stored-b')]\n    for task in tasks:\n        await task\n    batched = [read('/batched-a'), read('/batched-b')]\n    await asyncio.gather(*batched)\n    async with asyncio.TaskGroup() as group:\n        group.create_task(read('/grouped'))\ndef main():\n    loop = asyncio.new_event_loop()\n    loop.run_until_complete(read('/loop'))\n    loop.create_task(read('/loop-created'))\n    run_coroutine_threadsafe(read('/threadsafe'), loop)\n    loop.run_until_complete(schedule())\n",
            ),
            (
                "app/client.py",
                "async def read(path):\n    open(path).read()\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app/cli.py").unwrap();
    let resources: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.read")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    for path in [
        "/created",
        "/ensured",
        "/bound",
        "/stored-a",
        "/stored-b",
        "/batched-a",
        "/batched-b",
        "/grouped",
        "/loop",
        "/loop-created",
        "/threadsafe",
    ] {
        assert!(
            resources.iter().any(|resource| resource.contains(path)),
            "{path} is reached through its exact poller: {resources:?}"
        );
    }
}

#[test]
fn lookalike_async_pollers_do_not_consume_coroutines() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-script-lookalike-async-pollers",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"app.cli:main\"\n",
            ),
            ("app/__init__.py", ""),
            (
                "app/cli.py",
                "from .client import read\nclass Pool:\n    def run_until_complete(self, future):\n        pass\n    def create_task(self, future):\n        pass\ndef run_coroutine_threadsafe(future, loop):\n    pass\ndef main():\n    pool = Pool()\n    pool.run_until_complete(read('/wrong-loop'))\n    pool.create_task(read('/wrong-task'))\n    run_coroutine_threadsafe(read('/wrong-threadsafe'), pool)\n    tasks = [read('/stored')]\n    for task in tasks:\n        consume(task)\n    for task in (read('/tuple-a'), read('/tuple-b')):\n        pass\n",
            ),
            (
                "app/client.py",
                "async def read(path):\n    open(path).read()\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app/cli.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "filesystem.read"),
        "method names without receiver identity do not poll: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn pyproject_dotted_scripts_key_registers_console_entrypoint() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-scripts-dotted",
        &[
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\nscripts.app = \"app.main:cli\"\n",
            ),
            ("app/__init__.py", ""),
            (
                "app/main.py",
                "import os\n\ndef cli():\n    os.getenv(\"APP_HOME\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(ids(&idx).contains(&"app/main.py".to_string()));
    let report = effects_of(&idx, "app/main.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("APP_HOME")),
        "{:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn setup_cfg_console_scripts_register_console_entrypoint() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-setup-cfg",
        &[
            (
                "setup.cfg",
                "[options.entry_points]\nconsole_scripts =\n    tool = tool.run:main\n",
            ),
            ("tool/__init__.py", ""),
            (
                "tool/run.py",
                "import os\n\ndef main():\n    os.getenv(\"TOOL_ENV\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(ids(&idx).contains(&"tool/run.py".to_string()));
}

#[test]
fn console_script_attaches_entry_function_to_existing_main() {
    // A file with a `__main__` guard is already an entrypoint; the packaging
    // spec still names the callable the generated wrapper invokes.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-script-on-main",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"pkg.mod:main\"\n",
            ),
            (
                "pkg/mod.py",
                "import os\ndef main():\n    os.getenv(\"APP_HOME\")\nif __name__ == \"__main__\":\n    main()\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let entry = idx
        .entrypoints
        .iter()
        .find(|e| e.entrypoint.id == "pkg/mod.py")
        .expect("main-guard file is an entrypoint");
    assert_eq!(
        entry.entrypoint.entry_function.as_deref(),
        Some("main"),
        "console-script callable attaches to the existing entry: {:?}",
        entry.entrypoint.entry_function
    );
}

#[test]
fn console_script_keeps_evidence_for_its_entry_function() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-script-evidence-pair",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = \"pkg.mod:main\"\nappdev = \"pkg.mod:other\"\n",
            ),
            (
                "pkg/mod.py",
                "def main():\n    pass\ndef other():\n    pass\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let entry = index
        .entrypoints
        .iter()
        .find(|entry| entry.entrypoint.id == "pkg/mod.py")
        .unwrap();
    assert_eq!(entry.entrypoint.entry_function.as_deref(), Some("main"));
    assert_eq!(entry.entrypoint.evidence.file, "pyproject.toml");
    assert_eq!(entry.entrypoint.evidence.line, Some(2));
}

#[test]
fn poetry_scripts_register_console_entrypoint() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-poetry",
        &[
            (
                "pyproject.toml",
                "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.scripts]\napp = \"app:main\"\n",
            ),
            (
                "app.py",
                "import os\n\ndef main():\n    os.getenv(\"POETRY_APP\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(ids(&idx).contains(&"app.py".to_string()));
}

#[test]
fn imported_module_top_level_effects_surface() {
    // `os.environ.get` at an imported module's top level runs at import time
    // (websockets: WEBSOCKETS_USER_AGENT in http11.py).
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-import-time-env",
        &[
            ("pyproject.toml", "[project.scripts]\napp = \"cli:main\"\n"),
            ("cli.py", "import settings\n\ndef main():\n    pass\n"),
            (
                "settings.py",
                "import os\n\nUA = os.environ.get(\"APP_USER_AGENT\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "cli.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("APP_USER_AGENT")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "settings.py"),
        "import-time module effect surfaces with its origin: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn local_sibling_call_chain_composes_cross_file() {
    // Entry -> imported run() -> same-file main() -> cross-file helper: the
    // local sibling's cross-file edges must be walked (tox: __main__.py ->
    // run.py:run -> main -> get_options in another file).
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-local-sibling",
        &[
            (
                "main.py",
                "from runner import run\n\nif __name__ == \"__main__\":\n    run()\n",
            ),
            (
                "runner.py",
                "from helper import work\n\ndef run():\n    inner()\n\ndef inner():\n    work()\n",
            ),
            (
                "helper.py",
                "import os\n\ndef work():\n    os.getenv(\"SIBLING_VAR\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "main.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("SIBLING_VAR")),
        "{:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn classmethod_cls_constructor_composes() {
    // `cls(...)` inside a classmethod is not inlined by the frontend, so the
    // composed walk must collect the constructor chain's effects (tox:
    // ToxParser.base() -> cls() -> __init__ -> add_color_flags).
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-cls-ctor",
        &[
            (
                "app.py",
                "from parser import Parser\n\nif __name__ == \"__main__\":\n    Parser.base()\n",
            ),
            (
                "parser.py",
                "import os\n\nclass Parser:\n    def __init__(self):\n        setup(self)\n\n    @classmethod\n    def base(cls):\n        return cls()\n\ndef setup(p):\n    os.getenv(\"PARSER_COLOR\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("PARSER_COLOR")),
        "{:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn module_level_singleton_method_composes() {
    // `MANAGER = Plugin()` at module level, imported and called elsewhere
    // (tox: MANAGER.load_plugins).
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-singleton",
        &[
            (
                "app.py",
                "from manager import MANAGER\n\nif __name__ == \"__main__\":\n    MANAGER.load()\n",
            ),
            (
                "manager.py",
                "import os\n\nclass Plugin:\n    def __init__(self):\n        pass\n\n    def load(self):\n        os.environ.get(\"PLUGINS_DISABLED\")\n\nMANAGER = Plugin()\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("PLUGINS_DISABLED")),
        "{:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn declared_python_layout_roots_resolve_console_scripts_and_module_launches() {
    let layouts = [
        (
            "pyproject.toml",
            "[tool.setuptools.packages.find]\nwhere = [\"lib\", \"test/lib\"]\n",
        ),
        (
            "pyproject.toml",
            "[tool.setuptools]\npackage-dir = { \"\" = \"lib\" }\n",
        ),
        (
            "pyproject.toml",
            "[tool.setuptools.package-dir]\n\"\" = \"lib\"\n",
        ),
        (
            "pyproject.toml",
            "[tool.poetry]\npackages = [{ include = \"ansible\", from = \"lib\" }]\n",
        ),
        (
            "pyproject.toml",
            "[tool.setuptools.packages.find]\nwhere = [\n  \"lib\", # layout\n  \"test/lib\",\n]\n",
        ),
        (
            "pyproject.toml",
            "[tool.poetry]\npackages = [\n  { include = \"ansible\", from = \"lib\" },\n]\n",
        ),
        ("setup.cfg", "[options.packages.find]\nwhere = lib\n"),
        ("setup.cfg", "[options]\npackage_dir = =lib\n"),
        ("setup.cfg", "[options]\npackage_dir =\n    =lib\n"),
    ];
    for (case, (manifest, layout)) in layouts.iter().enumerate() {
        let scripts = if *manifest == "pyproject.toml" {
            "[project.scripts]\nansible = \"ansible.cli.adhoc:main\"\n"
        } else {
            "[options.entry_points]\nconsole_scripts =\n    ansible = ansible.cli.adhoc:main\n"
        };
        let metadata = format!("{scripts}{layout}");
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("python-declared-layout-{case}"),
            &[
                (manifest, &metadata),
                ("lib/ansible/__init__.py", ""),
                ("lib/ansible/cli/__init__.py", ""),
                (
                    "lib/ansible/cli/adhoc.py",
                    "import os\ndef main(): os.unlink('/declared-root')\nif __name__ == '__main__': main()\n",
                ),
                (
                    "package.json",
                    r#"{"scripts":{"run":"python -m ansible.cli.adhoc"}}"#,
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let entries = index
            .entrypoints
            .iter()
            .filter(|e| e.entrypoint.id == "lib/ansible/cli/adhoc.py")
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "{metadata}");
        assert_eq!(
            entries[0].entrypoint.evidence.kind,
            effinterp_repo::EntrypointKind::ConsoleScript
        );
        assert_eq!(
            entries[0].entrypoint.entry_function.as_deref(),
            Some("main")
        );
        assert!(!index.skipped.iter().any(|s| s.path == *manifest && s.category == effinterp_repo::SkipCategory::Failure));
        assert!(
            index
                .launch_edges
                .iter()
                .any(|edge| edge.wrapper == "package.json:scripts.run"
                    && edge.launched == "lib/ansible/cli/adhoc.py")
        );
        for entry in ["lib/ansible/cli/adhoc.py", "package.json:scripts.run"] {
            assert!(
                effects_of(&index, entry)
                    .unwrap()
                    .payload
                    .as_effects()
                    .unwrap()
                    .effects
                    .iter()
                    .any(|e| e.operation.as_str() == "filesystem.delete")
            );
        }
    }
}

#[test]
fn python_layout_roots_preserve_conventional_and_declared_order() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "python-layout-order",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\napp = 'pkg.cli:main'\n[tool.setuptools.packages.find]\nwhere = ['lib', 'other']\n",
            ),
            ("package.json", r#"{"scripts":{"run":"python -m pkg.cli"}}"#),
            ("src/pkg/cli.py", "def main(): pass\n"),
            ("lib/pkg/cli.py", "def main(): pass\n"),
            ("other/pkg/cli.py", "def main(): pass\n"),
        ],
    );
    for expected in ["src/pkg/cli.py", "lib/pkg/cli.py", "other/pkg/cli.py"] {
        let index = build_index(&root, IndexLimits::default());
        assert!(
            index
                .entrypoints
                .iter()
                .any(|entry| entry.entrypoint.id == expected
                    && entry.entrypoint.evidence.kind
                        == effinterp_repo::EntrypointKind::ConsoleScript)
        );
        assert!(
            index
                .launch_edges
                .iter()
                .any(|edge| edge.wrapper == "package.json:scripts.run" && edge.launched == expected)
        );
        std::fs::remove_file(root.join(expected)).unwrap();
    }
}
