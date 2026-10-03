//! Discovery recognizes execution roots, not "a file exists". Program-entry
//! matches inside strings/comments, test-tree files, and ordinary PHP classes
//! are not entrypoints; real mains, shell scripts, `__main__` guards, and PHP
//! bin scripts are.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{IndexLimits, build_index};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::{live, support::ids};

#[test]
fn string_and_comment_mains_are_not_entrypoints() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-strings",
        &[
            // `fn main` only inside a string literal (ripgrep's glue.rs shape).
            (
                "glue.rs",
                "pub fn run() -> String {\n    let fixture = \"fn main() { todo!() }\";\n    fixture.to_string()\n}\n",
            ),
            // `func main()` embedded in a generated-source string (_test.go also
            // lands under the test-filename rule, but the string masking alone
            // must already reject it).
            (
                "gen.go",
                "package gen\n\nconst Src = `package main\nfunc main() { println(\"x\") }`\n\nfunc Emit() string { return Src }\n",
            ),
            // Python touching __main__/__name__ only via import and an f-string.
            (
                "basic.py",
                "import __main__\n\ndef describe(x):\n    return f\"name={__name__} main={x}\"\n",
            ),
        ],
    );
    let ids = ids(&live(&root));
    assert!(!ids.contains(&"glue.rs".to_string()), "glue.rs: {ids:?}");
    assert!(!ids.contains(&"gen.go".to_string()), "gen.go: {ids:?}");
    assert!(!ids.contains(&"basic.py".to_string()), "basic.py: {ids:?}");
}

#[test]
fn go_test_file_with_string_main_is_not_an_entrypoint() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-gotest",
        &[(
            "internal/git/command_test.go",
            "package git\n\nvar generated = `package main\nfunc main() {}\n`\n\nfunc TestX() {}\n",
        )],
    );
    let ids = ids(&live(&root));
    assert!(
        !ids.contains(&"internal/git/command_test.go".to_string()),
        "command_test.go: {ids:?}"
    );
}

#[test]
fn python_under_test_tree_even_with_shebang_is_not_an_entrypoint() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-testtree",
        &[(
            "tests/data/case.py",
            "#!/usr/bin/env python3\nimport os\nif __name__ == \"__main__\":\n    os.remove(\"/tmp/x\")\n",
        )],
    );
    let ids = ids(&live(&root));
    assert!(
        !ids.contains(&"tests/data/case.py".to_string()),
        "file under tests/ is not a program: {ids:?}"
    );
}

#[test]
fn ordinary_php_class_is_not_an_entrypoint() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-phpclass",
        &[(
            "src/Foo/Status404.php",
            "<?php\nnamespace Foo;\nclass Status404 { public function code() { return 404; } }\n",
        )],
    );
    let ids = ids(&live(&root));
    assert!(
        !ids.contains(&"src/Foo/Status404.php".to_string()),
        "a plain PHP class is not a program: {ids:?}"
    );
}

#[test]
fn real_execution_roots_are_still_discovered() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-real",
        &[
            (
                "cmd/app/main.go",
                "package main\n\nimport \"os\"\n\nfunc main() { os.RemoveAll(\"/tmp/build\") }\n",
            ),
            ("run.sh", "#!/bin/sh\nrm -rf /tmp/scratch\n"),
            (
                "clean.py",
                "import shutil\nif __name__ == \"__main__\":\n    shutil.rmtree(\"/tmp/scratch\")\n",
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\nunlink(\"/tmp/y\");\n",
            ),
        ],
    );
    let ids = ids(&live(&root));
    assert!(
        ids.contains(&"cmd/app/main.go".to_string()),
        "real func main: {ids:?}"
    );
    assert!(ids.contains(&"run.sh".to_string()), "shell script: {ids:?}");
    assert!(
        ids.contains(&"clean.py".to_string()),
        "real __main__ guard: {ids:?}"
    );
    assert!(
        ids.contains(&"bin/tool".to_string()),
        "php bin shebang script: {ids:?}"
    );
}

#[test]
fn non_root_paths_and_libraries_do_not_become_execution_roots() {
    let python = "import os\nif __name__ == '__main__':\n    os.remove('/tmp/demo')\n";
    let js = "console.log('demo');\n";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-hygiene",
        &[
            ("run.py", python),
            (".tool.py", python),
            ("src/pkg/__main__.py", python),
            ("src/pkg/table.py", python),
            ("lib/run.rb", "if __FILE__ == $0\n  puts('run')\nend\n"),
            ("build/run.sh", "echo build\n"),
            ("dist/run.sh", "echo dist\n"),
            ("src/demonstration/run.py", python),
            ("src/pkg/_vendor/distro/distro.py", python),
            ("third_party/lib/tool.py", python),
            ("examples/demo.py", python),
            ("docs/contributors/generate.py", python),
            ("src/demo/run.py", python),
            ("demos/run.py", python),
            ("scripts/sync.test.mjs", js),
            ("scripts/sync.test.cjs", js),
            (
                "scripts/sync.test.ts",
                "#!/usr/bin/env node\nconsole.log('test');\n",
            ),
            ("assets/app.min.js", js),
            ("assets/render.bundle.js", js),
            ("controllers/user/index.js", "exports.x = function() {};\n"),
            ("lib/base.rb", "# __FILE__\ndef name\n  $0\nend\n"),
        ],
    );
    let mut actual = ids(&live(&root));
    actual.sort();
    assert_eq!(
        actual,
        [
            "build/run.sh",
            "dist/run.sh",
            "lib/run.rb",
            "run.py",
            "src/demonstration/run.py",
            "src/pkg/__main__.py",
            "src/pkg/table.py",
        ]
    );
}

#[test]
fn fastapi_declarations_select_handlers_and_common_initialization() {
    let source = r#"from fastapi import APIRouter as Router
import os
os.remove('/tmp/common-init')
router = Router(prefix='/local')
@router.get('/one')
def one():
    os.remove('/tmp/one')
@router.delete('/two')
def two():
    os.remove('/tmp/two')
router.add_api_route('/one', one, methods={'GET'})
@router.get(dynamic_path)
def dynamic():
    os.remove('/tmp/dynamic')
Router = unknown
fake = Router()
@fake.get('/fake')
def fake_handler():
    os.remove('/tmp/fake')
router = unknown
@router.get('/shadowed')
def shadowed():
    os.remove('/tmp/shadowed')
if __name__ == '__main__':
    os.remove('/tmp/main-only')
"#;
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-fastapi-registration",
        &[("api.py", source)],
    );
    let index = build_index(&root, IndexLimits::default());
    let entries: Vec<_> = index
        .entrypoints
        .iter()
        .filter(|entry| entry.entrypoint.registration.is_some())
        .collect();
    assert_eq!(entries.len(), 3, "{:?}", index.entrypoints);
    for entry in &entries {
        let registration = entry.entrypoint.registration.as_ref().unwrap();
        let surface = effinterp_repo::effective_surface(&index, &entry.entrypoint.id).unwrap();
        let resources: Vec<_> = surface
            .effects
            .iter()
            .map(|effect| effect.resource.as_str())
            .collect();
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains("/tmp/common-init")),
            "{resources:?}"
        );
        assert!(
            resources.iter().any(
                |resource| resource.contains(&format!("/tmp/{}", registration.primary_handler))
            ),
            "{}: {resources:?}; {:?}",
            entry.entrypoint.id,
            surface.boundaries
        );
        for sibling in ["one", "two", "dynamic", "fake", "shadowed", "main-only"] {
            if sibling != registration.primary_handler {
                assert!(
                    !resources
                        .iter()
                        .any(|resource| resource.ends_with(&format!("/tmp/{sibling}"))),
                    "{}: {resources:?}",
                    entry.entrypoint.id
                );
            }
        }
        if registration.primary_handler == "one" {
            assert_eq!(registration.spans.len(), 2);
            assert!(entry.entrypoint.id.contains(":GET:%2Flocal%2Fone:one"));
        }
        if registration.primary_handler == "dynamic" {
            assert!(
                registration
                    .unresolved
                    .iter()
                    .any(|value| value == "dynamic_registration")
            );
            assert!(
                surface
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason.as_str() == "dynamic_registration")
            );
        }
    }
    assert!(
        index
            .entrypoints
            .iter()
            .filter(|analyzed| analyzed.entrypoint.evidence.kind
                == effinterp_repo::EntrypointKind::Route)
            .all(|analyzed| analyzed.entrypoint.registration.is_some())
    );
}

#[test]
fn cobra_declarations_select_local_commands_and_own_hooks() {
    let source = r#"package commands
import (
    c "github.com/spf13/cobra"
    "os"
)
func init() { os.Remove("/tmp/common-init") }
func first(cmd *c.Command, args []string) { os.Remove("/tmp/first") }
func hook(cmd *c.Command, args []string) { os.Remove("/tmp/own-hook") }
var one = &c.Command{Use: "first [argument]", Run: first, PreRun: hook}
var two = &c.Command{Use: "second help", RunE: func(cmd *c.Command, args []string) error { return os.Remove("/tmp/second") }}
var dynamic = &c.Command{Use: dynamicName, Run: first, PreRun: chooseHook()}
func main() { os.Remove("/tmp/main-only") }
func parameterShadow(c any) { _ = &c.Command{Use: "fake", Run: first} }
func localShadow() { c := unknown; _ = &c.Command{Use: "fake", Run: first} }
type Left struct{}
type Right struct{}
func (Left) New() *c.Command { return &c.Command{Use: "shared", Run: first} }
func (Right) New() *c.Command { return &c.Command{Use: "shared", Run: first} }
func withHook(hook func(*c.Command, []string)) *c.Command { return &c.Command{Use: "parameter", Run: first, PreRun: hook} }
var unresolved = &c.Command{Use: "unresolved", Run: first, PreRun: unavailableHook}
"#;
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-cobra-registration",
        &[("commands.go", source)],
    );
    let index = build_index(&root, IndexLimits::default());
    let entries: Vec<_> = index
        .entrypoints
        .iter()
        .filter(|entry| entry.entrypoint.registration.is_some())
        .collect();
    assert_eq!(entries.len(), 7, "{:?}", index.entrypoints);
    for owner in ["Left.New", "Right.New"] {
        assert!(entries.iter().any(|entry| entry.entrypoint.id == format!("cmd:commands.go:{owner}:shared:first")));
    }
    for entry in entries {
        let registration = entry.entrypoint.registration.as_ref().unwrap();
        let surface = effinterp_repo::effective_surface(&index, &entry.entrypoint.id).unwrap();
        let resources: Vec<_> = surface
            .effects
            .iter()
            .map(|effect| effect.resource.as_str())
            .collect();
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains("/tmp/common-init")),
            "{resources:?}"
        );
        let (own, sibling) = if registration.label() == "second" {
            ("second", "first")
        } else {
            ("first", "second")
        };
        assert!(
            resources
                .iter()
                .any(|resource| resource.contains(&format!("/tmp/{own}"))),
            "{}: {resources:?}; {:?}",
            entry.entrypoint.id,
            surface.boundaries
        );
        assert!(
            !resources
                .iter()
                .any(|resource| resource.contains(&format!("/tmp/{sibling}"))),
            "{}: {resources:?}",
            entry.entrypoint.id
        );
        assert!(
            !resources
                .iter()
                .any(|resource| resource.contains("/tmp/main-only")),
            "{:#?}",
            surface.effects
        );
        assert_eq!(
            resources
                .iter()
                .any(|resource| resource.contains("/tmp/own-hook")),
            registration.label() == "first"
        );
        if registration.label() == "?" {
            assert!(
                registration
                    .unresolved
                    .iter()
                    .any(|value| value == "dynamic_hook")
            );
        }
    }
}

#[test]
fn registration_identity_and_limits() {
    let source = r#"from fastapi import APIRouter as R
import os
a = R(prefix='/α:')
b = R(prefix='/α:')
@a.get('?')
@a.get(dynamic)
@b.get('?')
def handler():
    os.remove('/tmp/identity')
"#;
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-identity",
        &[
            ("a:api.py", source),
            ("other.py", source),
            ("vendor/skipped.py", source),
            ("tests/skipped.py", source),
            (
                "generated.py",
                &format!("# Code generated automatically. DO NOT EDIT.\n{source}"),
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let ids: Vec<_> = index
        .entrypoints
        .iter()
        .map(|entry| entry.entrypoint.id.clone())
        .collect();
    assert_eq!(ids.len(), 6, "{ids:?}");
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        6
    );
    assert!(ids.contains(&"route:a%3Aapi.py:a:GET:%2F%CE%B1%3A%3F:handler".to_string()));
    assert!(ids.contains(&"route:a%3Aapi.py:a:GET:?:handler".to_string()));
    let moved = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-identity-moved",
        &[("a:api.py", source), ("other.py", source)],
    );
    assert_eq!(ids, self::ids(&live(&moved)));
    std::fs::write(
        moved.join("a:api.py"),
        format!("# unrelated comment\n{source}"),
    )
    .unwrap();
    assert_eq!(ids, self::ids(&live(&moved)));

    let mut limits = IndexLimits::default();
    limits.engine.insert("max_python_nodes".into(), 1);
    let limited = build_index(&root, limits);
    assert!(limited.entrypoints.is_empty());
    assert!(matches!(
        limited.snapshot_state,
        effinterp_proto::AnalysisStatus::Partial { .. }
    ));
    assert!(
        limited
            .skipped
            .iter()
            .any(|skip| skip.category == effinterp_repo::SkipCategory::Limit
                && skip.reason == "max_python_nodes")
    );
    let mut limits = IndexLimits::default();
    limits
        .engine
        .insert("max_analysis_bytes".into(), source.len() as u64 + 1);
    assert_eq!(
        effinterp_engine::registrations(
            source,
            effinterp_engine::Lang::Python,
            "a:api.py",
            &limits.engine
        ),
        Err("max_analysis_bytes")
    );
    let limited = build_index(&root, limits);
    assert!(
        limited
            .skipped
            .iter()
            .any(|skip| skip.reason == "max_analysis_bytes")
    );
    assert!(matches!(
        limited.snapshot_state,
        effinterp_proto::AnalysisStatus::Partial { .. }
    ));
    let mut limits = IndexLimits::default();
    limits.crawl.max_files = 1;
    let limited = build_index(&root, limits);
    assert!(
        limited
            .skipped
            .iter()
            .any(|skip| skip.category == effinterp_repo::SkipCategory::Limit)
    );
}

#[test]
fn registration_roots_follow_package_initializers_and_cross_file_handlers() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-packages",
        &[
            ("pkg/__init__.py", "import os\nos.remove('/python-init')\n"),
            (
                "pkg/api.py",
                "from fastapi import APIRouter\nfrom .worker import wipe\nrouter = APIRouter(prefix=unknown)\n@router.api_route('/local', methods=methods)\ndef handler(): wipe()\n",
            ),
            (
                "pkg/worker.py",
                "import os\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/sibling')\ndef sibling(): os.remove('/python-sibling')\ndef wipe(): os.remove('/python-handler')\n",
            ),
            (
                "cmd/command.go",
                "package cmd\nimport c \"github.com/spf13/cobra\"\nvar root = &c.Command{Use: \"local args\", Run: run}\n",
            ),
            (
                "cmd/run.go",
                "// Code generated automatically. DO NOT EDIT.\npackage cmd\nimport (\"os\"; c \"github.com/spf13/cobra\")\nfunc init() { os.Remove(\"/go-init\") }\nfunc run(cmd *c.Command, args []string) { os.Remove(\"/go-handler\") }\nvar generated = &c.Command{Use: \"generated\", Run: run}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(index.entrypoints.len(), 3);
    assert!(index.skipped.is_empty(), "{:?}", index.skipped);
    for entry in index
        .entrypoints
        .iter()
        .filter(|entry| entry.entrypoint.source_file != "pkg/worker.py")
    {
        let surface = effinterp_repo::effective_surface(&index, &entry.entrypoint.id).unwrap();
        assert!(
            surface
                .boundaries
                .iter()
                .all(|boundary| boundary.reason.as_str() != "no_entry_point"),
            "{surface:#?}"
        );
        let language = if entry.entrypoint.source_file.ends_with(".py") {
            "python"
        } else {
            "go"
        };
        assert!(
            !surface
                .effects
                .iter()
                .any(|effect| effect.resource.ends_with("/python-sibling")),
            "{surface:#?}"
        );
        for effect in ["init", "handler"] {
            assert!(
                surface
                    .effects
                    .iter()
                    .any(|item| item.resource.ends_with(&format!("/{language}-{effect}"))),
                "{}: {surface:#?}",
                entry.entrypoint.id
            );
        }
    }
}

// Symlink declarations must use snapshot paths for provenance and saved queries.
#[cfg(unix)]
#[test]
fn registration_symlinks_share_canonical_identity_and_snapshot() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-symlink",
        &[(
            "pkg/api.py",
            "from fastapi import FastAPI\nimport os\napp = FastAPI()\n@app.get('/clean')\ndef clean(): os.remove('/tmp/symlink-route')\n",
        )],
    );
    std::os::unix::fs::symlink("pkg/api.py", root.join("alias.py")).unwrap();
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(index.entrypoints.len(), 1);
    let entry = &index.entrypoints[0].entrypoint;
    assert_eq!(entry.source_file, "pkg/api.py");
    assert_eq!(entry.registration.as_ref().unwrap().file, "pkg/api.py");
    assert_eq!(entry.id, "route:pkg%2Fapi.py:app:GET:%2Fclean:clean");
    let surface = effinterp_repo::effective_surface(&index, &entry.id).unwrap();
    assert!(
        surface
            .effects
            .iter()
            .any(|effect| effect.resource.contains("/tmp/symlink-route"))
    );
}

// Long comments, literals and names are bytes, not thousands of scan steps.
#[test]
fn registration_scan_counts_work_independently_of_source_bytes() {
    let python = (0..2000)
        .map(|n| format!("def unused_{n}(): pass\n"))
        .collect::<String>();
    let go = format!("package plain\nconst text = {:?}\n", "x".repeat(90_000));
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-large",
        &[("plain.py", &python), ("plain.go", &go)],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.entrypoints.is_empty());
    assert!(index.skipped.is_empty(), "{:?}", index.skipped);
    for (source, lang) in [
        (&python, effinterp_engine::Lang::Python),
        (&go, effinterp_engine::Lang::Go),
    ] {
        let mut limits = IndexLimits::default().engine;
        limits.insert("max_analysis_steps".into(), 1);
        assert_eq!(
            effinterp_engine::registrations(source, lang, "plain", &limits),
            Err("max_analysis_steps")
        );
    }
}

#[test]
fn nested_fastapi_declarations_preserve_selected_handlers() {
    let source = "from fastapi import APIRouter as Router\nimport os\nrouter = Router()\nclass Routes:\n    @router.get('/class')\n    def clean(self): os.remove('/tmp/class-route')\nif os.environ.get('ENABLED'):\n    @router.get('/conditional')\n    async def conditional(): os.remove('/tmp/conditional-route')\n@router.get('/plain')\ndef plain(): os.remove('/tmp/plain-route')\nclass Shadowed:\n    router = unknown\n    @router.get('/fake')\n    def fake(self): os.remove('/tmp/fake-route')\nwith unknown as router:\n    @router.get('/fake-with')\n    def fake_with(): os.remove('/tmp/fake-with')\n";
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-nested",
        &[("api.py", source)],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(index.entrypoints.len(), 3, "{:?}", index.entrypoints);
    for entry in &index.entrypoints {
        let registration = entry.entrypoint.registration.as_ref().unwrap();
        let expected = match registration.primary_handler.as_str() {
            "Routes.clean" => "/tmp/class-route",
            "conditional" => "/tmp/conditional-route",
            "plain" => "/tmp/plain-route",
            other => panic!("unexpected handler {other}"),
        };
        let surface = effinterp_repo::effective_surface(&index, &entry.entrypoint.id).unwrap();
        let deletes: Vec<_> = surface
            .effects
            .iter()
            .filter(|effect| effect.operation == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1, "{}: {surface:?}", entry.entrypoint.id);
        assert!(deletes[0].resource.contains(expected), "{surface:?}");
    }
}

#[test]
fn nested_fastapi_imports_preserve_roots_without_accepting_shadowed_constructors() {
    let imports = [
        (
            "try-pass",
            "try:\n    from fastapi import APIRouter as Router\nexcept ImportError:\n    pass\n",
        ),
        (
            "try",
            "try:\n    from fastapi import APIRouter as Router\nexcept ImportError:\n    Router = None\n",
        ),
        (
            "if",
            "if True:\n    from fastapi import APIRouter as Router\n",
        ),
        (
            "with",
            "with context():\n    from fastapi import APIRouter as Router\n",
        ),
        (
            "nested",
            "if enabled:\n    try:\n        from fastapi import APIRouter as Router\n    except ImportError:\n        Router: object = None\n",
        ),
        (
            "else",
            "try:\n    import os\nexcept ImportError:\n    Router = None\nelse:\n    from fastapi import APIRouter as Router\n",
        ),
        (
            "finally",
            "try:\n    pass\nfinally:\n    from fastapi import APIRouter as Router\n",
        ),
    ];
    let routes = "import os\nrouter = Router(prefix='/local')\n@router.get('/one')\ndef one(): os.remove('/tmp/one')\n@router.delete('/two')\nasync def two(): os.remove('/tmp/two')\n";
    for (name, import) in imports {
        let source = format!("{import}{routes}");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("roots-nested-import-{name}"),
            &[("api.py", &source)],
        );
        let index = build_index(&root, IndexLimits::default());
        assert_eq!(
            index.entrypoints.len(),
            2,
            "{name}: {:?}",
            index.entrypoints
        );
        let index = &index;
        for entry in &index.entrypoints {
            let registration = entry.entrypoint.registration.as_ref().unwrap();
            let surface = effinterp_repo::effective_surface(index, &entry.entrypoint.id).unwrap();
            let deletes: Vec<_> = surface
                .effects
                .iter()
                .filter(|effect| effect.operation == "filesystem.delete")
                .collect();
            assert_eq!(deletes.len(), 1, "{name}: {surface:?}");
            assert!(
                deletes[0]
                    .resource
                    .contains(&format!("/tmp/{}", registration.primary_handler)),
                "{name}: {surface:?}"
            );
            assert!(
                matches!(&registration.kind, effinterp_engine::RegistrationKind::Route { path: Some(path), .. } if path.starts_with("/local/"))
            );
        }
    }
    let shadows = [
        "try:\n    Router = unknown\n    from fastapi import APIRouter as Router\nexcept ImportError:\n    pass\n",
        "if enabled:\n    from fastapi import APIRouter as Router\nelse:\n    Router = unknown\n",
        "try:\n    from fastapi import APIRouter as Router\nexcept ImportError:\n    Router = unknown\n",
        "try:\n    from fastapi import APIRouter as Router\nfinally:\n    Router = unknown\n",
        "try:\n    from fastapi import APIRouter as Router\nexcept ImportError:\n    Router = None\nelse:\n    Router = unknown\n",
        "with context():\n    from fastapi import APIRouter as Router\n    Router = unknown\n",
        "if enabled:\n    from fastapi import APIRouter as Router\nRouter = unknown\n",
        "if enabled:\n    from fastapi import APIRouter as Router\nelse:\n    from lookalike import APIRouter as Router\n",
        "class Local:\n    from fastapi import APIRouter as Router\n",
        "def local():\n    from fastapi import APIRouter as Router\n",
    ];
    for (case, import) in shadows.iter().enumerate() {
        let source = format!("{import}{routes}");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("roots-shadowed-import-{case}"),
            &[("api.py", &source)],
        );
        let index = build_index(&root, IndexLimits::default());
        assert!(
            index.entrypoints.is_empty(),
            "{import}: {:?}",
            index.entrypoints
        );
    }
}

#[test]
fn fastapi_member_writes_preserve_routes_and_invalidate_changed_labels() {
    for (case, mutation, dynamic) in [
        ("state", "router.state.ready = True", false),
        (
            "overrides",
            "router.dependency_overrides[object] = None",
            false,
        ),
        ("annotated", "router.state.ready: bool = True", false),
        ("augmented", "router.state.count += 1", false),
        ("deleted", "del router.state.ready", false),
        (
            "unpacked",
            "router.state.ready, router.dependency_overrides[object] = True, None",
            false,
        ),
        ("prefix", "router.prefix = unknown", true),
        ("literal-prefix", "router.prefix = '/changed'", true),
        ("annotated-prefix", "router.prefix: str = unknown", true),
        ("augmented-prefix", "router.prefix += '/changed'", true),
        ("deleted-prefix", "del router.prefix", true),
        (
            "conditional-prefix",
            "if enabled:\n    router.prefix = unknown",
            true,
        ),
        (
            "with-prefix",
            "with context():\n    router.prefix = unknown",
            true,
        ),
        (
            "try-prefix",
            "try:\n    router.prefix = unknown\nexcept Exception:\n    pass",
            true,
        ),
    ] {
        let source = format!(
            r#"from fastapi import APIRouter as Router
import os
router = Router(prefix='/local')
@router.get('/before')
def before(): os.remove('/tmp/before')
{mutation}
@router.delete(path='/after')
def after(): os.remove('/tmp/after')
class Routes:
    @router.put('/member')
    def member(self): os.remove('/tmp/member')
def direct(): os.remove('/tmp/direct')
router.get = unknown
router.add_api_route('/direct', direct, methods=['POST'])
@router.get('/fake')
def fake(): os.remove('/tmp/fake')
router = unknown
@router.delete('/shadowed')
def shadowed(): os.remove('/tmp/shadowed')
import fastapi as api
api.FastAPI = unknown
fake_app = api.FastAPI()
@fake_app.get('/constructor')
def constructor(): os.remove('/tmp/constructor')
"#
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("roots-member-write-{case}"),
            &[("api.py", &source)],
        );
        let index = build_index(&root, IndexLimits::default());
        assert_eq!(
            index.entrypoints.len(),
            4,
            "{case}: {:?}",
            index.entrypoints
        );
        for entry in &index.entrypoints {
            let registration = entry.entrypoint.registration.as_ref().unwrap();
            let handler = registration.primary_handler.rsplit('.').next().unwrap();
            let expected_dynamic = dynamic && handler != "before";
            let effinterp_engine::RegistrationKind::Route { path, .. } = &registration.kind else {
                panic!("expected route");
            };
            assert_eq!(path.is_none(), expected_dynamic, "{case}: {registration:?}");
            if let Some(path) = path {
                assert_eq!(path, &format!("/local/{handler}"));
            }
            assert_eq!(
                registration
                    .unresolved
                    .iter()
                    .any(|reason| reason == "dynamic_registration"),
                expected_dynamic
            );
            let surface = effinterp_repo::effective_surface(&index, &entry.entrypoint.id).unwrap();
            for candidate in [
                "before",
                "after",
                "member",
                "direct",
                "fake",
                "shadowed",
                "constructor",
            ] {
                assert_eq!(
                    surface.effects.iter().any(|effect| effect
                        .resource
                        .as_str()
                        .ends_with(&format!("/tmp/{candidate}"))),
                    candidate == handler,
                    "{case}: {registration:?}: {surface:?}"
                );
            }
            assert_eq!(
                surface
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason.as_str() == "dynamic_registration"),
                expected_dynamic
            );
        }
    }
}

#[test]
fn registration_filename_collisions_report_failure_in_either_crawl_order() {
    let source = "from fastapi import FastAPI\nimport os\napp = FastAPI()\nclass Cls:\n    @app.get('/a')\n    @app.get('/a')\n    def sh(self): os.remove('/tmp/route')\n";
    for file in ["a.py", "x.py"] {
        let id = format!("route:{file}:app:GET:%2Fa:Cls.sh");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("roots-registration-collision-{file}"),
            &[(file, source), (&id, "rm /tmp/shell\n")],
        );
        let index = build_index(&root, IndexLimits::default());
        assert_eq!(index.entrypoints.len(), 1);
        assert!(index.entrypoints[0].entrypoint.registration.is_none());
        assert!(index.skipped.iter().any(|skip| {
            skip.path == file
                && skip.category == effinterp_repo::SkipCategory::Failure
                && skip.reason == "registration_id_collision"
        }));
        assert!(matches!(
            index.snapshot_state,
            effinterp_proto::AnalysisStatus::Partial { .. }
        ));
        let surface = effinterp_repo::effective_surface(&index, &id).unwrap();
        assert!(
            surface
                .effects
                .iter()
                .any(|effect| effect.resource.ends_with("/tmp/shell"))
        );
        assert!(
            !surface
                .effects
                .iter()
                .any(|effect| effect.resource.ends_with("/tmp/route"))
        );
    }
}

#[test]
fn script_launch_does_not_reuse_a_selected_registration() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-registration-launch",
        &[
            ("package.json", r#"{"scripts":{"start":"python api.py"}}"#),
            (
                "api.py",
                "from fastapi import FastAPI\nimport os\napp = FastAPI()\n@app.get('/one')\ndef one(): os.remove('/tmp/one')\n@app.get('/two')\ndef two(): os.remove('/tmp/two')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let launched = index
        .entrypoints
        .iter()
        .find(|entry| {
            entry.entrypoint.source_file == "api.py" && entry.entrypoint.registration.is_none()
        })
        .expect("a script launch needs a whole-file root");
    let surface = effinterp_repo::effective_surface(&index, &launched.entrypoint.id).unwrap();
    for sink in ["/tmp/one", "/tmp/two"] {
        assert!(
            surface
                .effects
                .iter()
                .any(|effect| effect.resource.ends_with(sink)),
            "{surface:#?}"
        );
    }
}

#[test]
fn ruby_declarations_are_reached_only_through_a_requiring_root() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-ruby-declarations",
        &[
            ("run.rb", "require_relative 'consts'\nputs 'run'\n"),
            ("consts.rb", "X = File.delete('/require-time')\n"),
            (
                "ext/patch.rb",
                "App::Cleaner.singleton_class.prepend(Faster)\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(
        index
            .entrypoints
            .iter()
            .map(|entry| entry.entrypoint.id.as_str())
            .collect::<Vec<_>>(),
        ["run.rb"]
    );
    let report = effinterp_repo::effects_of(&index, "run.rb")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effect
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.source_file == "consts.rb")),
        "{report:?}"
    );
}

#[test]
fn python_fire_and_raise_execution_roots() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "roots-python-fire-raise",
        &[
            (
                "fire.py",
                "import fire\ndef main(): pass\nfire.Fire(main)\n",
            ),
            (
                "bare.py",
                "from fire import Fire as run\ndef main(): pass\nrun()\n",
            ),
            (
                "raise.py",
                "def main(): pass\nif __name__ == '__main__':\n    raise SystemExit(main())\n",
            ),
            ("library.py", "import fire\ndef main():\n    fire.Fire()\n"),
        ],
    );
    let found = ids(&live(&root));
    for file in ["fire.py", "bare.py", "raise.py"] {
        assert!(found.contains(&file.to_string()), "{found:?}");
    }
    assert!(!found.contains(&"library.py".to_string()));
}
