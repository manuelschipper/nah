//! Non-shebang Python/JS script files are discovered as entrypoints, while
//! pure-library files are not.
#![allow(clippy::disallowed_methods)]

use effinterp_proto::Subject;
use effinterp_repo::{
    IndexLimits, RepoChange, Selector, apply_changes, build_index, effects_of, normalize_surface,
    reach,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn ids(idx: &effinterp_repo::RepoIndex) -> Vec<String> {
    idx.entrypoints
        .iter()
        .map(|e| e.entrypoint.id.clone())
        .collect()
}

fn display(effect: &effinterp_proto::EffectFact) -> String {
    effinterp_proto::display_resource(&effect.resource)
}

fn origin(effect: &effinterp_proto::EffectFact) -> &str {
    effect
        .origin
        .as_ref()
        .map(|origin| origin.source_file.as_str())
        .unwrap_or("")
}

#[test]
fn python_main_guard_is_an_entrypoint_library_is_not() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "py-main-guard",
        &[
            (
                "app.py",
                "import os\nif __name__ == \"__main__\":\n    os.remove(\"/tmp/x\")\n",
            ),
            ("lib.py", "def helper():\n    return 1\n"),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(ids.contains(&"app.py".to_string()), "app.py: {ids:?}");
    assert!(
        !ids.contains(&"lib.py".to_string()),
        "pure-library lib.py is not an entrypoint"
    );

    let report = reach(&idx, &Selector::parse("fs:/tmp/x").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "app.py" && h.fact.operation.0 == "filesystem.delete"),
        "the __main__ delete is queryable"
    );
}

#[test]
fn js_script_is_an_entrypoint_module_is_not() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-script",
        &[
            (
                "run.js",
                "const fs = require('fs');\nfs.rmSync('/tmp/y');\n",
            ),
            (
                "lib.js",
                "function helper() { return 1; }\nmodule.exports = { helper };\n",
            ),
            ("mod.mjs", "export function f() {}\n"),
            (
                "exports.js",
                "exports.list = function() {};\nconsole.log('loaded');\n",
            ),
            ("exports-call.js", "exports.list();\n"),
            ("computed.js", "const name = 'execute'\nbash[name]()\n"),
            (
                "computed-multiline.js",
                "const name =\n 'execute'\nbash[name]()\n",
            ),
            (
                "multiline-import.js",
                "const fs =\nrequire('fs');\nexports.wipe = function () { fs.rmSync('/uncalled'); };\n",
            ),
            (
                "inert-initializer.js",
                "module.exports = console.log('loaded');\n",
            ),
            (
                "default-initializer.mjs",
                "export default console.log('loaded');\n",
            ),
            (
                "async-library.js",
                "async function wipe() { require('fs').rmSync('/uncalled'); }\n",
            ),
            (
                "multiline-library.js",
                "function\nwipe()\n{\nrequire('fs').rmSync('/uncalled');\n}\n",
            ),
            (
                "arrow-library.cjs",
                "const fs = require('fs');\nconst remove = (p) =>\n  fs.unlinkSync(p);\nmodule.exports = { remove };\n",
            ),
            (
                "arrow-library.mjs",
                "import fs from 'fs';\nexport const del = (p) =>\n  fs.unlinkSync(p);\nexport const keep = 1;\n",
            ),
            (
                "arrow-network.js",
                "const https = require('https');\nconst load = (u) =>\n  https.get(u);\nmodule.exports = { load };\n",
            ),
            (
                "arrow-parenthesized.js",
                "const remove = (p) => (\n  require('fs').unlinkSync(p)\n);\nmodule.exports = { remove };\n",
            ),
            (
                "arrow-conditional.js",
                "const remove = (p) => p ?\n  require('fs').unlinkSync(p) :\n  console.log('ignored');\nmodule.exports = { remove };\n",
            ),
            (
                "arrow-async.js",
                "export const remove = async (p) =>\n  await require('fs').promises.unlink(p);\n",
            ),
            (
                "arrow-inert.js",
                "export const log = () =>\n  console.log('uncalled')\n",
            ),
            (
                "arrow-mixed.js",
                "const remove = (p) =>\n  require('fs').unlinkSync(p);\nmodule.exports = { remove };\nrequire('fs').unlinkSync('/arrow-mixed');\n",
            ),
            (
                "arrow-inert-mixed.js",
                "export const log = () => (\n  console.log('uncalled')\n)\nconsole.log('loaded');\n",
            ),
            (
                "iife-arrow.js",
                "const fs = require('fs');\n(async () => {\n  fs.unlinkSync('/iife-arrow');\n})();\n",
            ),
            (
                "iife-function.js",
                "const fs = require('fs');\n(function () {\n  fs.unlinkSync('/iife-function');\n})();\n",
            ),
            ("inert-comparison.js", "console.log(1 === 1);\n"),
            (
                "assigned-body.js",
                "module.exports = function (p) {\n  require('fs').rmSync('/uncalled');\n};\n",
            ),
            (
                "controller.js",
                "function wipe() { require('fs').rmSync('/uncalled'); }\nexports.wipe = wipe;\n",
            ),
            (
                "declaration.js",
                "function wipe() {\nrequire('fs').rmSync('/uncalled');\n}\n",
            ),
            (
                "initializer.js",
                "exports.result =\n    require('fs').rmSync('/initializer');\n",
            ),
            (
                "mixed.mjs",
                "import fs from 'fs';\nexport function wipe() { fs.rmSync('/uncalled'); }\n    fs.rmSync(\n      '/mixed'\n    );\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(ids.contains(&"exports.js".to_string()));
    assert!(ids.contains(&"exports-call.js".to_string()));
    assert!(ids.contains(&"computed.js".to_string()));
    assert!(ids.contains(&"computed-multiline.js".to_string()));
    assert!(ids.contains(&"inert-initializer.js".to_string()));
    assert!(ids.contains(&"default-initializer.mjs".to_string()));
    assert!(ids.contains(&"inert-comparison.js".to_string()), "{ids:?}");
    for library in [
        "controller.js",
        "declaration.js",
        "async-library.js",
        "multiline-library.js",
        "multiline-import.js",
        "arrow-library.cjs",
        "arrow-library.mjs",
        "arrow-network.js",
        "arrow-parenthesized.js",
        "arrow-conditional.js",
        "arrow-async.js",
        "arrow-inert.js",
        "assigned-body.js",
    ] {
        assert!(!ids.contains(&library.to_string()), "{ids:?}");
    }
    assert!(ids.contains(&"arrow-inert-mixed.js".to_string()));
    for (file, path) in [
        ("initializer.js", "/initializer"),
        ("mixed.mjs", "/mixed"),
        ("arrow-mixed.js", "/arrow-mixed"),
        ("iife-arrow.js", "/iife-arrow"),
        ("iife-function.js", "/iife-function"),
    ] {
        let surface =
            effinterp_repo::effective_surface(&idx, file).expect("executing export module");
        assert!(
            surface
                .effects
                .iter()
                .any(|e| e.operation == "filesystem.delete" && e.resource == format!("fs:{path}")),
            "{surface:?}"
        );
        assert!(!surface.effects.iter().any(|e| e.resource == "fs:/uncalled"));
    }
    assert!(
        ids.contains(&"run.js".to_string()),
        "run.js script: {ids:?}"
    );
    assert!(
        !ids.contains(&"lib.js".to_string()),
        "module.exports library is not an entrypoint"
    );
    assert!(
        !ids.contains(&"mod.mjs".to_string()),
        "export module is not an entrypoint"
    );
}

#[test]
fn js_parse_failures_retain_execution_uncertainty() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-parse-failures",
        &[
            (
                "index.js",
                "import React from 'react';\nimport ReactDOM from 'react-dom';\nimport App from './App';\nfetch('/api/boot');\nReactDOM.render(<App />, document.getElementById('root'));\n",
            ),
            (
                "main.cjs",
                "const fs = require('fs');\nfs.unlinkSync('/tmp/a');\nconst el = <div className=\"x\" />;\n",
            ),
            (
                "App.js",
                "import React from 'react';\nexport default function App() {\n  return <div>hi</div>;\n}\n",
            ),
            (
                "arrow.mjs",
                "export const App = () =>\n  render(<div />);\n",
            ),
            (
                "library.cjs",
                "module.exports = function App() { return <div />; };\n",
            ),
            ("broken.mjs", "fetch('/api/boot');\nfunction broken( {\n"),
            ("healthy.js", "require('fs').unlinkSync('/healthy');\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(ids(&index), ["healthy.js"]);
    for file in [
        "index.js",
        "main.cjs",
        "broken.mjs",
        "App.js",
        "arrow.mjs",
        "library.cjs",
    ] {
        assert!(
            index.skipped.iter().any(|skip| {
                skip.path == file && skip.category == effinterp_repo::SkipCategory::Failure
            }),
            "unclassifiable source disappeared: {file}"
        );
    }
    let healthy = effects_of(&index, "healthy.js").unwrap();
    assert!(matches!(
        healthy.status,
        effinterp_proto::AnalysisStatus::Complete
    ));
    let report = reach(&index, &Selector::parse("fs:/**").unwrap(), None);
    assert!(matches!(
        report.status,
        effinterp_proto::AnalysisStatus::Partial { .. }
    ));
    let mut limits = IndexLimits::default();
    limits.crawl.max_skips = 1;
    let limited = build_index(&root, limits);
    assert_eq!(limited.skipped.len(), 1);
    assert!(limited.skips_truncated);
    assert!(matches!(
        limited.snapshot_state,
        effinterp_proto::AnalysisStatus::Partial { .. }
    ));

    // A manifest supplies execution-root evidence even when syntax does not.
    std::fs::write(
        root.join("package.json"),
        r#"{"scripts":{"boot":"node index.js"}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("bin.js"),
        "#!/usr/bin/env node\nrender(<App />);\n",
    )
    .unwrap();
    let explicit = build_index(&root, IndexLimits::default());
    assert!(ids(&explicit).contains(&"bin.js".to_string()));
    assert!(!explicit.skipped.iter().any(|skip| skip.path == "bin.js"));
    let surface = explicit
        .entrypoints
        .iter()
        .find_map(|entry| {
            let surface = effinterp_repo::effective_surface(&explicit, &entry.entrypoint.id)?;
            (surface.source_file == "index.js").then_some(surface)
        })
        .expect("manifest-launched parse failure");
    assert!(
        surface
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "parse_error")
    );
}

#[test]
fn shell_wrapper_discovers_the_php_it_execs() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "php-from-shell",
        &[
            (
                "bin/wp",
                "#!/bin/sh\nphp=\"$(command -v php)\"\nSCRIPT_PATH=\"$(dirname \"$0\")/../php/boot-fs.php\"\ncase \"$MODE\" in\n  win) SCRIPT_PATH=\"$(cygpath \"$SCRIPT_PATH\")\" ;;\nesac\nexec \"$php\" $PHP_ARGS \"$SCRIPT_PATH\"\n",
            ),
            (
                "php/boot-fs.php",
                "<?php\ndefine('WP_CLI_ROOT', dirname(__DIR__));\nrequire_once WP_CLI_ROOT . '/php/wp-cli.php';\n",
            ),
            (
                "php/wp-cli.php",
                "<?php\ndefine('WP_CLI', true);\nrequire_once WP_CLI_ROOT . '/php/runner.php';\ngetenv('WP_CLI_USER_AGENT');\n",
            ),
            ("php/runner.php", "<?php\nunlink('/tmp/wp-cache');\n"),
            ("php/class-wp-cli.php", "<?php\nclass WP_CLI {}\n"),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids = ids(&idx);
    assert!(ids.contains(&"bin/wp".to_string()), "wrapper: {ids:?}");
    assert!(
        ids.contains(&"php/boot-fs.php:launch@unknown".to_string()),
        "launched php: {ids:?}"
    );
    assert!(
        !ids.contains(&"php/wp-cli.php".to_string()),
        "required files ride the include graph, not the entrypoint list: {ids:?}"
    );
    assert!(
        !ids.contains(&"php/class-wp-cli.php".to_string()),
        "unrelated class file is not an entrypoint: {ids:?}"
    );
    // Effects across the include chain surface on the launched program,
    // reached through nested include invocations.
    let report = reach(
        &idx,
        &Selector::parse("env:WP_CLI_USER_AGENT").unwrap(),
        None,
    );
    assert!(
        report.payload.as_reach().unwrap().matches.iter().any(|h| {
            h.fact.entrypoint == "php/boot-fs.php:launch@unknown"
                && h.fact.operation.0 == "environment.read"
        }),
        "getenv one require deep is queryable: {report:?}"
    );
    let report = reach(&idx, &Selector::parse("fs:/tmp/wp-cache").unwrap(), None);
    assert!(
        report.payload.as_reach().unwrap().matches.iter().any(|h| {
            h.fact.entrypoint == "php/boot-fs.php:launch@unknown"
                && h.fact.operation.0 == "filesystem.delete"
        }),
        "the delete two requires deep is queryable: {report:?}"
    );

    // The wrapper → launched-program edge is first-class: bin/wp's surface
    // unions the launched chain, and each effect attributes to the file that
    // actually contains it.
    assert!(
        idx.launch_edges
            .iter()
            .any(|e| e.wrapper == "bin/wp" && e.launched == "php/boot-fs.php"),
        "launch edge recorded: {:?}",
        idx.launch_edges
    );
    let wp_report = effects_of(&idx, "bin/wp").expect("wrapper surface");
    let wp = &wp_report.payload.as_effects().unwrap();
    let getenv = wp
        .effects
        .iter()
        .find(|e| e.operation.0 == "environment.read" && display(e).contains("WP_CLI_USER_AGENT"))
        .expect("wrapper surface carries the deep env read");
    assert_eq!(
        origin(getenv),
        "php/wp-cli.php",
        "the effect attributes to the included file that contains it"
    );
    assert!(
        wp_report.provenance.nodes.iter().any(|node| {
            matches!(
                &node.evidence,
                effinterp_proto::ProtocolProvenanceKind::CrossFileCall { from, into }
                    if from.contains("bin/wp") && into.contains("php/boot-fs.php")
            )
        }),
        "provenance retains the wrapper -> launched program edge"
    );
    let delete = wp
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("wrapper surface carries the deep delete");
    assert_eq!(origin(delete), "php/runner.php");
}

#[test]
fn sourced_shell_definitions_are_exact_and_incremental() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "shell-source-definitions",
        &[
            (
                "bin/tool",
                "#!/bin/sh\n. ./lib/actions.sh\nwipe \"$TARGET\"\n",
            ),
            (
                "bin/lib/actions.sh",
                "TARGET=/tmp/sourced-before\nrm -- \"$0.cache\"\nwipe() { rm -- \"$1\"; }\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "bin/tool")
        .expect("sourced wrapper")
        .payload
        .into_effects()
        .unwrap();
    let delete = effects
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.delete"
                && display(effect).contains("/tmp/sourced-before")
        })
        .expect("sourced function delete");
    assert_eq!(origin(delete), "bin/lib/actions.sh");
    let cache_deletes = effects
        .effects
        .iter()
        .filter(|effect| {
            effect.operation.0 == "filesystem.delete" && display(effect).contains(".cache")
        })
        .collect::<Vec<_>>();
    assert_eq!(cache_deletes.len(), 1);
    assert!(display(cache_deletes[0]).contains("bin/tool.cache"));
    assert_eq!(origin(cache_deletes[0]), "bin/lib/actions.sh");

    std::fs::write(
        root.join("bin/lib/actions.sh"),
        "TARGET=/tmp/sourced-after\nwipe() { rm -- \"$1\"; }\n",
    )
    .unwrap();
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("bin/lib/actions.sh".to_string())],
    );
    let rebuilt = build_index(&root, IndexLimits::default());
    assert_eq!(normalize_surface(&index), normalize_surface(&rebuilt));
    assert!(
        effects_of(&index, "bin/tool")
            .expect("updated wrapper")
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && display(effect).contains("/tmp/sourced-after")
            })
    );
}

#[test]
fn dynamic_source_path_does_not_select_a_repository_file() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "shell-source-dynamic-negative",
        &[
            ("bin/tool", "#!/bin/sh\n. \"$LIB\"\nwipe /tmp/invented\n"),
            ("bin/lib/actions.sh", "wipe() { rm -- \"$1\"; }\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "bin/tool")
        .expect("dynamic wrapper")
        .payload
        .into_effects()
        .unwrap();
    assert!(effects.effects.iter().all(|effect| {
        effect.operation.0 != "filesystem.delete" || !display(effect).contains("/tmp/invented")
    }));
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_source")
    );
}

#[test]
fn audited_nested_scripts_keep_direct_runtime_cwd_unknown() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-audited-direct-cwd",
        &[
            (
                "bin/package",
                "#!/bin/sh\ncp Cargo.lock dist/\nrustup target add x86_64-unknown-linux-gnu\n",
            ),
            ("script/pkgmacos", "#!/bin/sh\nrm -f ./dist/pkg\n"),
            (
                "scripts/build-js.mjs",
                "import fs from 'fs'\nfs.writeFileSync('./build/deno.js', '')\n",
            ),
            (
                "scripts/coverage.sh",
                "#!/bin/sh\ntail -n 1 coverage_sorted.txt\n",
            ),
            (
                "scripts/xcompile.sh",
                "#!/bin/sh\ncd build\nrm yq.1\ntar -cf out.tar yq.1\n",
            ),
            (
                "scripts/migrate-black.py",
                "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run(['git', 'apply', '-h'])\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    for (entrypoint, source_cwd) in [
        ("bin/package", "bin"),
        ("script/pkgmacos", "script"),
        ("scripts/build-js.mjs", "scripts"),
        ("scripts/coverage.sh", "scripts"),
        ("scripts/xcompile.sh", "scripts"),
        ("scripts/migrate-black.py", "scripts"),
    ] {
        let discovered = index.find(entrypoint).unwrap();
        assert_eq!(
            discovered.entrypoint.source_cwd.as_deref(),
            Some(source_cwd)
        );
        assert!(matches!(
            discovered.entrypoint.subject,
            Subject::Shell { cwd: None, .. } | Subject::Source { cwd: None, .. }
        ));
    }

    for (entrypoint, operation, leaf, wrong_parent) in [
        ("bin/package", "filesystem.read", "Cargo.lock", "bin"),
        ("script/pkgmacos", "filesystem.delete", "dist/pkg", "script"),
        (
            "scripts/build-js.mjs",
            "filesystem.write",
            "build/deno.js",
            "scripts",
        ),
        (
            "scripts/coverage.sh",
            "filesystem.read",
            "coverage_sorted.txt",
            "scripts",
        ),
        (
            "scripts/xcompile.sh",
            "filesystem.delete",
            "yq.1",
            "scripts/build",
        ),
    ] {
        let effects = effects_of(&index, entrypoint)
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        let effect = effects
            .iter()
            .find(|effect| effect.operation.0 == operation && display(effect).contains(leaf))
            .unwrap_or_else(|| panic!("{entrypoint}: {effects:?}"));
        assert!(display(effect).contains("<cwd>"), "{}", display(effect));
        assert!(
            !display(effect).contains(&format!("fs:{wrong_parent}/{leaf}")),
            "{}",
            display(effect)
        );
    }

    for (entrypoint, executable, wrong_cwd) in [
        ("bin/package", "rustup", "fs:bin"),
        ("scripts/migrate-black.py", "git", "fs:scripts"),
    ] {
        let effects = effects_of(&index, entrypoint)
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        let effect = effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "process.exec" && display(effect).contains(executable)
            })
            .unwrap();
        assert!(display(effect).contains("@ <cwd>"), "{}", display(effect));
        assert!(!display(effect).contains(wrong_cwd), "{}", display(effect));
    }

    let effects = effects_of(&index, "scripts/xcompile.sh")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects;
    let tar = effects
        .iter()
        .find(|effect| effect.operation.0 == "process.exec" && display(effect).contains("proc:tar"))
        .unwrap_or_else(|| panic!("{effects:?}"));
    assert!(
        display(tar).contains("join(<cwd>, fs:build)"),
        "{}",
        display(tar)
    );
}

#[test]
fn direct_unknown_cwd_does_not_create_a_local_launch_after_cd() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-direct-cd-local-launch",
        &[
            ("scripts/run.sh", "#!/bin/sh\ncd build\npython3 task.py\n"),
            (
                "build/task.py",
                "import os\nif __name__ == '__main__':\n    os.remove('/wrong-root-launch')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    assert!(
        index
            .launch_edges
            .iter()
            .all(|edge| edge.wrapper != "scripts/run.sh"),
        "{:?}",
        index.launch_edges
    );
    let effects = effects_of(&index, "scripts/run.sh")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects;
    assert!(effects.iter().all(|effect| {
        origin(effect) != "build/task.py" || !display(effect).contains("/wrong-root-launch")
    }));
}

#[test]
fn ruby_script_detection_uses_code_lines() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-code-lines",
        &[
            ("run.rb", "if __FILE__ == $0\n  puts('run')\nend\n"),
            (
                "reverse.rb",
                "if $PROGRAM_NAME==__FILE__\n  puts('run')\nend\n",
            ),
            ("comment.rb", "# __FILE__ == $0\n# puts('run')\n"),
            ("broken-string.rb", "\"puts('run')\n"),
            ("string.rb", "\"__FILE__ == $0\nputs('run')\"\n'puts(1)'\n"),
            ("separate.rb", "FILE = __FILE__\nPROGRAM = $0\n"),
            ("uncompared.rb", "FILE = [__FILE__, $0]\n"),
            ("call.rb", "puts('run')\n"),
            ("ext/patch.rb", "App::Cleaner.prepend(Faster)\n"),
            ("consts.rb", "X = %w[a b].freeze\n"),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let mut actual = ids(&idx);
    actual.sort();
    assert_eq!(actual, ["call.rb", "reverse.rb", "run.rb"]);
}

#[test]
fn shell_polyglot_entrypoint_composes_embedded_ruby_effects() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "shell-ruby-polyglot",
        &[(
            "bin/shim",
            "#!/bin/bash\nexec ruby -x \"$0\"\n#!/usr/bin/env ruby\nFile.delete('/tmp/polyglot')\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let entrypoint = index.find("bin/shim").unwrap();
    assert!(matches!(
        entrypoint.entrypoint.subject,
        Subject::Shell { .. }
    ));
    assert!(entrypoint.plan().unwrap().execution_graph.nodes.iter().any(
        |node| matches!(&node.subject, Subject::Source { language, source, .. }
            if language == "ruby" && source.starts_with("#!/usr/bin/env ruby"))
    ));
    let report = reach(&index, &Selector::parse("fs:/tmp/polyglot").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "bin/shim"
                && hit.fact.operation.0 == "filesystem.delete"),
        "{report:?}"
    );
}
