//! JS/TS workspace package ownership and bin-wrapper handoff: a workspace
//! member's `package.json` owns its `name`, a bin wrapper's `import('@pkg')`
//! maps through `exports` to source, and ambiguous build-output stems stay
//! unresolved rather than guessed.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

/// workspace manifest -> bin -> wrapper -> source: `bin.js` imports the
/// workspace package by name, whose `exports` point at missing `dist/`, and
/// the unique source under that package is launched.
#[test]
fn workspace_bin_wrapper_imports_package_source() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-bin-wrapper",
        &[
            ("package.json", r#"{"name": "@app/repo", "private": true}"#),
            (
                "packages/cli/package.json",
                r#"{
                  "name": "@app/cli",
                  "bin": { "app": "bin.js" },
                  "exports": { ".": "./dist/index.mjs" }
                }"#,
            ),
            (
                "packages/cli/bin.js",
                "#!/usr/bin/env node\n\
                 if (globalThis.process?.getBuiltinModule) {\n\
                   const { enableCompileCache } =\n\
                     globalThis.process.getBuiltinModule(\"node:module\");\n\
                   enableCompileCache();\n\
                 }\n\
                 await import(\"@app/cli\");\n",
            ),
            (
                "packages/cli/src/index.ts",
                "import process from 'node:process'\nconst token = process.env.CLI_TOKEN\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let wrapper = effects_of(&idx, "packages/cli/bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        wrapper.effects.iter().any(|e| {
            e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("CLI_TOKEN")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "packages/cli/src/index.ts"
        }),
        "wrapper unions the workspace source's env read: {:?}",
        wrapper.effects
    );
    assert!(
        wrapper
            .effects
            .iter()
            .any(|effect| !effect.provenance_roots.is_empty()),
        "launch provenance is retained: {:?}",
        wrapper.effects
    );
    assert!(
        wrapper
            .boundaries
            .iter()
            .any(|b| b.domains.iter().any(|d| d == "filesystem")),
        "compile-cache behavior remains uncertain: {:?}",
        wrapper.boundaries
    );
}

#[test]
fn literal_function_import_matches_direct_import_and_an_esm_shim() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-function-import-wrapper",
        &[
            (
                "package.json",
                r#"{"name":"app","type":"module","bin":{"direct":"bin/direct.mjs","wrapped":"bin/wrapped.cjs","shimmed":"bin/shimmed.cjs"}}"#,
            ),
            (
                "bin/direct.mjs",
                "#!/usr/bin/env node\nimport * as cli from '../src/cli/index.js'\ncli.run()\n",
            ),
            (
                "bin/wrapped.cjs",
                r#"#!/usr/bin/env node
function run() {
    var dynamicImport = new Function("module", "return import(module)");
    return dynamicImport("../src/cli/index.js").then(function runCli(cli) {
        return cli.run();
    });
}
module.exports.__promise = run();
"#,
            ),
            (
                "bin/shimmed.cjs",
                r#"#!/usr/bin/env node
function run() {
    var dynamicImport = new Function("module", "return import(module)");
    return dynamicImport("../src/cli/shim.js").then(function (cli) {
        return cli.run();
    });
}
module.exports.__promise = run();
"#,
            ),
            ("src/cli/shim.js", "export { run } from './index.js'\n"),
            (
                "src/cli/index.js",
                "import { readFile, writeFile } from 'node:fs/promises'\n\
                 export async function run() {\n\
                   await readFile('input.txt')\n\
                   if (process.env.WRITE_OUTPUT) await writeFile('output.txt', '')\n\
                 }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let reached = |entry: &str| {
        let report = effects_of(&index, entry).expect("entrypoint analyzed");
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str().starts_with("filesystem."))
            .map(|effect| {
                (
                    effect.operation.as_str().to_string(),
                    effinterp_proto::display_resource_with_scope(&effect.resource),
                    effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .clone(),
                    effect.modality,
                )
            })
            .collect::<Vec<_>>()
    };
    let direct = reached("bin/direct.mjs");
    let wrapped = reached("bin/wrapped.cjs");
    let shimmed = reached("bin/shimmed.cjs");
    assert_eq!(wrapped, direct);
    assert_eq!(shimmed, direct);
    assert!(
        direct.iter().any(|(operation, resource, origin, _)| {
            operation == "filesystem.read"
                && resource.contains("input.txt")
                && origin == "src/cli/index.js"
        }),
        "direct import did not reach the read: {direct:?}"
    );
    assert!(direct.iter().any(|(operation, resource, origin, _)| {
        operation == "filesystem.write"
            && resource.contains("output.txt")
            && origin == "src/cli/index.js"
    }));

    let live = serde_json::to_string(&effects_of(&index, "bin/wrapped.cjs").unwrap()).unwrap();
    assert_eq!(
        live,
        serde_json::to_string(&effects_of(&index, "bin/wrapped.cjs").unwrap()).unwrap()
    );
}

#[test]
fn rejected_function_import_shapes_remain_boundaries_without_target_effects() {
    let cases = [
        (
            "changed-body",
            "var dynamicImport = new Function('module', 'touch(); return import(module)');\n\
             dynamicImport('../src/cli/index.js').then(cli => cli.run());",
        ),
        (
            "computed-target",
            "var dynamicImport = new Function('module', 'return import(module)');\n\
             dynamicImport('../src/cli/' + name).then(cli => cli.run());",
        ),
        (
            "reassigned-wrapper",
            "var dynamicImport = new Function('module', 'return import(module)');\n\
             dynamicImport = replacement;\n\
             dynamicImport('../src/cli/index.js').then(cli => cli.run());",
        ),
        (
            "wrong-callback",
            "var dynamicImport = new Function('module', 'return import(module)');\n\
             dynamicImport('../src/cli/index.js').then(other);",
        ),
        (
            "external-target",
            "var dynamicImport = new Function('module', 'return import(module)');\n\
             dynamicImport('external-cli').then(cli => cli.run());",
        ),
    ];

    for (tag, body) in cases {
        let bin = format!("#!/usr/bin/env node\nfunction run() {{ {body} }}\nrun();\n");
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("js-function-import-{tag}"),
            &[
                (
                    "package.json",
                    r#"{"name":"app","bin":{"app":"bin/prettier.cjs"}}"#,
                ),
                ("bin/prettier.cjs", &bin),
                (
                    "src/cli/index.js",
                    "import { readFile } from 'fs/promises'\nexport function run() { readFile('guessed.txt') }\n",
                ),
            ],
        );
        let report = effects_of(
            &build_index(&root, IndexLimits::default()),
            "bin/prettier.cjs",
        )
        .expect("wrapper analyzed")
        .payload
        .into_effects()
        .unwrap();
        assert!(
            report
                .effects
                .iter()
                .all(
                    |effect| !effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("guessed.txt")
                ),
            "case {tag} guessed target effects: {:?}",
            report.effects
        );
        assert!(
            !report.boundaries.is_empty(),
            "case {tag} did not stay loud"
        );
    }
}

/// A same-workspace import of another member follows `exports` (including a
/// conditional `import` target) to that member's TypeScript source.
#[test]
fn workspace_package_import_resolves_through_exports() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-exports",
        &[
            (
                "packages/cli/package.json",
                r#"{"name": "@app/cli", "bin": {"app": "bin.js"}, "exports": {".": "./dist/index.mjs"}}"#,
            ),
            (
                "packages/cli/bin.js",
                "#!/usr/bin/env node\nawait import('@app/cli');\n",
            ),
            (
                "packages/cli/src/index.ts",
                "import { load } from '@app/config'\nload()\n",
            ),
            (
                "packages/config/package.json",
                r#"{
                  "name": "@app/config",
                  "exports": {
                    ".": {
                      "types": "./dist/index.d.ts",
                      "import": "./dist/index.mjs",
                      "require": "./dist/index.cjs"
                    }
                  }
                }"#,
            ),
            (
                "packages/config/src/index.ts",
                "import { readFileSync } from 'fs'\nexport function load() { readFileSync('config.json') }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "packages/cli/bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|e| {
            e.operation.as_str() == "filesystem.read"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("config.json")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "packages/config/src/index.ts"
        }),
        "workspace export maps to the config source: {:?}",
        report.effects
    );
}

/// Two sources share the artifact's stem and no conventional `src/<stem>`
/// exists: the mapping stays unresolved instead of guessing.
#[test]
fn ambiguous_build_stem_stays_unresolved() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-ambiguous-stem",
        &[
            (
                "packages/cli/package.json",
                r#"{"name": "@app/cli", "bin": {"app": "bin.js"}, "exports": {".": "./dist/util.mjs"}}"#,
            ),
            (
                "packages/cli/bin.js",
                "#!/usr/bin/env node\nawait import('@app/cli');\n",
            ),
            (
                "packages/cli/src/a/util.ts",
                "import process from 'node:process'\nconst a = process.env.STEM_A\n",
            ),
            (
                "packages/cli/src/b/util.ts",
                "import process from 'node:process'\nconst b = process.env.STEM_B\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "packages/cli/bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && (effinterp_proto::display_resource_with_scope(&e.resource).contains("STEM_A")
                    || effinterp_proto::display_resource_with_scope(&e.resource)
                        .contains("STEM_B"))),
        "an ambiguous stem must not dispatch: {:?}",
        report.effects
    );
}

/// `import run from './cli.js'; run()` enters the default export, which
/// calls a same-file helper — release-it's bin → cli → runTasks shape.
#[test]
fn default_export_call_reaches_the_aliased_function() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-default-export",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./bin.js"}}"#,
            ),
            ("bin.js", "import release from './cli.js'\nrelease()\n"),
            (
                "cli.js",
                "import runTasks from './index.js'\n\
                 export default async function release() { return runTasks() }\n",
            ),
            (
                "index.js",
                "import { readFileSync } from 'fs'\n\
                 const runTasks = () => { readFileSync('config.json') }\n\
                 export default runTasks\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|e| {
            e.operation.as_str() == "filesystem.read"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("config.json")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "index.js"
        }),
        "default-export handoff reaches runTasks: {:?}",
        report.effects
    );
}

/// A function that returns a namespace import types the caller's local, so
/// `tool.publish()` dispatches to the namespace's exported function.
#[test]
fn namespace_return_dispatches_method_to_exported_function() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ns-return",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./bin.js"}}"#,
            ),
            (
                "bin.js",
                "import { publish } from './publish.js'\npublish()\n",
            ),
            (
                "publish.js",
                "import { getTool } from './tool.js'\n\
                 export async function publish() {\n\
                   const tool = await getTool()\n\
                   await tool.publish()\n\
                 }\n",
            ),
            (
                "tool.js",
                "import * as npm from './npm.js'\n\
                 export async function getTool() { return npm }\n",
            ),
            (
                "npm.js",
                "import { exec } from 'tinyexec'\n\
                 export async function publish() { await exec('npm', ['publish']) }\n\
                 export function getOtp() { return process.env.npm_config_otp }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|e| {
            e.operation.as_str() == "process.exec"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("npm")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "npm.js"
        }),
        "returned namespace method reaches npm.publish: {:?}",
        report.effects
    );
    assert!(
        !report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"),
        "an uncalled export of the namespace is not invoked: {:?}",
        report.effects
    );
}

/// Two namespace returns are ambiguous: the caller must not pick a winner.
#[test]
fn divergent_namespace_return_does_not_dispatch() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ns-divergent",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./bin.js"}}"#,
            ),
            ("bin.js", "import { run } from './run.js'\nrun()\n"),
            (
                "run.js",
                "import { pick } from './pick.js'\n\
                 export async function run() {\n\
                   const tool = await pick()\n\
                   await tool.publish()\n\
                 }\n",
            ),
            (
                "pick.js",
                "import * as npm from './npm.js'\n\
                 import * as yarn from './yarn.js'\n\
                 export async function pick() {\n\
                   if (Math.random() > 0.5) return yarn\n\
                   return npm\n\
                 }\n",
            ),
            (
                "npm.js",
                "import { exec } from 'tinyexec'\nexport async function publish() { await exec('npm', []) }\n",
            ),
            (
                "yarn.js",
                "import { exec } from 'tinyexec'\nexport async function publish() { await exec('yarn', []) }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "process.exec"),
        "an ambiguous return must not dispatch: {:?}",
        report.effects
    );
}

/// `.action(handler)` may-invokes an imported command function.
#[test]
fn named_action_callback_is_invoked() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-action-cb",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./bin.js"}}"#,
            ),
            ("bin.js", "import { cli } from './cli.js'\ncli.parse()\n"),
            (
                "cli.js",
                "import { init } from './init.js'\n\
                 export const cli = { command() { return this }, parse() {} }\n\
                 cli.command('init').action(init)\n",
            ),
            (
                "init.js",
                "import { readFileSync } from 'fs'\n\
                 export function init() { readFileSync('config.json') }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|e| {
            e.operation.as_str() == "filesystem.read"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("config.json")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "init.js"
        }),
        "action(init) reaches the command: {:?}",
        report.effects
    );
}

/// A constructed class stored on a bag and destructured later still dispatches
/// `shell.exec` to the class method — release-it's container.shell shape.
#[test]
fn constructed_class_method_dispatches_after_destructure() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-class-shell",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./bin.js"}}"#,
            ),
            ("bin.js", "import run from './index.js'\nrun()\n"),
            (
                "index.js",
                "import Shell from './shell.js'\n\
                 export default function run() {\n\
                   const container = {}\n\
                   container.shell = container.shell || new Shell()\n\
                   const { shell } = container\n\
                   const task = () => shell.exec('git status')\n\
                   spinner.show({ task })\n\
                 }\n",
            ),
            (
                "shell.js",
                "import { exec } from 'child_process'\n\
                 class Shell {\n\
                   exec(cmd) { exec(cmd) }\n\
                 }\n\
                 export default Shell\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|e| {
            e.operation.as_str() == "process.exec"
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "shell.js"
        }),
        "destructured Shell.exec is reached: {:?}",
        report.effects
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "uncomposed_subprocess"
                && boundary.domains.iter().any(|domain| domain == "filesystem"))
    );
}

/// An import of a package the workspace does not own stays a boundary, never
/// a fabricated in-repo file.
#[test]
fn external_package_is_not_a_workspace_member() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-external",
        &[
            (
                "packages/cli/package.json",
                r#"{"name": "@app/cli", "bin": {"app": "bin.js"}, "exports": {".": "./src/index.ts"}}"#,
            ),
            (
                "packages/cli/bin.js",
                "#!/usr/bin/env node\nawait import('@app/cli');\n",
            ),
            (
                "packages/cli/src/index.ts",
                "import { defu } from 'defu'\ndefu({}, {})\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "packages/cli/src/index.ts")
        .expect("index analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !report.effects.iter().any(|e| e
            .origin
            .as_ref()
            .expect("effect origin")
            .source_file
            .as_str()
            .contains("defu")),
        "external package must not resolve to a repo file: {:?}",
        report.effects
    );
}

#[test]
fn package_conditions_distinguish_esm_from_commonjs() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-module-conditions",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "bin.js"}}"#,
            ),
            (
                "bin.js",
                "import { run as runEsm } from '@app/tool'\n\
                 const { run: runCjs } = require('@app/tool')\n\
                 runEsm()\nrunCjs()\n",
            ),
            (
                "packages/tool/package.json",
                r#"{"name":"@app/tool","exports":{".":{"import":"./src/esm.ts","require":"./src/cjs.ts"}}}"#,
            ),
            (
                "packages/tool/src/esm.ts",
                "import { readFileSync } from 'fs'\nexport function run() { readFileSync('/esm') }\n",
            ),
            (
                "packages/tool/src/cjs.ts",
                "import { readFileSync } from 'fs'\nexport function run() { readFileSync('/cjs') }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    for (resource, origin) in [
        ("/esm", "packages/tool/src/esm.ts"),
        ("/cjs", "packages/tool/src/cjs.ts"),
    ] {
        assert!(
            report.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.read"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains(resource)
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == origin
            }),
            "missing {resource} through {origin}: {:?}",
            report.effects
        );
    }
}

#[test]
fn workspace_package_subpath_pattern_resolves_exact_source() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-subpath-pattern",
        &[
            ("package.json", r#"{"name":"app","bin":{"app":"bin.js"}}"#),
            (
                "bin.js",
                "import { load } from '@app/tool/config'\nload()\n",
            ),
            (
                "packages/tool/package.json",
                r#"{"name":"@app/tool","exports":{"./*":"./dist/*.mjs"}}"#,
            ),
            (
                "packages/tool/src/config.ts",
                "import { readFileSync } from 'fs'\nexport function load() { readFileSync('/pattern') }\n",
            ),
            (
                "packages/tool/src/other.ts",
                "import { readFileSync } from 'fs'\nexport function load() { readFileSync('/wrong') }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/pattern")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "packages/tool/src/config.ts"
    }));
    assert!(report.effects.iter().all(|effect| {
        !effinterp_proto::display_resource_with_scope(&effect.resource).contains("/wrong")
    }));
}

#[test]
fn finite_types_only_narrow_a_runtime_backed_receiver() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ts-runtime-receiver",
        &[
            (
                "package.json",
                r#"{"name": "app", "bin": {"app": "./bin.js"}}"#,
            ),
            (
                "bin.js",
                "import { boot, ambiguous, rejectIntruder } from './run.ts'\nboot()\nambiguous(unknown())\nrejectIntruder()\n",
            ),
            (
                "run.ts",
                "import Store from './store.ts'\n\
                 import Other from './other.ts'\n\
                 import Intruder from './intruder.ts'\n\
                 import Base from './base.ts'\n\
                 import Derived from './derived.ts'\n\
                 interface Wiper { wipe(): void }\n\
                 type StoreAlias = Store\n\
                 export function invoke(value: Store | Other) { value.wipe() }\n\
                 function invokeInterface(value: Wiper) { value.wipe() }\n\
                 function invokeBase(value: Base) { value.wipe() }\n\
                 function invokeGeneric<T>(value: T) { value.wipe() }\n\
                 function invokeAlias(value: StoreAlias) { value.wipe() }\n\
                 export function boot() {\n\
                   invoke(new Store())\n\
                   invokeInterface(new Store())\n\
                   invokeBase(new Derived())\n\
                   invokeGeneric(new Store())\n\
                   invokeAlias(new Store())\n\
                 }\n\
                 export function ambiguous(value: Store | Other) { value.wipe() }\n\
                 export function rejected(value: Store | Other) { value.wipe() }\n\
                 export function rejectIntruder() { rejected(new Intruder()) }\n",
            ),
            (
                "store.ts",
                "import { rmSync } from 'fs'\n\
                 export default class Store { wipe() { rmSync('/selected') } }\n",
            ),
            (
                "other.ts",
                "import { rmSync } from 'fs'\n\
                 export default class Other { wipe() { rmSync('/other') } }\n",
            ),
            (
                "intruder.ts",
                "import { rmSync } from 'fs'\n\
                 export default class Intruder { wipe() { rmSync('/intruder') } }\n",
            ),
            (
                "base.ts",
                "import { rmSync } from 'fs'\n\
                 export default class Base { wipe() { rmSync('/base') } }\n",
            ),
            (
                "derived.ts",
                "import Base from './base.ts'\n\
                 export default class Derived extends Base {}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/selected")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "store.ts"
    }));
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/base")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "base.ts"
    }));
    assert!(
        report.effects.iter().all(|effect| {
            !effinterp_proto::display_resource_with_scope(&effect.resource).contains("/other")
                && !effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/intruder")
        }),
        "the erased union must not invent the other receiver: {:?}",
        report.effects
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_call"),
        "the annotation-only call remains a boundary: {:?}",
        report.boundaries
    );
    assert_eq!(
        report
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason == "type_narrowing")
            .count(),
        1,
        "incompatible runtime evidence is rejected explicitly: {:?}",
        report.boundaries
    );
}

#[test]
fn rebound_commonjs_package_binding_does_not_dispatch() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-rebound-commonjs",
        &[
            ("package.json", r#"{"name":"app","bin":{"app":"bin.js"}}"#),
            (
                "bin.js",
                "let { run } = require('@app/tool')\nrun = userCallback\nfunction userCallback() {}\nrun()\n",
            ),
            (
                "packages/tool/package.json",
                r#"{"name":"@app/tool","exports":{".":{"require":"./src/index.js"}}}"#,
            ),
            (
                "packages/tool/src/index.js",
                "const { rmSync } = require('fs')\nexports.run = () => rmSync('/stale')\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .all(
                |effect| !effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/stale")
            ),
        "rebound package import dispatched stale evidence: {:?}",
        report.effects
    );
}

#[test]
fn function_local_shadow_does_not_erase_workspace_import_evidence() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-ws-function-shadow",
        &[
            ("package.json", r#"{"name":"app","bin":{"app":"bin.js"}}"#),
            ("bin.js", "import { run } from './lib.js'\nrun()\n"),
            (
                "lib.js",
                "import { rmSync } from 'fs'\n\
                 export function run() { rmSync('/shadow') }\n\
                 function helper() { const rmSync = 0; return rmSync }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.js")
        .expect("bin.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/shadow")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "lib.js"
    }));
}

#[test]
fn reexported_child_process_keeps_child_behavior_gap() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-reexported-fork",
        &[
            ("package.json", r#"{"name":"app","bin":{"app":"./bin.js"}}"#),
            (
                "bin.js",
                "import { launch } from './launch.js'; launch('/child.js');",
            ),
            (
                "launch.js",
                "export { fork as launch } from 'child_process';",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "bin.js")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "process.exec")
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "uncomposed_subprocess"
                && boundary.domains.iter().any(|domain| domain == "filesystem"))
    );
}
