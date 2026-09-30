//! JS re-export chains: a name imported from an aggregator file resolves
//! through named/star re-exports to the repo function — or wrapped external
//! module — that defines it (zx's vendored-wrapper shape).
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

const PACKAGE_JSON: &str = r#"{"name": "app", "bin": {"app": "./build/cli.js"}}"#;
const TSCONFIG: &str = r#"{"compilerOptions": {"rootDir": "./src", "outDir": "./build"}}"#;

#[test]
fn wrapped_fs_resolves_through_reexport_chain() {
    // cli.ts -> index.ts (named re-export) -> vendor.ts (star re-export) ->
    // vendor-extra.ts (`export const fs = wrap('fs', _fs)` over fs-extra).
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-reexport-wrap",
        &[
            ("package.json", PACKAGE_JSON),
            ("tsconfig.json", TSCONFIG),
            (
                "src/cli.ts",
                "import { fs } from './index.ts'\n\
                 export async function main(tempPath: string, script: string) {\n\
                   await fs.writeFile(tempPath, script)\n\
                 }\n\
                 main(process.argv[2], '')\n",
            ),
            ("src/index.ts", "export { fs } from './vendor.ts'\n"),
            ("src/vendor.ts", "export * from './vendor-extra.ts'\n"),
            (
                "src/vendor-extra.ts",
                "import * as _fs from 'fs-extra'\n\
                 function wrap(name: string, api: any) { return api }\n\
                 export const fs = wrap('fs', _fs)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "src/cli.ts")
        .expect("cli.ts analyzed")
        .payload
        .into_effects()
        .unwrap();
    let write = report
        .effects
        .iter()
        .find(|e| e.operation.as_str() == "filesystem.write")
        .expect("wrapped fs.writeFile surfaces as a write");
    assert_eq!(
        write
            .origin
            .as_ref()
            .expect("effect origin")
            .source_file
            .as_str(),
        "src/cli.ts"
    );
}

#[test]
fn unmodeled_member_on_wrapped_module_is_loud() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-reexport-unmodeled",
        &[
            ("package.json", PACKAGE_JSON),
            ("tsconfig.json", TSCONFIG),
            (
                "src/cli.ts",
                "import { fs } from './vendor.ts'\n\
                 export function main(p: string) { return fs.ensureDirSync(p) }\n\
                 main(process.argv[2])\n",
            ),
            (
                "src/vendor.ts",
                "import * as _fs from 'fs-extra'\n\
                 function wrap(name: string, api: any) { return api }\n\
                 export const fs = wrap('fs', _fs)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "src/cli.ts")
        .expect("cli.ts analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .boundaries
            .iter()
            .any(|b| b.reason == "external_unmodeled"
                && b.detail.as_deref().unwrap_or("").contains("ensureDirSync")
                && b.domains
                    .iter()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == effinterp_proto::DOMAINS.into_iter().collect()),
        "an unmodeled member of the wrapped module stays a loud boundary: {:?}",
        report.boundaries
    );
}

#[test]
fn ambiguous_star_reexport_never_resolves() {
    // Two star-exported files both bind `fs`; the name is ambiguous, so no
    // effect may be fabricated.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-reexport-ambiguous",
        &[
            ("package.json", PACKAGE_JSON),
            ("tsconfig.json", TSCONFIG),
            (
                "src/cli.ts",
                "import { fs } from './vendor.ts'\n\
                 export function main(p: string) { return fs.writeFile(p, '') }\n\
                 main(process.argv[2])\n",
            ),
            (
                "src/vendor.ts",
                "export * from './a.ts'\nexport * from './b.ts'\n",
            ),
            (
                "src/a.ts",
                "import * as _fs from 'fs-extra'\n\
                 function wrap(n: string, api: any) { return api }\n\
                 export const fs = wrap('fs', _fs)\n",
            ),
            (
                "src/b.ts",
                "import * as _cp from 'child_process'\n\
                 function wrap(n: string, api: any) { return api }\n\
                 export const fs = wrap('cp', _cp)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "src/cli.ts")
        .expect("cli.ts analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !report
            .effects
            .iter()
            .any(|e| e.operation.as_str().starts_with("filesystem.")),
        "an ambiguous re-export must not dispatch: {:?}",
        report.effects
    );
}

#[test]
fn esm_import_follows_commonjs_object_spread() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "js-reexport-cjs-spread",
        &[
            (
                "package.json",
                r#"{"name":"app","bin":{"app":"./bin.mjs"}}"#,
            ),
            (
                "bin.mjs",
                "import { wipe } from './hub.cjs'\nwipe('/mixed')\n",
            ),
            ("hub.cjs", "module.exports = { ...require('./impl.cjs') }\n"),
            (
                "impl.cjs",
                "const { rmSync } = require('fs')\nfunction wipe(path) { rmSync(path) }\nexports.wipe = wipe\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "bin.mjs")
        .expect("bin.mjs analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/mixed")
                && effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "impl.cjs"
        }),
        "mixed ESM/CommonJS forward did not resolve: {:?}",
        report.effects
    );
}
