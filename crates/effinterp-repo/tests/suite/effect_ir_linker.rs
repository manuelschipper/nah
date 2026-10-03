#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_engine::Assurance;
use effinterp_proto::{ResourceExpr, ResourceIdentity, display_resource_with_scope};
use effinterp_repo::{IndexLimits, RepoIndex, build_index, effects_of};

fn fixture(tag: &str, files: Vec<(String, String)>) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(tag);
    let _ = std::fs::remove_dir_all(&root);
    for (rel, content) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}

fn index(tag: &str, files: &[(&str, &str)]) -> RepoIndex {
    let files = files
        .iter()
        .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
        .collect();
    build_index(&fixture(tag, files), IndexLimits::default())
}

fn composed_deletes(index: &RepoIndex, entrypoint: &str) -> Vec<(String, Assurance)> {
    let mut effects: Vec<_> = index
        .composition(entrypoint)
        .into_iter()
        .flat_map(|composition| {
            composition.occurrence_effects.iter().filter(|occurrence| {
                composition.effects[occurrence.effect].effect.operation.0 == "filesystem.delete"
            })
        })
        .map(|effect| (effect.source_file.clone(), effect.assurance))
        .collect();
    effects.sort_by(|a, b| a.0.cmp(&b.0));
    effects.dedup();
    effects
}

#[test]
fn composer_semantics_do_not_dispatch_on_source_language() {
    for (path, source) in [
        (
            "compose/function.rs",
            include_str!("../../src/compose/function.rs"),
        ),
        (
            "compose/budget.rs",
            include_str!("../../src/compose/budget.rs"),
        ),
        (
            "compose/instance.rs",
            include_str!("../../src/compose/instance.rs"),
        ),
        ("compose/mod.rs", include_str!("../../src/compose/mod.rs")),
        (
            "compose/module_execution.rs",
            include_str!("../../src/compose/module_execution.rs"),
        ),
        (
            "compose/control_discharge.rs",
            include_str!("../../src/compose/control_discharge.rs"),
        ),
        ("compose/memo.rs", include_str!("../../src/compose/memo.rs")),
        (
            "compose/lifecycle.rs",
            include_str!("../../src/compose/lifecycle.rs"),
        ),
        ("linker/mod.rs", include_str!("../../src/linker/mod.rs")),
        (
            "linker/python.rs",
            include_str!("../../src/linker/python.rs"),
        ),
        ("linker/js.rs", include_str!("../../src/linker/js.rs")),
        ("linker/rust.rs", include_str!("../../src/linker/rust.rs")),
        ("linker/java.rs", include_str!("../../src/linker/java.rs")),
        ("linker/php.rs", include_str!("../../src/linker/php.rs")),
        ("linker/ruby.rs", include_str!("../../src/linker/ruby.rs")),
        ("normalize.rs", include_str!("../../src/normalize.rs")),
    ] {
        let production = if path.starts_with("compose/") {
            source
        } else {
            source
                .split_once("#[cfg(test)]")
                .map_or(source, |(source, _)| source)
        };
        assert!(
            !production.contains("Lang::"),
            "{path} contains source-language semantic dispatch"
        );
    }
}

/// Fixture name, its files, the queried operation and resource, and the
/// assurance the linker must reach.
type LinkerCase = (
    &'static str,
    Vec<(&'static str, &'static str)>,
    &'static str,
    &'static str,
    Assurance,
);

#[test]
fn every_linker_resolves_repository_targets() {
    let cases: Vec<LinkerCase> = vec![
        (
            "linker-python",
            vec![
                (
                    "app.py",
                    "from util import wipe\nif __name__ == '__main__': wipe()\n",
                ),
                ("util.py", "import os\ndef wipe(): os.remove('/python')\n"),
            ],
            "app.py",
            "util.py",
            Assurance::Exact,
        ),
        (
            "linker-js",
            vec![
                ("app.js", "import { wipe } from './util.js'\nwipe()\n"),
                (
                    "util.js",
                    "import fs from 'fs'\nexport function wipe() { fs.unlinkSync('/js') }\n",
                ),
            ],
            "app.js",
            "util.js",
            Assurance::Exact,
        ),
        (
            "linker-ruby",
            vec![
                (
                    "exe/app",
                    "#!/usr/bin/env ruby\nrequire_relative '../lib/util'\nwipe\n",
                ),
                ("lib/util.rb", "def wipe\n  File.delete('/ruby')\nend\n"),
            ],
            "exe/app",
            "lib/util.rb",
            Assurance::Heuristic,
        ),
        (
            "linker-rust",
            vec![
                (
                    "src/main.rs",
                    "mod util;\nuse crate::util::wipe;\nfn main() { wipe(); }\n",
                ),
                (
                    "src/util.rs",
                    "pub fn wipe() { std::fs::remove_file(\"/rust\").ok(); }\n",
                ),
            ],
            "src/main.rs",
            "src/util.rs",
            Assurance::Exact,
        ),
        (
            "linker-go",
            vec![
                ("go.mod", "module example.com/app\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\nimport \"example.com/app/util\"\nfunc main() { util.Wipe() }\n",
                ),
                (
                    "util/util.go",
                    "package util\nimport \"os\"\nfunc Wipe() { os.RemoveAll(\"/go\") }\n",
                ),
            ],
            "main.go",
            "util/util.go",
            Assurance::Exact,
        ),
        (
            "linker-java",
            vec![
                (
                    "src/App.java",
                    "package a;\nimport a.util.Helper;\npublic class App { public static void main(String[] x) { Helper.wipe(); } }\n",
                ),
                (
                    "src/a/util/Helper.java",
                    "package a.util;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\npublic class Helper { public static void wipe() throws Exception { Files.delete(Path.of(\"/java\")); } }\n",
                ),
            ],
            "src/App.java",
            "src/a/util/Helper.java",
            Assurance::Exact,
        ),
    ];

    for (tag, files, entrypoint, source, assurance) in cases {
        let index = index(tag, &files);
        assert_eq!(
            composed_deletes(&index, entrypoint),
            [(source.to_string(), assurance)],
            "{tag}"
        );
    }

    let php = index(
        "linker-php",
        &[
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\nrequire_once dirname(__DIR__) . '/autoload.php';\n$runner = new App\\Runner();\n$runner->run();\n",
            ),
            ("autoload.php", "<?php\n"),
            (
                "src/Runner.php",
                "<?php\nnamespace App;\nclass Runner { public function run() { unlink('/php'); } }\n",
            ),
        ],
    );
    let surface = effects_of(&php, "bin/tool")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(surface.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect
                .origin
                .as_ref()
                .is_some_and(|origin| origin.source_file == "src/Runner.php")
    }));
}

fn rust_trait_index(tag: &str, count: usize) -> RepoIndex {
    let mut files = vec![
        (
            "src/main.rs".to_string(),
            format!(
                "mod trait_def;\n{}\nuse crate::trait_def::Wipe;\nfn main() {{ let value: &dyn Wipe = external(); value.wipe(); }}\n",
                (0..count)
                    .map(|index| format!("mod impl_{index};"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        ),
        (
            "src/trait_def.rs".to_string(),
            "pub trait Wipe { fn wipe(&self); }\n".to_string(),
        ),
    ];
    for index in 0..count {
        files.push((
            format!("src/impl_{index}.rs"),
            format!(
                "use crate::trait_def::Wipe;\npub struct Type{index};\nimpl Wipe for Type{index} {{ fn wipe(&self) {{ std::fs::remove_file(\"/rust-{index}\").ok(); }} }}\n"
            ),
        ));
    }
    build_index(&fixture(tag, files), IndexLimits::default())
}

#[test]
fn rust_trait_cardinality_is_one_three_six() {
    let single = rust_trait_index("linker-rust-one", 1);
    assert_eq!(
        composed_deletes(&single, "src/main.rs"),
        [("src/impl_0.rs".to_string(), Assurance::Heuristic)]
    );

    let three = rust_trait_index("linker-rust-three", 3);
    assert_eq!(
        composed_deletes(&three, "src/main.rs"),
        (0..3)
            .map(|index| (format!("src/impl_{index}.rs"), Assurance::Alternatives))
            .collect::<Vec<_>>()
    );

    let six = rust_trait_index("linker-rust-six", 6);
    assert!(composed_deletes(&six, "src/main.rs").is_empty());
    let boundaries = &six.composition("src/main.rs").unwrap().boundaries;
    assert!(boundaries.iter().any(|boundary| {
        boundary.reason == "dynamic_dispatch"
            && boundary.detail == "trait Wipe method \"wipe\" has 6 typed candidates"
    }));
}

fn ruby_class_index(tag: &str, count: usize) -> RepoIndex {
    let mut files = vec![(
        "exe/app".to_string(),
        "#!/usr/bin/env ruby\nRunner.new.run\n".to_string(),
    )];
    for index in 0..count {
        files.push((
            format!("lib/runner_{index}.rb"),
            format!("class Runner\n  def run\n    File.delete('/ruby-{index}')\n  end\nend\n"),
        ));
    }
    build_index(&fixture(tag, files), IndexLimits::default())
}

#[test]
fn ruby_class_cardinality_is_one_two_five() {
    let single = ruby_class_index("linker-ruby-one", 1);
    assert_eq!(
        composed_deletes(&single, "exe/app"),
        [("lib/runner_0.rb".to_string(), Assurance::Heuristic)]
    );

    let two = ruby_class_index("linker-ruby-two", 2);
    assert_eq!(
        composed_deletes(&two, "exe/app"),
        (0..2)
            .map(|index| (format!("lib/runner_{index}.rb"), Assurance::Alternatives))
            .collect::<Vec<_>>()
    );

    let five = ruby_class_index("linker-ruby-five", 5);
    assert!(composed_deletes(&five, "exe/app").is_empty());
    let boundaries = &five.composition("exe/app").unwrap().boundaries;
    assert!(boundaries.iter().any(|boundary| {
        boundary.reason == "dynamic_dispatch"
            && boundary.detail == "method \"run\" has 5 candidate Ruby definitions"
    }));
}

#[test]
fn go_execution_roots_are_ordered_and_package_scoped() {
    let index = index(
        "linker-go-roots",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/main\") }\n",
            ),
            (
                "a.go",
                "package main\nimport \"os\"\nvar _ = os.RemoveAll(\"/module\")\nfunc init() { os.RemoveAll(\"/init-a\") }\nfunc init() { os.RemoveAll(\"/init-b\") }\n",
            ),
            (
                "ignored_test.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(\"/test\") }\n",
            ),
        ],
    );
    let composition = index.composition("main.go").unwrap();
    let resources: Vec<_> = composition
        .effects
        .iter()
        .filter(|effect| effect.effect.operation.0 == "filesystem.delete")
        .map(|effect| display_resource_with_scope(&effect.effect.resource))
        .collect();
    assert_eq!(resources, ["fs:/module", "fs:/init-a", "fs:/init-b"]);
    assert!(!resources.iter().any(|resource| resource.contains("test")));
}

#[test]
fn frontend_effect_propagation_facts_control_all_three_composer_sites() {
    let python_local = index(
        "linker-inline-python-local",
        &[(
            "app.py",
            "import os\ndef wipe(): os.remove('/local')\nif __name__ == '__main__': wipe()\n",
        )],
    );
    assert!(composed_deletes(&python_local, "app.py").is_empty());

    let js_local = index(
        "linker-inline-js-local",
        &[(
            "app.js",
            "import fs from 'fs'\nfunction wipe() { fs.unlinkSync('/local') }\nwipe()\n",
        )],
    );
    assert_eq!(
        composed_deletes(&js_local, "app.js"),
        [("app.js".to_string(), Assurance::Exact)]
    );

    let go_static = index(
        "linker-inline-go-static",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/static\") }\nfunc main() { Runner.Wipe(Runner{}) }\n",
            ),
        ],
    );
    assert_eq!(
        composed_deletes(&go_static, "main.go"),
        [("main.go".to_string(), Assurance::Exact)]
    );

    let python_chained = index(
        "linker-inline-python-chained",
        &[(
            "app.py",
            "import os\nclass Runner:\n  def wipe(self): os.remove('/chained')\nif __name__ == '__main__': Runner().wipe()\n",
        )],
    );
    assert_eq!(
        composed_deletes(&python_chained, "app.py"),
        [("app.py".to_string(), Assurance::Exact)]
    );
}

#[test]
fn external_unknown_and_ambiguous_outcomes_remain_explicit() {
    let python = index(
        "linker-unknown-python",
        &[(
            "app.py",
            "from missing import call\nif __name__ == '__main__': call()\n",
        )],
    );
    assert!(
        python
            .composition("app.py")
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "cross_module")
    );

    let js = index(
        "linker-unknown-js",
        &[
            ("app.js", "import { wipe } from './hub.js'\nwipe()\n"),
            ("hub.js", "export * from './a.js'\nexport * from './b.js'\n"),
            ("a.js", "export function wipe() {}\n"),
            ("b.js", "export function wipe() {}\n"),
        ],
    );
    assert!(composed_deletes(&js, "app.js").is_empty());
}

#[test]
fn js_named_namespace_alias_keeps_the_called_member() {
    let index = index(
        "linker-js-external-alias",
        &[
            (
                "app.js",
                "import { update } from './util.js'\nupdate('/old', '/new')\n",
            ),
            (
                "util.js",
                "import { promises as fs } from 'node:fs'\nexport function update(oldPath, newPath) { fs.writeFile(newPath, 'x'); fs.unlink(oldPath) }\n",
            ),
        ],
    );
    let surface = effects_of(&index, "app.js")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let mut operations: Vec<_> = surface
        .effects
        .iter()
        .filter(|effect| {
            effect
                .origin
                .as_ref()
                .is_some_and(|origin| origin.source_file == "util.js")
        })
        .map(|effect| effect.operation.0.as_str())
        .collect();
    operations.sort_unstable();
    assert_eq!(operations, ["filesystem.delete", "filesystem.write"]);
}

#[test]
fn rust_import_executes_an_exact_module_with_a_static_item() {
    let index = index(
        "linker-rust-static-import",
        &[
            (
                "src/main.rs",
                "mod directories;\nuse directories::PROJECT_DIRS;\nfn main() { PROJECT_DIRS.path(); }\n",
            ),
            (
                "src/directories.rs",
                "use std::env;\nuse once_cell::sync::Lazy;\npub struct Dirs;\nimpl Dirs { fn new() -> Dirs { let _ = env::var(\"P4_CACHE\"); Dirs } pub fn path(&self) {} }\npub static PROJECT_DIRS: Lazy<Dirs> = Lazy::new(|| Dirs::new());\n",
            ),
        ],
    );
    let surface = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = surface
        .effects
        .iter()
        .filter(|effect| {
            effect
                .origin
                .as_ref()
                .is_some_and(|origin| origin.source_file == "src/directories.rs")
        })
        .map(|effect| &effect.resource)
        .collect();
    assert!(matches!(
        resources.as_slice(),
        [ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        }] if name == "P4_CACHE"
    ));
}
