#![allow(clippy::disallowed_types)]

use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

#[test]
fn explicit_reexport_chain_preserves_definition_origin() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-reexport-chain",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe('/p7a/right')\n",
            ),
            ("api.py", "from forwarding import wipe\n"),
            ("forwarding.py", "from right.impl import wipe\n"),
            (
                "right/impl.py",
                "import shutil\ndef wipe(p): shutil.rmtree(p)\n",
            ),
            (
                "wrong/impl.py",
                "import shutil\ndef wipe(p): shutil.rmtree('/p7a/wrong')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effects_of(&index, "app.py").unwrap();
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/right")
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == "right/impl.py"
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
                    && !effect.provenance_roots.is_empty()
            })
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "wrong/impl.py"
            })
    );
}

#[test]
fn python_star_reexport_forwards_only_public_definitions() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-star-reexport",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe, _hidden\nwipe('/p7a/python-star')\n_hidden()\n",
            ),
            ("api.py", "from impl import *\n"),
            (
                "impl.py",
                "import os\ndef wipe(p): os.remove(p)\ndef _hidden(): os.remove('/p7a/python-star-private')\n",
            ),
            (
                "wrong.py",
                "import os\ndef wipe(p): os.remove('/p7a/python-star-wrong')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
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
                        == "impl.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/python-star")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/p7a/python-star-private")
                    || effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == "wrong.py"
            })
    );
}

#[test]
fn later_python_reexport_binding_wins() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-reexport-rebind",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe('/p7a/python-rebind')\n",
            ),
            ("api.py", "from wrong import wipe\nfrom right import wipe\n"),
            ("right.py", "import os\ndef wipe(p): os.remove(p)\n"),
            (
                "wrong.py",
                "import os\ndef wipe(p): os.remove('/p7a/python-wrong-rebind')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
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
                        == "right.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/python-rebind")
            })
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "wrong.py"
            })
    );
}

#[test]
fn later_python_module_bindings_preserve_reexport_origin() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-module-rebind",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe, move\nwipe('/p7a/python-import-after-def')\nmove('/p7a/python-assigned-import')\n",
            ),
            (
                "api.py",
                "import os\ndef wipe(p): os.remove('/p7a/python-shadowed-def')\nfrom right import wipe\nfrom wrong import move\nfrom other import move as _move\nmove = _move\n",
            ),
            ("right.py", "import os\ndef wipe(p): os.remove(p)\n"),
            ("other.py", "import os\ndef move(p): os.remove(p)\n"),
            (
                "wrong.py",
                "import os\ndef move(p): os.remove('/p7a/python-wrong-assignment')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    for (origin, resource) in [
        ("right.py", "/p7a/python-import-after-def"),
        ("other.py", "/p7a/python-assigned-import"),
    ] {
        assert!(
            surface
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
                            == origin
                        && effinterp_proto::display_resource_with_scope(&effect.resource)
                            .contains(resource)
                        && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
                }),
            "missing {origin} {resource}: {:?} {:?}",
            surface.payload.as_effects().unwrap().effects,
            surface.payload.as_effects().unwrap().boundaries
        );
    }
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    != "api.py"
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        != "wrong.py"
            })
    );
}

#[test]
fn later_python_star_reexport_binding_wins() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-star-reexport-rebind",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe('/p7a/python-star-rebind')\n",
            ),
            ("api.py", "from wrong import wipe\nfrom right import *\n"),
            ("right.py", "import os\ndef wipe(p): os.remove(p)\n"),
            (
                "wrong.py",
                "import os\ndef wipe(p): os.remove('/p7a/python-star-wrong-rebind')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
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
                        == "right.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/python-star-rebind")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "wrong.py"
            })
    );
}

#[test]
fn conditional_python_star_reexport_stays_ambiguous() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-conditional-star-reexport",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe('/p7a/python-conditional-star')\n",
            ),
            (
                "api.py",
                "from left import wipe\nif FLAG:\n    from right import *\n",
            ),
            (
                "left.py",
                "import os\ndef wipe(p): os.remove('/p7a/python-star-left')\n",
            ),
            (
                "right.py",
                "import os\ndef wipe(p): os.remove('/p7a/python-star-right')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    != "left.py"
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        != "right.py"
            })
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == "reexport_ambiguous" }),
        "{:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn later_python_function_import_does_not_rebind_an_earlier_scope() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-scoped-rebind",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import first\nfirst()\n",
            ),
            (
                "lib.py",
                "def first():\n    from right import wipe\n    wipe()\n\ndef second():\n    from wrong import wipe\n    wipe()\n",
            ),
            (
                "right.py",
                "import os\ndef wipe(): os.remove('/p7a/right-scope')\n",
            ),
            (
                "wrong.py",
                "import os\ndef wipe(): os.remove('/p7a/wrong-scope')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
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
                        == "right.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/right-scope")
            })
    );
    assert!(
        !surface
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
                        == "wrong.py"
            })
    );
}

#[test]
fn python_class_reexport_reaches_the_producer() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-class-reexport",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import Wiper\nwiper = Wiper()\nwiper.wipe('/p7a/python-class')\n",
            ),
            ("api.py", "from impl import Wiper\n"),
            (
                "impl.py",
                "import os\nclass Wiper:\n    def wipe(self, p): os.remove(p)\n",
            ),
            (
                "wrong.py",
                "import os\nclass Wiper:\n    def wipe(self, p): os.remove('/p7a/python-class-wrong')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
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
                        == "impl.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/python-class")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "wrong.py"
            })
    );
}

#[test]
fn language_forwarders_keep_the_producer_origin() {
    let php = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-php-forward",
        &[
            (
                "app.php",
                "#!/usr/bin/env php\n<?php\nrequire __DIR__ . '/api.php';\nwipe('/p7a/php-forward');\n",
            ),
            ("api.php", "<?php\nrequire __DIR__ . '/impl.php';\n"),
            ("impl.php", "<?php\nfunction wipe($p) { unlink($p); }\n"),
        ],
    );
    let surface = effects_of(&build_index(&php, IndexLimits::default()), "app.php").unwrap();
    assert!(
        surface
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
                        == "impl.php"
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );

    let ruby = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-ruby-forward",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire_relative '../api'\nwipe('/p7a/ruby-forward')\n",
            ),
            ("api.rb", "require_relative 'impl'\n"),
            ("impl.rb", "def wipe(p)\n  File.delete(p)\nend\n"),
        ],
    );
    let surface = effects_of(&build_index(&ruby, IndexLimits::default()), "exe/app").unwrap();
    assert!(
        surface
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
                        == "impl.rb"
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("heuristic")
            })
    );

    let go = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-go-forward",
        &[
            ("go.mod", "module example.test/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"example.test/app/api\"\nfunc main() { api.Wipe(\"/p7a/go-forward\") }\n",
            ),
            (
                "api/api.go",
                "package api\nimport \"example.test/app/impl\"\nfunc Wipe(p string) { impl.Wipe(p) }\n",
            ),
            (
                "impl/impl.go",
                "package impl\nimport \"os\"\nfunc Wipe(p string) { os.RemoveAll(p) }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&go, IndexLimits::default()), "main.go").unwrap();
    assert!(
        surface
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
                        == "impl/impl.go"
            })
    );

    let rust = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-rust-forward",
        &[
            (
                "main.rs",
                "mod api;\nmod implementation;\nfn main() { crate::api::wipe(); }\n",
            ),
            ("api.rs", "pub use crate::implementation::wipe;\n"),
            (
                "implementation.rs",
                "pub fn wipe() { std::fs::remove_dir_all(\"/p7a/rust-forward\").ok(); }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&rust, IndexLimits::default()), "main.rs").unwrap();
    assert!(
        surface
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
                        == "implementation.rs"
            })
    );

    let java = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-java-forward",
        &[
            (
                "src/main/java/p7a/App.java",
                "package p7a;\nimport p7a.Api;\npublic class App {\n  public static void main(String[] a) { Api.wipe(\"/p7a/java-forward\"); }\n}\n",
            ),
            (
                "src/main/java/p7a/Api.java",
                "package p7a; import p7a.Impl; public class Api extends Impl {}\n",
            ),
            (
                "src/main/java/p7a/Impl.java",
                "package p7a; import java.io.File; public class Impl { public static void wipe(String p) { new File(p).delete(); } }\n",
            ),
            (
                "src/main/java/wrong/Impl.java",
                "package wrong; import java.io.File; public class Impl { public static void wipe(String p) { new File(\"/p7a/wrong-java\").delete(); } }\n",
            ),
        ],
    );
    let index = build_index(&java, IndexLimits::default());
    let surface = effects_of(&index, "src/main/java/p7a/App.java").unwrap();
    assert!(
        surface
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
                        == "src/main/java/p7a/Impl.java"
            })
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "src/main/java/wrong/Impl.java"
            })
    );
}

#[test]
fn php_include_forwarding_rejects_same_name_ambiguity() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-php-ambiguous-forward",
        &[
            (
                "app.php",
                "#!/usr/bin/env php\n<?php\nrequire __DIR__ . '/a.php';\nrequire __DIR__ . '/b.php';\nwipe();\n",
            ),
            ("a.php", "<?php function wipe() { unlink('/p7a/php/a'); }\n"),
            ("b.php", "<?php function wipe() { unlink('/p7a/php/b'); }\n"),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.php").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "an ambiguous include must not select a definition: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "reexport_ambiguous"),
        "ambiguity must remain explicit: {:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn php_function_local_include_is_not_a_module_reexport() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-php-function-local-include",
        &[
            (
                "app.php",
                "#!/usr/bin/env php\n<?php\nrequire __DIR__ . '/api.php';\nwipe();\n",
            ),
            (
                "api.php",
                "<?php\nfunction setup() { require __DIR__ . '/impl.php'; }\n",
            ),
            (
                "impl.php",
                "<?php function wipe() { unlink('/p7a/function-local'); }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.php").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "impl.php"),
        "an uncalled function-local include must not forward definitions: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
}

#[test]
fn private_js_import_is_not_a_reexport() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-js-private-import",
        &[
            (
                "app.js",
                "import { wipe } from './api.js'\nwipe('/p7a/private')\n",
            ),
            (
                "api.js",
                "import { wipe } from './impl.js'\nexport const visible = 1\n",
            ),
            (
                "impl.js",
                "import { rmSync } from 'fs'\nexport function wipe(p) { rmSync(p) }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.js").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete")
    );
}

#[test]
fn js_reexport_cannot_forward_a_private_target_definition() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-js-private-reexport-target",
        &[
            (
                "app.js",
                "import { wipe } from './api.js'\nwipe('/p7a/private-target')\n",
            ),
            ("api.js", "export { wipe } from './impl.js'\n"),
            (
                "impl.js",
                "import { rmSync } from 'fs'\nfunction wipe(p) { rmSync(p) }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.js").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "a private target definition is not part of the re-export surface: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
}

#[test]
fn commonjs_reexport_forwards_only_confirmed_target_exports() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-commonjs-reexport",
        &[
            (
                "app.js",
                "const { wipe } = require('./api.js')\nwipe('/p7a/commonjs')\n",
            ),
            (
                "api.js",
                "const { wipe } = require('./impl.js')\nmodule.exports = { wipe }\n",
            ),
            (
                "impl.js",
                "const { rmSync } = require('fs')\nfunction wipe(p) { rmSync(p) }\nmodule.exports = { wipe }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.js").unwrap();
    assert!(
        surface
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
                        == "impl.js"
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
            })
    );

    let private = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-commonjs-private-target",
        &[
            (
                "app.js",
                "const { wipe } = require('./api.js')\nwipe('/p7a/private-commonjs')\n",
            ),
            (
                "api.js",
                "const { wipe } = require('./impl.js')\nmodule.exports = { wipe }\n",
            ),
            (
                "impl.js",
                "const { rmSync } = require('fs')\nfunction wipe(p) { rmSync(p) }\nmodule.exports = { visible: true }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&private, IndexLimits::default()), "app.js").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "a private CommonJS definition must not be forwarded: {:?}",
        surface.payload.as_effects().unwrap().effects
    );

    let rebound = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-commonjs-rebound-exports",
        &[
            (
                "app.js",
                "const { wipe } = require('./api.js')\nwipe('/p7a/rebound-commonjs')\n",
            ),
            (
                "api.js",
                "const { wipe } = require('./impl.js')\nexports = {}\nexports.wipe = wipe\n",
            ),
            (
                "impl.js",
                "const { rmSync } = require('fs')\nfunction wipe(p) { rmSync(p) }\nmodule.exports = { wipe }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&rebound, IndexLimits::default()), "app.js").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "impl.js"),
        "a rebound exports name must not mutate the runtime export object: {:?}",
        surface.payload.as_effects().unwrap().effects
    );

    let declared_rebound = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-commonjs-declared-rebound-exports",
        &[
            (
                "app.js",
                "const { wipe } = require('./api.js')\nwipe('/p7a/declared-rebound-commonjs')\n",
            ),
            (
                "api.js",
                "const { wipe } = require('./impl.js')\nvar exports = {}\nexports.wipe = wipe\n",
            ),
            (
                "impl.js",
                "const { rmSync } = require('fs')\nfunction wipe(p) { rmSync(p) }\nmodule.exports = { wipe }\n",
            ),
        ],
    );
    let surface = effects_of(
        &build_index(&declared_rebound, IndexLimits::default()),
        "app.js",
    )
    .unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "impl.js"),
        "a declared exports name must not mutate the runtime export object: {:?}",
        surface.payload.as_effects().unwrap().effects
    );

    let shadowed = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-commonjs-shadowed-exports",
        &[
            (
                "destructured.js",
                "const { wipe } = require('./api-destructured.js')\nwipe('/p7a/destructured-commonjs')\n",
            ),
            (
                "api-destructured.js",
                "const { wipe } = require('./impl.js')\nconst { exports } = globalThis\nexports.wipe = wipe\n",
            ),
            (
                "function.js",
                "const { wipe } = require('./api-function.js')\nwipe('/p7a/function-commonjs')\n",
            ),
            (
                "api-function.js",
                "const { wipe } = require('./impl.js')\nexports.wipe = wipe\nfunction exports() {}\n",
            ),
            (
                "impl.js",
                "const { rmSync } = require('fs')\nfunction wipe(p) { rmSync(p) }\nmodule.exports = { wipe }\n",
            ),
        ],
    );
    let index = build_index(&shadowed, IndexLimits::default());
    for app in ["destructured.js", "function.js"] {
        let surface = effects_of(&index, app).unwrap();
        assert!(
            !surface
                .payload
                .as_effects()
                .unwrap()
                .effects
                .iter()
                .any(|effect| effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "impl.js"),
            "a local exports binding must not confirm runtime exports for {app}: {:?}",
            surface.payload.as_effects().unwrap().effects
        );
    }
}

#[test]
fn commonjs_whole_module_require_forwards_confirmed_exports() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-commonjs-whole-module-forward",
        &[
            (
                "app.js",
                "const { wipe } = require('./api.js')\nwipe('/p7a/commonjs-whole')\n",
            ),
            ("api.js", "module.exports = require('./impl.js')\n"),
            (
                "impl.js",
                "const { rmSync } = require('fs')\nfunction wipe(p) { rmSync(p) }\nmodule.exports = { wipe }\n",
            ),
            (
                "wrong.js",
                "const { rmSync } = require('fs')\nfunction wipe() { rmSync('/p7a/commonjs-wrong') }\nmodule.exports = { wipe }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.js").unwrap();
    assert!(
        surface
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
                        == "impl.js"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/commonjs-whole")
            })
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "wrong.js"
            })
    );
}

#[test]
fn typescript_class_reexport_reaches_the_producer() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-typescript-class-reexport",
        &[
            ("package.json", r#"{"scripts":{"run":"node app.ts"}}"#),
            (
                "app.ts",
                "import { Wiper } from './api'\nconst wiper = new Wiper()\nwiper.wipe('/p7a/ts-class')\n",
            ),
            ("api.ts", "export { Wiper } from './impl'\n"),
            (
                "impl.ts",
                "import { rmSync } from 'fs'\nexport class Wiper { wipe(p: string) { rmSync(p) } }\n",
            ),
            (
                "wrong.ts",
                "import { rmSync } from 'fs'\nexport class Wiper { wipe() { rmSync('/p7a/ts-wrong') } }\n",
            ),
        ],
    );
    let surface = effects_of(
        &build_index(&root, IndexLimits::default()),
        "package.json:scripts.run",
    )
    .unwrap();
    assert!(
        surface
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
                        == "impl.ts"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/ts-class")
            }),
        "type re-export did not reach its producer: {:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "wrong.ts"
            })
    );
}

#[test]
fn conditional_python_reexport_is_an_ambiguous_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-python-conditional-reexport",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe('/p7a/conditional-python')\n",
            ),
            (
                "api.py",
                "if FLAG:\n    from right import wipe\nelse:\n    from wrong import wipe\n",
            ),
            (
                "right.py",
                "import os\ndef wipe(p): os.remove('/p7a/right-conditional')\n",
            ),
            (
                "wrong.py",
                "import os\ndef wipe(p): os.remove('/p7a/wrong-conditional')\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.py").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "a conditional export must not select its first definition: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "reexport_ambiguous"),
        "conditional definitions must stay explicit: {:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn reexport_cycles_and_limits_are_deterministic_boundaries() {
    let cycle = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-reexport-cycle",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom a import wipe\nwipe()\n",
            ),
            ("a.py", "from b import wipe\n"),
            ("b.py", "from a import wipe\n"),
        ],
    );
    let first = build_index(&cycle, IndexLimits::default());
    let second = build_index(&cycle, IndexLimits::default());
    let boundary = |index: &effinterp_repo::RepoIndex| {
        effects_of(index, "app.py")
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .boundaries
            .into_iter()
            .map(|boundary| (boundary.reason, boundary.detail))
            .collect::<Vec<_>>()
    };
    assert_eq!(boundary(&first), boundary(&second));
    assert!(
        boundary(&first)
            .iter()
            .any(|(reason, _)| reason == "reexport_cycle")
    );

    let mut owned = vec![(
        "app.py".to_string(),
        "#!/usr/bin/env python\nfrom hop0 import wipe\nwipe()\n".to_string(),
    )];
    for index in 0..65 {
        owned.push((
            format!("hop{index}.py"),
            format!("from hop{} import wipe\n", index + 1),
        ));
    }
    owned.push(("hop65.py".to_string(), "def wipe(): pass\n".to_string()));
    let borrowed = owned
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    let over = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-reexport-limit",
        &borrowed,
    );
    let surface = effects_of(&build_index(&over, IndexLimits::default()), "app.py").unwrap();
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "reexport_limit")
    );
}

#[test]
fn shared_php_reexport_graph_is_bounded() {
    let files = 30;
    let mut owned = vec![(
        "app.php".to_string(),
        "#!/usr/bin/env php\n<?php require __DIR__ . '/f0.php'; missing();\n".to_string(),
    )];
    for index in 0..files {
        let imports = [index + 1, index + 2]
            .into_iter()
            .filter(|next| *next < files)
            .map(|next| format!("require __DIR__ . '/f{next}.php';"))
            .collect::<Vec<_>>()
            .join("\n");
        owned.push((format!("f{index}.php"), format!("<?php\n{imports}\n")));
    }
    let borrowed = owned
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-shared-php-reexports",
        &borrowed,
    );

    let index = build_index(&root, IndexLimits::default());
    let surface = effects_of(&index, "app.php").unwrap();
    // Each file includes the next two, so the graph has about two edges per
    // file and a chase that enters each shared file once is linear in it.
    // Enumerating every route instead grows like the Fibonacci numbers.
    assert!(
        index.registry.export_visits() <= 8 * files as u64,
        "the bounded export walk revisited shared include paths: {} visits",
        index.registry.export_visits()
    );
    assert!(
        !surface.payload.as_effects().unwrap().boundaries.is_empty(),
        "the missing definition must remain an explicit boundary"
    );
}

#[test]
fn javascript_star_reexport_does_not_forward_default() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-js-star-default",
        &[
            (
                "app.js",
                "import { default as wipe } from './api.js'\nwipe('/p7a/js-default')\n",
            ),
            ("api.js", "export * from './impl.js'\n"),
            (
                "impl.js",
                "import { rmSync } from 'fs'\nexport default function wipe(p) { rmSync(p) }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.js").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "impl.js"),
        "export-star must not forward default: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
}

#[test]
fn conditional_php_include_is_not_reexport_evidence() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-php-conditional-include",
        &[
            (
                "app.php",
                "#!/usr/bin/env php\n<?php\nrequire __DIR__ . '/api.php';\nwipe();\n",
            ),
            (
                "api.php",
                "<?php\nif (false) { require __DIR__ . '/impl.php'; }\n",
            ),
            (
                "impl.php",
                "<?php function wipe() { unlink('/p7a/conditional-include'); }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "app.php").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "impl.php"),
        "conditional include must not forward definitions: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
}

#[test]
fn rust_reexport_requires_a_visible_target_definition() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-rust-private-target",
        &[
            (
                "main.rs",
                "mod api;\nmod implementation;\nfn main() { crate::api::wipe(); }\n",
            ),
            ("api.rs", "pub use crate::implementation::wipe;\n"),
            (
                "implementation.rs",
                "fn wipe() { std::fs::remove_dir_all(\"/p7a/rust-private\").ok(); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effects_of(&index, "main.rs").unwrap();
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "implementation.rs"),
        "a private Rust definition must not be re-exported: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
}
