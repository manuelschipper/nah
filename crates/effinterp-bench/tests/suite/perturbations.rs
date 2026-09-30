//! Cross-file and flow-graph perturbations: mutations whose expected delta
//! only shows at the repo-composition or serialized-flow layer. Each test
//! pairs a base with a small semantic mutation and asserts the specific
//! difference. Plan-local perturbations live in the engine's suite.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_engine::Engine;
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};
use effinterp_repo::{Composition, IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;
use effinterp_trace::{Reachability, reachable_pairs};

fn composition(tag: &str, files: &[(&str, &str)]) -> Composition {
    let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, files);
    let idx = build_index(&root, IndexLimits::default());
    // An entrypoint whose composition stayed empty may not store one at all.
    idx.composition("app.py").cloned().unwrap_or_default()
}

fn composed_delete(comp: &Composition, path: &str) -> bool {
    comp.effects.iter().any(|e| {
        e.effect.operation.0 == "filesystem.delete"
            && matches!(
                &e.effect.resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path
            )
    })
}

fn indexed_delete(tag: &str, entrypoint: &str, files: &[(&str, &str)], path: &str) -> bool {
    let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, files);
    effects_of(&build_index(&root, IndexLimits::default()), entrypoint)
        .expect("entrypoint analyzed")
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && effinterp_proto::display_resource(&effect.resource) == format!("fs:{path}")
        })
}

fn shell(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

const UTIL_PY: &str = "import shutil\ndef wipe(root):\n    shutil.rmtree(root)\n";

// 4. Rename an imported function: importing and calling `wipe` composes its
// delete; renaming the import target to a name util.py does not define must
// yield an unresolved boundary INSTEAD of the effects.
#[test]
fn renaming_the_import_target_trades_effects_for_a_boundary() {
    let base = composition(
        "pert-import-base",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom util import wipe\nwipe('/var/cache/app')\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    assert!(
        composed_delete(&base, "/var/cache/app"),
        "base composes util.wipe's delete: {:?}",
        base.effects
    );
    assert!(
        !base
            .boundaries
            .iter()
            .any(|b| b.reason == "unresolved_call")
    );

    let mutant = composition(
        "pert-import-renamed",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom util import wupe\nwupe('/var/cache/app')\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    assert!(
        !composed_delete(&mutant, "/var/cache/app"),
        "renamed import must not still compose the delete"
    );
    let boundary = mutant
        .boundaries
        .iter()
        .find(|b| b.reason == "unresolved_call")
        .expect("renamed import yields an unresolved_call boundary");
    assert!(
        boundary.detail.contains("wupe") && boundary.detail.contains("util.py"),
        "boundary names the missing target: {}",
        boundary.detail
    );
}

// 7. Rebind a tracked variable: `d=$(cat f); rm "$d"` carries a read->delete
// flow pair; rebinding `d` to a literal in between must drop the pair (and the
// delete resolves to the literal instead of the tracked value).
#[test]
fn rebinding_the_tracked_variable_drops_the_flow_pair() {
    let read_reaches_delete =
        |plan: &Plan| match reachable_pairs(plan).expect("causality detail required") {
            Reachability::Complete(pairs) => pairs
                .iter()
                .any(|r| r.from.op == "filesystem.read" && r.to.op == "filesystem.delete"),
            Reachability::Saturated { limits, .. } => {
                panic!("reachability unexpectedly saturated: {limits:?}")
            }
        };

    let base = shell("d=$(cat manifest.txt)\nrm \"$d\"");
    assert!(
        read_reaches_delete(&base),
        "base plan must connect the read to the delete"
    );

    let mutant = shell("d=$(cat manifest.txt)\nd=lit\nrm \"$d\"");
    assert!(
        !read_reaches_delete(&mutant),
        "rebinding must break the read->delete pair"
    );
    // The delete now targets the literal rebinding, not the tracked output.
    assert!(mutant.effects.iter().any(|e| {
        e.operation.0 == "filesystem.delete"
            && matches!(
                &e.resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                    if path == "/w/lit"
            )
    }));
}

// 9 (Python, repo layer). Effects follow the actually-passed named callback:
// composition descends into `danger` when it is the argument, and swapping in
// the effect-free `safe` removes the delete.
#[test]
fn swapping_the_named_callback_removes_its_composed_effects() {
    let app = |cb: &str| {
        format!(
            "#!/usr/bin/env python\nimport os\ndef runner(cb):\n    cb()\ndef danger():\n    os.remove('/cb')\ndef safe():\n    pass\nrunner({cb})\n"
        )
    };
    let base = composition("pert-callback-danger", &[("app.py", &app("danger"))]);
    assert!(
        composed_delete(&base, "/cb"),
        "passing danger composes its delete: {:?}",
        base.effects
    );

    let mutant = composition("pert-callback-safe", &[("app.py", &app("safe"))]);
    assert!(
        !composed_delete(&mutant, "/cb"),
        "passing safe must not compose danger's delete"
    );
}

#[test]
fn rebinding_a_returned_session_removes_its_network_effect() {
    let files = |rebind: &str| {
        vec![
            (
                "app.py".to_string(),
                format!(
                    "#!/usr/bin/env python\nimport requests\nfrom transport import build_session\nsession = build_session()\n{rebind}request = requests.Request('GET', 'https://api.example.test/items').prepare()\nsession.send(request)\n"
                ),
            ),
            (
                "transport.py".to_string(),
                "import requests\ndef build_session():\n    session = requests.Session()\n    return session\n"
                    .to_string(),
            ),
        ]
    };
    let network = |tag: &str, rebind: &str| {
        let files = files(rebind);
        let borrowed: Vec<_> = files
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect();
        let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, &borrowed);
        effects_of(&build_index(&root, IndexLimits::default()), "app.py")
            .expect("app.py analyzed")
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.request")
    };
    assert!(network("pert-session-exact", ""));
    assert!(!network("pert-session-rebound", "session = object()\n"));
}

#[test]
fn removing_a_feature_branch_removes_its_process_effect() {
    let has_process = |tag: &str, body: &str| {
        let app = format!(
            "#!/usr/bin/env python\nfrom update import spawn\ndef program(enabled):\n{body}\nprogram(flag)\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[
                ("app.py", &app),
                (
                    "update.py",
                    "import subprocess\ndef spawn():\n    subprocess.Popen(['python', '-m', 'update'])\n",
                ),
            ],
        );
        effects_of(&build_index(&root, IndexLimits::default()), "app.py")
            .expect("app.py analyzed")
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    };
    assert!(has_process(
        "pert-feature-present",
        "    if enabled:\n        spawn()"
    ));
    assert!(!has_process("pert-feature-removed", "    pass"));
}

#[test]
fn removing_literal_source_evidence_removes_sourced_effects() {
    let files = |operand: &str| {
        vec![
            (
                "bin/tool".to_string(),
                format!("#!/bin/sh\n. {operand}\nwipe /tmp/sourced\n"),
            ),
            (
                "bin/lib/actions.sh".to_string(),
                "wipe() { rm -- \"$1\"; }\n".to_string(),
            ),
        ]
    };
    let build = |tag: &str, operand: &str| {
        let files = files(operand);
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect();
        let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, &borrowed);
        build_index(&root, IndexLimits::default())
    };

    let exact = build("pert-shell-source-exact", "./lib/actions.sh");
    assert!(
        effects_of(&exact, "bin/tool")
            .expect("exact source wrapper")
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && effinterp_proto::display_resource(&effect.resource).contains("/tmp/sourced")
            })
    );

    let dynamic = build("pert-shell-source-dynamic", "\"$LIB\"");
    assert!(
        effects_of(&dynamic, "bin/tool")
            .expect("dynamic source wrapper")
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| {
                effect.operation.0 != "filesystem.delete"
                    || !effinterp_proto::display_resource(&effect.resource).contains("/tmp/sourced")
            })
    );
}

#[test]
fn removing_java_inheritance_evidence_removes_the_inherited_effect() {
    let files = |extends: bool| {
        vec![
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion><groupId>a</groupId><artifactId>app</artifactId><version>1</version></project>",
            ),
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App { public static void main(String[] x) { new Child().run(); } }",
            ),
            (
                "src/main/java/a/Child.java",
                if extends {
                    "package a; public class Child extends Base {}"
                } else {
                    "package a; public class Child {}"
                },
            ),
            (
                "src/main/java/a/Base.java",
                "package a; import java.io.File; public class Base { public void run() { new File(\"/java-perturb\").delete(); } }",
            ),
        ]
    };

    assert!(indexed_delete(
        "pert-java-inheritance",
        "src/main/java/a/App.java",
        &files(true),
        "/java-perturb",
    ));
    assert!(!indexed_delete(
        "pert-java-no-inheritance",
        "src/main/java/a/App.java",
        &files(false),
        "/java-perturb",
    ));
}

#[test]
fn removing_ruby_mixin_evidence_removes_the_mixin_effect() {
    let files = |include: bool| {
        vec![
            ("Gemfile", ""),
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'app'\nApp::Runner.new.run\n",
            ),
            (
                "lib/app.rb",
                if include {
                    "require 'app/cleanup'\nmodule App\n  class Runner\n    include Cleanup\n    def run\n      cleanup\n    end\n  end\nend\n"
                } else {
                    "require 'app/cleanup'\nmodule App\n  class Runner\n    def run\n      cleanup\n    end\n  end\nend\n"
                },
            ),
            (
                "lib/app/cleanup.rb",
                "module App\n  module Cleanup\n    def cleanup\n      File.delete('/ruby-perturb')\n    end\n  end\nend\n",
            ),
        ]
    };

    assert!(indexed_delete(
        "pert-ruby-mixin",
        "exe/app",
        &files(true),
        "/ruby-perturb",
    ));
    assert!(!indexed_delete(
        "pert-ruby-no-mixin",
        "exe/app",
        &files(false),
        "/ruby-perturb",
    ));
}

#[test]
fn changing_php_autoload_evidence_removes_the_autoloaded_effect() {
    let files = |prefix: &'static str| {
        vec![
            (
                "composer.json",
                if prefix == "App\\" {
                    r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"app/"}}}"#
                } else {
                    r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"Other\\":"app/"}}}"#
                },
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php $runner = new App\\Runner(); $runner->run();\n",
            ),
            (
                "app/Runner.php",
                "<?php namespace App; class Runner { public function run() { unlink('/php-perturb'); } }\n",
            ),
        ]
    };

    assert!(indexed_delete(
        "pert-php-autoload",
        "bin/tool",
        &files("App\\"),
        "/php-perturb",
    ));
    assert!(!indexed_delete(
        "pert-php-wrong-autoload",
        "bin/tool",
        &files("Other\\"),
        "/php-perturb",
    ));
}
