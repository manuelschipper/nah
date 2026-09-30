#![allow(clippy::disallowed_methods)]

use effinterp_proto::{ExecutionRealm, ResourceExpr, ResourceIdentity, validate_repo_query};
use effinterp_repo::{IndexLimits, build_index, effects_of};

use super::plan_execution;
use effinterp_testkit::repo_fixture::repo_test_fixture;

#[test]
fn package_bin_launch_composes_the_selected_source_module() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-package-bin-composition",
        &[
            ("package.json", r#"{"bin":{"demo":"bin/demo.mjs"}}"#),
            (
                "bin/demo.mjs",
                "#!/usr/bin/env node\nimport '../dist/demo.mjs'\n",
            ),
            (
                "src/demo.ts",
                "import { wipe } from './helper'\nwipe('/p7a/package-bin')\n",
            ),
            (
                "src/helper.ts",
                "import { unlinkSync } from 'node:fs'\nexport function wipe(p: string) { unlinkSync(p) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "bin/demo.mjs" && edge.launched == "src/demo.ts" && edge.process.is_none()
    }));
    let surface = effects_of(&index, "bin/demo.mjs").unwrap();
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
                        .contains("/p7a/package-bin")
                    && effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str()
                        == "src/helper.ts"
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
            }),
        "package-bin source composition was lost: {:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn package_bin_launch_cycle_is_one_deterministic_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-package-bin-cycle",
        &[
            (
                "packages/a/package.json",
                r#"{"name":"qa-a","bin":{"qa-a":"src/index.js"},"exports":{".":"./src/index.js"}}"#,
            ),
            ("packages/a/src/index.js", "await import('qa-b')\n"),
            (
                "packages/b/package.json",
                r#"{"name":"qa-b","bin":{"qa-b":"src/index.js"},"exports":{".":"./src/index.js"}}"#,
            ),
            ("packages/b/src/index.js", "await import('qa-a')\n"),
        ],
    );
    let boundaries = |index: &effinterp_repo::RepoIndex| {
        let report = effects_of(index, "packages/a/src/index.js").unwrap();
        validate_repo_query(&report).unwrap();
        effinterp_conformance::validate_conformance_bytes(report.to_canonical_json().as_bytes())
            .unwrap();
        report
            .payload
            .into_effects()
            .unwrap()
            .boundaries
            .into_iter()
            .filter(|boundary| boundary.reason == "launch_cycle")
            .map(|boundary| boundary.detail)
            .collect::<Vec<_>>()
    };
    let first = build_index(&root, IndexLimits::default());
    let second = build_index(&root, IndexLimits::default());
    assert!(first.launch_edges.iter().any(|edge| {
        edge.wrapper == "packages/a/src/index.js" && edge.launched == "packages/b/src/index.js"
    }));
    assert!(first.launch_edges.iter().any(|edge| {
        edge.wrapper == "packages/b/src/index.js" && edge.launched == "packages/a/src/index.js"
    }));
    assert_eq!(boundaries(&first), boundaries(&second));
    assert_eq!(boundaries(&first).len(), 1);
}

#[test]
fn local_source_launches_compose_every_admitted_language() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-local-launches",
        &[
            (
                "scripts/package.json",
                r#"{"scripts":{"run":"python3 ../src/task.py token\nnode ../src/task.js token\nphp ../src/task.php token\nruby ../src/task.rb token\ngo run ../src/task.go token\njava ../src/Task.java token\nrust-script ../src/task.rs token"}}"#,
            ),
            ("src/task.py", "import os\nos.remove('/p7a/python')\n"),
            (
                "src/task.js",
                "import { unlinkSync } from 'fs'\nunlinkSync('/p7a/js')\n",
            ),
            ("src/task.php", "<?php unlink('/p7a/php');\n"),
            ("src/task.rb", "File.delete('/p7a/ruby')\n"),
            (
                "src/task.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/p7a/go\") }\n",
            ),
            (
                "src/Task.java",
                "import java.io.File; class Task { public static void main(String[] a) { new File(\"/p7a/java\").delete(); } }\n",
            ),
            (
                "src/task.rs",
                "fn main() { std::fs::remove_dir_all(\"/p7a/rust\").ok(); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let expected = [
        "src/task.py",
        "src/task.js",
        "src/task.php",
        "src/task.rb",
        "src/task.go",
        "src/Task.java",
        "src/task.rs",
    ];
    for origin in expected {
        assert!(index.launch_edges.iter().any(|edge| {
            edge.wrapper == "scripts/package.json:scripts.run"
                && edge.launched == origin
                && edge.process.as_ref().is_some_and(|process| {
                    process.realm == ExecutionRealm::Host
                        && !process.provenance.is_empty()
                        && matches!(&process.resource, ResourceExpr::Concrete {
                            identity: ResourceIdentity::Process { argv, cwd: Some(cwd), .. }
                        } if argv.iter().any(|arg| matches!(arg, ResourceExpr::Literal { value } if value == "token"))
                            && matches!(cwd.as_ref(), ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path }
                            } if path == "scripts"))
                })
        }), "missing launch evidence for {origin}: {:?}", index.launch_edges);
    }
    let surface = effects_of(&index, "scripts/package.json:scripts.run").unwrap();
    for origin in expected {
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
                }),
            "missing composed effect from {origin}: {:?}",
            surface.payload.as_effects().unwrap().effects
        );
    }
}

#[test]
fn ruby_cwd_and_java_classpath_select_their_programs() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-ruby-java-launch-options",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"ruby -C sub task.rb\njava -classpath decoy.java Actual.java"}}"#,
            ),
            ("task.rb", "File.delete('/p7a/ruby-root')\n"),
            ("sub/task.rb", "File.delete('/p7a/ruby-sub')\n"),
            (
                "decoy.java",
                "import java.io.File; class Decoy { public static void main(String[] a) { new File(\"/p7a/java-decoy\").delete(); } }\n",
            ),
            (
                "Actual.java",
                "import java.io.File; class Actual { public static void main(String[] a) { new File(\"/p7a/java-actual\").delete(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(
        index.launch_edges.iter().any(|edge| {
            edge.wrapper == "package.json:scripts.run" && edge.launched == "Actual.java"
        }),
        "{:?}",
        index.launch_edges
    );
    assert!(
        index.launch_edges.iter().all(|edge| {
            edge.launched != "task.rb"
                && edge.launched != "sub/task.rb"
                && edge.launched != "decoy.java"
        }),
        "{:?}",
        index.launch_edges
    );
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
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
                        == "Actual.java"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/java-actual")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
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
                        == "sub/task.rb"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/ruby-sub")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| {
                !matches!(
                    effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str(),
                    "task.rb" | "decoy.java"
                )
            }),
        "{:?}",
        surface.payload.as_effects().unwrap().effects
    );
}

#[test]
fn php_file_selector_composes_the_selected_source() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-php-file-selector",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"php -n -f task.php"}}"#,
            ),
            ("task.php", "<?php unlink('/p7a/php-file');\n"),
            ("wrong.php", "<?php unlink('/p7a/php-file-wrong');\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(
        index.launch_edges.iter().any(|edge| {
            edge.wrapper == "package.json:scripts.run" && edge.launched == "task.php"
        })
    );
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
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
                        == "task.php"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/php-file")
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );
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
                    != "wrong.php"
            })
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unrecoverable_source")
    );
}

#[test]
fn local_launch_uses_repo_root_and_preserves_invocation_cwd() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-root-cwd",
        &[
            ("package.json", r#"{"scripts":{"run":"python3 task.py"}}"#),
            ("task.py", "import os\nos.remove('/p7a/root-launch')\n"),
            (
                "scripts/package.json",
                r#"{"scripts":{"run":"python3 ../src/task.py"}}"#,
            ),
            ("src/task.py", "import os\nos.remove('victim.txt')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let root_surface = effects_of(&index, "package.json:scripts.run").unwrap();
    assert!(
        root_surface
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
                        == "task.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/root-launch")
            })
    );
    assert!(
        !root_surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unrecoverable_source"
                && boundary.affected_resource.is_some()),
        "the selected root source must be observed: {:?}",
        root_surface.payload.as_effects().unwrap().boundaries
    );

    let nested = effects_of(&index, "scripts/package.json:scripts.run").unwrap();
    assert!(
        nested
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
                        == "src/task.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == "fs:scripts/victim.txt"
            }),
        "invocation cwd effect missing: {:?}",
        nested.payload.as_effects().unwrap().effects
    );
    assert!(
        !nested
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
                        == "src/task.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == "fs:src/victim.txt"
            }),
        "standalone source cwd leaked into the launch: {:?}",
        nested.payload.as_effects().unwrap().effects
    );
}

#[test]
fn local_launch_requires_a_known_cwd() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-known-cwd",
        &[
            (
                "package.json",
                r#"{"scripts":{"literal":"cd sub && python3 task.py"}}"#,
            ),
            ("task.py", "import os\nos.remove('/p7a/wrong-root-cwd')\n"),
            (
                "sub/task.py",
                "import os\nos.remove('/p7a/right-literal-cwd')\n",
            ),
            (
                "scripts/dynamic.sh",
                "#!/bin/sh\ncd \"$(dirname \"$0\")/..\"\npython3 task.py\n",
            ),
            (
                "scripts/task.py",
                "import os\nos.remove('/p7a/wrong-dynamic-cwd')\n",
            ),
            (
                "scripts/anchored.sh",
                "#!/bin/sh\nSELF_PATH=\"$(dirname \"$0\")/anchored.sh\"\ncd \"$UNKNOWN\"\nSCRIPT=\"$(dirname \"$SELF_PATH\")/../anchored.py\"\npython3 \"$SCRIPT\"\n",
            ),
            (
                "anchored.py",
                "import os, subprocess\nos.remove('/p7a/right-wrapper-anchor')\nsubprocess.run(['python3', 'task.py'])\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.literal" && edge.launched == "sub/task.py"
    }));
    let literal = effects_of(&index, "package.json:scripts.literal").unwrap();
    assert!(
        literal
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
                        == "sub/task.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/right-literal-cwd")
            })
    );
    assert!(
        !literal
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
                        == "task.py"
            })
    );

    assert!(!index.launch_edges.iter().any(|edge| {
        edge.wrapper == "scripts/dynamic.sh" && edge.launched == "scripts/task.py"
    }));
    let dynamic = effects_of(&index, "scripts/dynamic.sh").unwrap();
    assert!(
        !dynamic
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
                        == "scripts/task.py"
            })
    );
    assert!(
        dynamic
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unrecoverable_source")
    );

    assert!(
        index.launch_edges.iter().any(|edge| {
            edge.wrapper == "scripts/anchored.sh" && edge.launched == "anchored.py"
        })
    );
    let anchored = effects_of(&index, "scripts/anchored.sh").unwrap();
    assert!(
        anchored
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
                        == "anchored.py"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/right-wrapper-anchor")
            })
    );
    assert!(
        !anchored
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
                        == "task.py"
            })
    );
    assert!(
        anchored
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unrecoverable_source")
    );
}

#[test]
fn launch_option_values_do_not_become_programs() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-option-values",
        &[
            (
                "package.json",
                r#"{"scripts":{"cd":"cd -P sub && python3 task.py","pushd":"pushd -n sub >/dev/null && python3 task.py","node":"node --conditions decoy.js actual.js"}}"#,
            ),
            ("task.py", "import os\nos.remove('/p7a/right-pushd-n')\n"),
            ("sub/task.py", "import os\nos.remove('/p7a/right-cd-p')\n"),
            (
                "-P/task.py",
                "import os\nos.remove('/p7a/wrong-cd-option')\n",
            ),
            (
                "-n/task.py",
                "import os\nos.remove('/p7a/wrong-pushd-option')\n",
            ),
            (
                "decoy.js",
                "const fs = require('fs'); fs.unlinkSync('/p7a/wrong-node-option')\n",
            ),
            (
                "actual.js",
                "const fs = require('fs'); fs.unlinkSync('/p7a/right-node-program')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    for (wrapper, launched, resource) in [
        ("package.json:scripts.cd", "sub/task.py", "/p7a/right-cd-p"),
        (
            "package.json:scripts.pushd",
            "task.py",
            "/p7a/right-pushd-n",
        ),
        (
            "package.json:scripts.node",
            "actual.js",
            "/p7a/right-node-program",
        ),
    ] {
        assert!(
            index
                .launch_edges
                .iter()
                .any(|edge| { edge.wrapper == wrapper && edge.launched == launched })
        );
        let surface = effects_of(&index, wrapper).unwrap();
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
                            == launched
                        && effinterp_proto::display_resource_with_scope(&effect.resource)
                            .contains(resource)
                })
        );
    }
    for wrong in ["-P/task.py", "-n/task.py", "decoy.js"] {
        assert!(!index.launch_edges.iter().any(|edge| edge.launched == wrong));
    }
}

#[test]
fn discovery_only_js_launchers_compose_the_selected_program() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-discovery-only-js-launchers",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"tsx task.ts\nts-node task.ts\nbun task.ts\ndeno run task.ts","deno":"deno run --cert decoy.ts actual.ts"}}"#,
            ),
            (
                "task.ts",
                "import { rmSync } from 'fs'\nrmSync('/p7a/discovery-js')\n",
            ),
            (
                "actual.ts",
                "import { rmSync } from 'fs'\nrmSync('/p7a/deno-actual')\n",
            ),
            (
                "decoy.ts",
                "import { rmSync } from 'fs'\nrmSync('/p7a/deno-decoy')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
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
                        == "task.ts"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/discovery-js")
            }),
        "{:?} {:?}",
        surface.payload.as_effects().unwrap().effects,
        surface.payload.as_effects().unwrap().boundaries
    );

    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.deno" && edge.launched == "actual.ts"
    }));
    assert!(!index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.deno" && edge.launched == "decoy.ts"
    }));
    let deno = effects_of(&index, "package.json:scripts.deno").unwrap();
    assert!(
        deno.payload
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
                        == "actual.ts"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/deno-actual")
            }),
        "{:?} {:?}",
        deno.payload.as_effects().unwrap().effects,
        deno.payload.as_effects().unwrap().boundaries
    );
    assert!(
        !deno
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
                    == "decoy.ts"
            })
    );
}

#[test]
fn recovered_launches_keep_each_wrapper_cwd() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-context-cwds",
        &[
            (
                "a/package.json",
                r#"{"scripts":{"run":"SCRIPT=\"$(dirname \"$0\")/../src/task.py\"; python3 \"$SCRIPT\""}}"#,
            ),
            (
                "b/package.json",
                r#"{"scripts":{"run":"SCRIPT=\"$(dirname \"$0\")/../src/task.py\"; python3 \"$SCRIPT\""}}"#,
            ),
            ("src/task.py", "import os\nos.remove('victim.txt')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.find("src/task.py").is_none());
    assert!(
        index.find("src/task.py:launch@a").is_some(),
        "{:?}",
        index.launch_edges
    );
    assert!(
        index.find("src/task.py:launch@b").is_some(),
        "{:?}",
        index.launch_edges
    );
    for (wrapper, expected, wrong) in [
        (
            "a/package.json:scripts.run",
            "fs:a/victim.txt",
            "fs:b/victim.txt",
        ),
        (
            "b/package.json:scripts.run",
            "fs:b/victim.txt",
            "fs:a/victim.txt",
        ),
    ] {
        let surface = effects_of(&index, wrapper).unwrap();
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
                            == "src/task.py"
                        && effinterp_proto::display_resource_with_scope(&effect.resource)
                            == expected
                }),
            "{wrapper}: {:?} {:?}",
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
                        == "src/task.py"
                        && effinterp_proto::display_resource_with_scope(&effect.resource) == wrong
                })
        );
    }
}

#[test]
fn local_launch_tracks_directory_stack_and_dot_cwds() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-directory-stack",
        &[
            (
                "package.json",
                r#"{"scripts":{"pushd":"pushd sub >/dev/null && python3 task.py","dynamic":"pushd \"$TARGET\" >/dev/null && python3 task.py","dot":"cd . && python3 task.py"}}"#,
            ),
            (
                "scripts/package.json",
                r#"{"scripts":{"parent":"cd .. && python3 task.py"}}"#,
            ),
            (
                "task.py",
                "import os\nos.remove('/p7a/root-directory-stack')\n",
            ),
            (
                "sub/task.py",
                "import os\nos.remove('/p7a/pushd-directory-stack')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.pushd" && edge.launched == "sub/task.py"
    }));
    let pushed = effects_of(&index, "package.json:scripts.pushd").unwrap();
    assert!(
        pushed
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
                        == "sub/task.py"
            })
    );
    assert!(
        !pushed
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
                        == "task.py"
            })
    );

    assert!(
        !index
            .launch_edges
            .iter()
            .any(|edge| edge.wrapper == "package.json:scripts.dynamic")
    );
    for wrapper in [
        "package.json:scripts.dot",
        "scripts/package.json:scripts.parent",
    ] {
        assert!(
            index
                .launch_edges
                .iter()
                .any(|edge| { edge.wrapper == wrapper && edge.launched == "task.py" })
        );
        let surface = effects_of(&index, wrapper).unwrap();
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
                            == "task.py"
                })
        );
    }
}

#[test]
fn go_run_composes_every_explicit_source_file() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-go-multi-source",
        &[
            (
                "scripts/package.json",
                r#"{"scripts":{"run":"go run -overlay ../cmd/decoy.go ../cmd/main.go ../cmd/extra.go token"}}"#,
            ),
            (
                "cmd/decoy.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(\"/p7a/go-overlay-decoy\") }\n",
            ),
            ("cmd/main.go", "package main\nfunc main() {}\n"),
            (
                "cmd/extra.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(\"/p7a/go-extra\") }\n",
            ),
            (
                "cmd/wrong.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(\"/p7a/go-wrong\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for launched in ["cmd/main.go", "cmd/extra.go"] {
        assert!(
            index.launch_edges.iter().any(|edge| {
                edge.wrapper == "scripts/package.json:scripts.run"
                    && edge.launched == launched
                    && !edge.alternative
            }),
            "missing exact Go source {launched}: {:?}",
            index.launch_edges
        );
    }
    assert!(
        !index
            .launch_edges
            .iter()
            .any(|edge| matches!(edge.launched.as_str(), "cmd/decoy.go" | "cmd/wrong.go"))
    );
    let surface = effects_of(&index, "scripts/package.json:scripts.run").unwrap();
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
                        == "cmd/extra.go"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/go-extra")
            }),
        "selected Go source effect missing: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                matches!(
                    effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .as_str(),
                    "cmd/decoy.go" | "cmd/wrong.go"
                )
            })
    );
}

#[test]
fn direct_source_executable_resolves_once_from_the_wrapper_directory() {
    let nested = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-direct-source-executable",
        &[
            (
                "scripts/package.json",
                r#"{"scripts":{"run":"./job.py token"}}"#,
            ),
            (
                "scripts/job.py",
                "#!/usr/bin/env python3\nimport os\nos.remove('/p7a/direct-right')\n",
            ),
            (
                "scripts/scripts/job.py",
                "#!/usr/bin/env python3\nimport os\nos.remove('/p7a/direct-wrong')\n",
            ),
        ],
    );
    let index = build_index(&nested, IndexLimits::default());
    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "scripts/package.json:scripts.run" && edge.launched == "scripts/job.py"
    }));
    assert!(!index.launch_edges.iter().any(|edge| {
        edge.wrapper == "scripts/package.json:scripts.run"
            && edge.launched == "scripts/scripts/job.py"
    }));
    let surface = effects_of(&index, "scripts/package.json:scripts.run").unwrap();
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
                        == "scripts/job.py"
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
                    == "scripts/scripts/job.py"
            })
    );

    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-root-direct-source-executable",
        &[
            ("package.json", r#"{"scripts":{"run":"./job.py token"}}"#),
            (
                "job.py",
                "#!/usr/bin/env python3\nimport os\nos.remove('/p7a/direct-root')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(
        index.launch_edges.iter().any(|edge| {
            edge.wrapper == "package.json:scripts.run" && edge.launched == "job.py"
        }),
        "{:?}",
        index.launch_edges
    );
    assert!(
        effects_of(&index, "package.json:scripts.run")
            .unwrap()
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
                == "job.py")
    );
}

#[test]
fn launching_a_packaged_module_does_not_replace_its_entry_function() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-packaged-module",
        &[
            (
                "pyproject.toml",
                "[project.scripts]\nmytool = \"pkg.cli:main\"\n",
            ),
            (
                "package.json",
                r#"{"scripts":{"run":"python3 pkg/cli.py"}}"#,
            ),
            ("pkg/__init__.py", ""),
            (
                "pkg/cli.py",
                "import os\nos.getenv('P7A_MODULE')\ndef main():\n    os.remove('/p7a/from-main')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(
        index
            .find("pkg/cli.py")
            .unwrap()
            .entrypoint
            .entry_function
            .as_deref(),
        Some("main")
    );
    let packaged = effects_of(&index, "pkg/cli.py").unwrap();
    assert!(
        packaged
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/from-main")
            })
    );
    let wrapper = effects_of(&index, "package.json:scripts.run").unwrap();
    assert!(
        wrapper
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
                        == "pkg/cli.py"
            })
    );
    assert!(
        !wrapper
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/p7a/from-main")
            })
    );
}

#[test]
fn local_launch_uses_exact_origin_and_leaves_dynamic_or_overwide_targets_open() {
    let exact = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-origin",
        &[
            (
                "scripts/package.json",
                r#"{"scripts":{"run":"python3 ../right/job.py"}}"#,
            ),
            ("right/job.py", "import os\nos.remove('/p7a/right-job')\n"),
            ("wrong/job.py", "import os\nos.remove('/p7a/wrong-job')\n"),
        ],
    );
    let index = build_index(&exact, IndexLimits::default());
    let surface = effects_of(&index, "scripts/package.json:scripts.run").unwrap();
    assert!(
        surface
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
                    == "right/job.py"
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
                    == "wrong/job.py"
            })
    );

    let alternatives = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-alternatives",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"case \"$MODE\" in a) python3 a.py ;; b) python3 b.py ;; esac"}}"#,
            ),
            ("a.py", "import os\nos.remove('/p7a/a')\n"),
            ("b.py", "import os\nos.remove('/p7a/b')\n"),
        ],
    );
    let index = build_index(&alternatives, IndexLimits::default());
    assert_eq!(
        index
            .launch_edges
            .iter()
            .filter(|edge| edge.wrapper == "package.json:scripts.run")
            .count(),
        2
    );
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
    assert!(["a.py", "b.py"].into_iter().all(|origin| {
        surface
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
                    == origin
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("exact")
            })
    }));

    let assigned_alternatives = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-assigned-alternatives",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"if [ \"$MODE\" = a ]; then SCRIPT=a.py; else SCRIPT=b.py; fi; python3 \"$SCRIPT\""}}"#,
            ),
            ("a.py", "import os\nos.remove('/p7a/assigned-a')\n"),
            ("b.py", "import os\nos.remove('/p7a/assigned-b')\n"),
        ],
    );
    let index = build_index(&assigned_alternatives, IndexLimits::default());
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
    assert!(["a.py", "b.py"].into_iter().all(|origin| {
        surface
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
                    == origin
                    && effect.assurance.map(|assurance| assurance.as_str()) == Some("alternatives")
            })
    }));

    let unresolved = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-unresolved",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"python3 \"$TARGET\""}}"#,
            ),
            ("job.py", "import os\nos.remove('/p7a/dynamic')\n"),
        ],
    );
    let index = build_index(&unresolved, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "package.json:scripts.run")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .is_empty()
    );

    let unrelated_operand = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-unresolved-with-source-data",
        &[
            (
                "run.sh",
                "#!/bin/sh\nSCRIPT=\"$(cat /etc/which-tool)\"\npython3 \"$SCRIPT\" --config tools/settings.py\n",
            ),
            (
                "tools/settings.py",
                "import os\nos.remove('/p7a/settings-side-effect')\n",
            ),
        ],
    );
    let index = build_index(&unrelated_operand, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "run.sh")
            .unwrap()
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
                == "tools/settings.py")
    );

    let overwide = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-overwide",
        &[
            (
                "run.sh",
                "#!/bin/sh\nTARGET=\"$(printf '%s' a.py b.py c.py d.py e.py)\"\npython3 \"$TARGET\"\n",
            ),
            ("a.py", "pass\n"),
            ("b.py", "pass\n"),
            ("c.py", "pass\n"),
            ("d.py", "pass\n"),
            ("e.py", "pass\n"),
        ],
    );
    let index = build_index(&overwide, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "run.sh")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .is_empty()
    );
}

#[test]
fn attached_interpreter_modes_do_not_launch_data_operands() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-attached-interpreter-modes",
        &[
            (
                "python-m.sh",
                "#!/bin/sh\npython3 -mpytest targets/wrong.py\n",
            ),
            (
                "python-c.sh",
                "#!/bin/sh\npython3 -c'import os; os.remove(\"/p7a/inline-python\")' targets/wrong.py\n",
            ),
            (
                "node-e.sh",
                "#!/bin/sh\nnode -e'require(\"fs\").rmSync(\"/p7a/inline-node\")' targets/wrong.js\n",
            ),
            (
                "php-r.sh",
                "#!/bin/sh\nphp -r'unlink(\"/p7a/inline-php\");' targets/wrong.php\n",
            ),
            (
                "ruby-e.sh",
                "#!/bin/sh\nruby -e'File.delete(\"/p7a/inline-ruby\")' targets/wrong.rb\n",
            ),
            (
                "targets/wrong.py",
                "import os\nos.remove('/p7a/wrong-python')\n",
            ),
            (
                "targets/wrong.js",
                "require('fs').rmSync('/p7a/wrong-node')\n",
            ),
            ("targets/wrong.php", "<?php unlink('/p7a/wrong-php');\n"),
            ("targets/wrong.rb", "File.delete('/p7a/wrong-ruby')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);

    let module = effects_of(&index, "python-m.sh").unwrap();
    assert!(
        module
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
                    != "targets/wrong.py"
            })
    );
    assert!(
        !module
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unmodeled_command")
    );
    assert!(
        module
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.read"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("targets/wrong.py"))
    );

    for (wrapper, inline_resource, wrong_origin) in [
        ("python-c.sh", "/p7a/inline-python", "targets/wrong.py"),
        ("node-e.sh", "/p7a/inline-node", "targets/wrong.js"),
        ("php-r.sh", "/p7a/inline-php", "targets/wrong.php"),
        ("ruby-e.sh", "/p7a/inline-ruby", "targets/wrong.rb"),
    ] {
        let surface = effects_of(&index, wrapper).unwrap();
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
                            .contains(inline_resource)
                        && effect
                            .origin
                            .as_ref()
                            .expect("effect origin")
                            .source_file
                            .as_str()
                            == wrapper
                }),
            "attached source was not analyzed for {wrapper}: {:?}",
            surface.payload.as_effects().unwrap().effects
        );
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
                        != wrong_origin
                })
        );
    }
}

#[test]
fn stdin_interpreter_modes_do_not_launch_data_operands() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-stdin-interpreter-modes",
        &[
            ("node.sh", "#!/bin/sh\nnode - targets/wrong.js\n"),
            ("ruby.sh", "#!/bin/sh\nruby - targets/wrong.rb\n"),
            (
                "targets/wrong.js",
                "require('fs').rmSync('/p7a/wrong-node-stdin')\n",
            ),
            ("targets/wrong.rb", "File.delete('/p7a/wrong-ruby-stdin')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    for (wrapper, wrong_origin) in [
        ("node.sh", "targets/wrong.js"),
        ("ruby.sh", "targets/wrong.rb"),
    ] {
        let surface = effects_of(&index, wrapper).unwrap();
        assert!(
            surface
                .payload
                .as_effects()
                .unwrap()
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unrecoverable_source")
        );
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
                        != wrong_origin
                })
        );
    }
}

#[test]
fn source_models_use_only_the_program_operand_and_keep_dynamic_boundaries() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-program-position",
        &[
            (
                "run.sh",
                "#!/bin/sh\nPROGRAM=\"$(cat /etc/program)\"\ngo run ./cmd payload.go\njava -jar launcher.jar Payload.java\nrust-script \"$PROGRAM\" payload.rs\nnode \"$PROGRAM\"\n",
            ),
            (
                "payload.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/p7a/go-data\") }\n",
            ),
            (
                "Payload.java",
                "import java.io.File; class Payload { public static void main(String[] a) { new File(\"/p7a/java-data\").delete(); } }\n",
            ),
            (
                "payload.rs",
                "fn main() { std::fs::remove_dir_all(\"/p7a/rust-data\").ok(); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    let surface = effects_of(&index, "run.sh").unwrap();
    assert!(
        ["payload.go", "Payload.java", "payload.rs"]
            .into_iter()
            .all(
                |origin| !surface
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
                        == origin)
            ),
        "data operands must not become launched programs: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason == "unrecoverable_source")
            .count()
            >= 3,
        "each unavailable or dynamic program remains explicit: {:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unmodeled_command"),
        "non-source commands stay unmodeled: {:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn launched_php_follows_source_relative_include() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launched-php-include",
        &[
            ("package.json", r#"{"scripts":{"run":"php sub/main.php"}}"#),
            ("sub/main.php", "<?php require __DIR__ . '/lib.php';\n"),
            ("sub/lib.php", "<?php unlink('/p7a/php-include');\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.run" && edge.launched == "sub/main.php"
    }));
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete")
    );
    let execution = plan_execution(&index, "package.json:scripts.run").unwrap();
    assert!(execution.graph.nodes.iter().any(|node| {
        node.selected_source_path() == Some("/sub/lib.php")
            && node.input.as_ref().is_some_and(|input| {
                input.role == effinterp_proto::ExecutionInputRole::DependencyRequest
                    && matches!(
                        input.content,
                        effinterp_proto::ExecutionContent::Observed { .. }
                    )
            })
    }));
    assert!(
        !surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_include"),
        "__DIR__ must resolve from the launched source: {:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn local_launch_ignores_unrelated_source_assignments() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-assignment-origin",
        &[
            (
                "bin/run",
                "#!/bin/sh\nphp=\"$(command -v php)\"\nSCRIPT_PATH=\"$(dirname \"$0\")/../right.php\"\nDECOY=\"$(dirname \"$0\")/../wrong.php\"\ncase \"$MODE\" in\n  win) SCRIPT_PATH=\"$(cygpath \"$SCRIPT_PATH\")\" ;;\nesac\nexec \"$php\" \"$SCRIPT_PATH\"\n",
            ),
            ("right.php", "<?php unlink('/p7a/right-assignment');\n"),
            ("wrong.php", "<?php unlink('/p7a/wrong-assignment');\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let launched = index
        .launch_edges
        .iter()
        .filter(|edge| edge.wrapper == "bin/run")
        .map(|edge| edge.launched.as_str())
        .collect::<Vec<_>>();
    assert_eq!(launched, ["right.php"]);
    let surface = effects_of(&index, "bin/run").unwrap();
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
                        == "right.php"
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
                    == "wrong.php"
            })
    );

    let argv_data = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-argv-data-assignment",
        &[
            (
                "bin/run",
                "#!/bin/sh\nCFG=\"$(dirname \"$0\")/../cfg/wrong.py\"\nSCRIPT=\"$(dirname \"$0\")/../app/right.py\"\npython3 \"$SCRIPT\" --config \"$CFG\"\n",
            ),
            ("app/right.py", "import os\nos.remove('/p7a/right-argv')\n"),
            ("cfg/wrong.py", "import os\nos.remove('/p7a/wrong-argv')\n"),
        ],
    );
    let index = build_index(&argv_data, IndexLimits::default());
    let launched = index
        .launch_edges
        .iter()
        .filter(|edge| edge.wrapper == "bin/run")
        .map(|edge| edge.launched.as_str())
        .collect::<Vec<_>>();
    assert_eq!(launched, ["app/right.py"]);
    let surface = effects_of(&index, "bin/run").unwrap();
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
                    == "cfg/wrong.py"
            })
    );

    let blocked_mode = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-blocked-mode-assignment",
        &[
            (
                "run.sh",
                "#!/bin/sh\nDATA=\"$(dirname \"$0\")/cfg/schema.py\"\npython3 -m mytool \"$DATA\"\n",
            ),
            (
                "cfg/schema.py",
                "import os\nos.remove('/p7a/schema-data')\n",
            ),
        ],
    );
    let index = build_index(&blocked_mode, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    let surface = effects_of(&index, "run.sh").unwrap();
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
                    == "cfg/schema.py"
            })
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unrecoverable_source")
    );

    let dynamic_assignment = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-dynamic-assignment-data",
        &[
            (
                "run.sh",
                "#!/bin/sh\nSCRIPT=\"$(cat cfg/wrong.py)\"\npython3 \"$SCRIPT\"\n",
            ),
            (
                "cfg/wrong.py",
                "import os\nos.remove('/p7a/assignment-data')\n",
            ),
        ],
    );
    let index = build_index(&dynamic_assignment, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "run.sh")
            .unwrap()
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
                == "cfg/wrong.py")
    );

    let substitution_prefix = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-substitution-prefix",
        &[
            (
                "run.sh",
                "#!/bin/sh\nSCRIPT=\"$(cat prefix)wrong.py\"\npython3 \"$SCRIPT\"\n",
            ),
            (
                "wrong.py",
                "import os\nos.remove('/p7a/substitution-prefix')\n",
            ),
        ],
    );
    let index = build_index(&substitution_prefix, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "run.sh")
            .unwrap()
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
                == "wrong.py")
    );
}

#[test]
fn launched_source_must_be_admitted_by_the_crawl() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-size-limit",
        &[
            ("run.sh", "#!/bin/sh\npython3 large.py\n"),
            (
                "large.py",
                "import os\nos.remove('/p7a/large-before')\n# padding padding padding padding padding padding padding padding padding padding\n",
            ),
        ],
    );
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_file_bytes: 100,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let before = build_index(&root, limits.clone());
    assert!(
        before
            .skipped
            .iter()
            .any(|skip| skip.path == "large.py" && skip.reason.contains("max_file_bytes"))
    );
    assert!(
        before
            .dependency_manifest
            .source_digest("large.py")
            .is_none()
    );
    assert!(before.launch_edges.is_empty(), "{:?}", before.launch_edges);
    assert!(
        !effects_of(&before, "run.sh")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete")
    );

    std::fs::write(
        root.join("large.py"),
        "import os\nos.remove('/p7a/large-after')\n# padding padding padding padding padding padding padding padding padding padding\n",
    )
    .unwrap();
    let after = build_index(&root, limits);
    assert_eq!(before.fingerprint, after.fingerprint);
    assert!(after.launch_edges.is_empty(), "{:?}", after.launch_edges);

    let vendored = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-skipped-directory",
        &[
            ("bin/run.sh", "#!/bin/sh\npython3 ../vendor/tool.py\n"),
            (
                "vendor/tool.py",
                "import os\nos.remove('/p7a/vendored-before')\n",
            ),
        ],
    );
    let before = build_index(&vendored, IndexLimits::default());
    assert!(
        before
            .dependency_manifest
            .source_digest("vendor/tool.py")
            .is_none()
    );
    assert!(before.launch_edges.is_empty(), "{:?}", before.launch_edges);
    assert!(
        !effects_of(&before, "bin/run.sh")
            .unwrap()
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
                == "vendor/tool.py")
    );
    std::fs::write(
        vendored.join("vendor/tool.py"),
        "import os\nos.remove('/p7a/vendored-after')\n",
    )
    .unwrap();
    let after = build_index(&vendored, IndexLimits::default());
    assert_eq!(before.fingerprint, after.fingerprint);
    assert!(
        !effects_of(&after, "bin/run.sh")
            .unwrap()
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
                == "vendor/tool.py")
    );
}

#[test]
fn package_bin_source_must_be_admitted_by_the_crawl() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-package-bin-size-limit",
        &[
            ("package.json", r#"{"bin":{"demo":"build/demo.js"}}"#),
            ("build/demo.js", "#!/usr/bin/env node\n"),
            (
                "src/demo.ts",
                "import { unlinkSync } from 'node:fs'\nunlinkSync('/p7a/package-bin-before')\n// padding padding padding padding padding padding padding padding\n",
            ),
        ],
    );
    let limits = IndexLimits {
        crawl: effinterp_repo::CrawlLimits {
            max_file_bytes: 100,
            ..Default::default()
        },
        ..IndexLimits::default()
    };
    let before = build_index(&root, limits.clone());
    assert!(
        before
            .dependency_manifest
            .source_digest("src/demo.ts")
            .is_none()
    );
    assert!(before.find("src/demo.ts").is_none());
    assert!(
        before
            .launch_edges
            .iter()
            .all(|edge| edge.launched != "src/demo.ts")
    );

    std::fs::write(
        root.join("src/demo.ts"),
        "import { unlinkSync } from 'node:fs'\nunlinkSync('/p7a/package-bin-after')\n// padding padding padding padding padding padding padding padding\n",
    )
    .unwrap();
    let after = build_index(&root, limits);
    assert_eq!(before.fingerprint, after.fingerprint);
    assert!(after.find("src/demo.ts").is_none());
    assert!(
        after
            .launch_edges
            .iter()
            .all(|edge| edge.launched != "src/demo.ts")
    );
}

#[test]
fn go_module_metadata_is_bound_into_the_fingerprint() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-go-module-fingerprint",
        &[
            ("go.mod", "module example.test/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"example.test/app/util\"\nfunc main() { util.Wipe() }\n",
            ),
            (
                "util/util.go",
                "package util\nimport \"os\"\nfunc Wipe() { os.RemoveAll(\"/p7a/go-module\") }\n",
            ),
        ],
    );
    let before = build_index(&root, IndexLimits::default());
    assert!(before.dependency_manifest.source_digest("go.mod").is_some());
    assert!(
        effects_of(&before, "main.go")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "util/util.go")
    );

    std::fs::write(
        root.join("go.mod"),
        "module example.test/renamed\n\ngo 1.21\n",
    )
    .unwrap();
    let after = build_index(&root, IndexLimits::default());
    assert_ne!(before.fingerprint, after.fingerprint);
    assert!(
        !effects_of(&after, "main.go")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "util/util.go")
    );
}

#[test]
fn explicitly_launched_test_source_is_a_program() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-test-source",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"python3 tests/helper.py"}}"#,
            ),
            (
                "tests/helper.py",
                "import os\nos.remove('/p7a/explicit-test-launch')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.find("tests/helper.py").is_none());
    assert!(index.find("tests/helper.py:launch@root").is_some());
    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.run" && edge.launched == "tests/helper.py"
    }));
    assert!(
        effects_of(&index, "package.json:scripts.run")
            .unwrap()
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
                == "tests/helper.py")
    );
}

#[test]
fn absolute_runtime_paths_do_not_identify_repository_sources() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-absolute-runtime-path",
        &[
            (
                "run.sh",
                "#!/bin/sh\ndocker run some/image python3 /app/job.py\ncd /python-home\npython3 task.py\ncd /node-home\nnode task.js\ncd /php-home\nphp task.php\ncd /ruby-home\nruby task.rb\ncd /go-home\ngo run task.go\ncd /java-home\njava Task.java\ncd /rust-home\nrust-script task.rs\n",
            ),
            (
                "app/job.py",
                "import os\nos.remove('/p7a/container-collision')\n",
            ),
            (
                "python-home/task.py",
                "import os\nos.remove('/p7a/python-collision')\n",
            ),
            (
                "node-home/task.js",
                "import { unlinkSync } from 'fs'\nunlinkSync('/p7a/node-collision')\n",
            ),
            ("php-home/task.php", "<?php unlink('/p7a/php-collision');\n"),
            ("ruby-home/task.rb", "File.delete('/p7a/ruby-collision')\n"),
            (
                "go-home/task.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/p7a/go-collision\") }\n",
            ),
            (
                "java-home/Task.java",
                "import java.io.File; class Task { public static void main(String[] a) { new File(\"/p7a/java-collision\").delete(); } }\n",
            ),
            (
                "rust-home/task.rs",
                "fn main() { std::fs::remove_dir_all(\"/p7a/rust-collision\").ok(); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    let collision_origins = [
        "app/job.py",
        "python-home/task.py",
        "node-home/task.js",
        "php-home/task.php",
        "ruby-home/task.rb",
        "go-home/task.go",
        "java-home/Task.java",
        "rust-home/task.rs",
    ];
    assert!(
        !effects_of(&index, "run.sh")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| collision_origins.contains(
                &effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
            ))
    );
}

#[test]
fn foreign_realms_do_not_identify_host_repository_sources() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-foreign-realm",
        &[
            (
                "run.sh",
                "#!/bin/sh\ndocker run --rm image python3 job.py\ndocker run --rm -w /srv image python3 job.py\ndocker exec c1 python3 job.py\n",
            ),
            (
                "job.py",
                "import os\nos.remove('/p7a/foreign-realm-collision')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    let surface = effects_of(&index, "run.sh").unwrap();
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
                == "job.py"),
        "container paths must not resolve against host files: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
    assert!(
        surface
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unrecoverable_source"),
        "foreign source remains an explicit boundary: {:?}",
        surface.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn host_launch_cwd_does_not_bind_container_resources() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-launch-cwd-realm",
        &[(
            "package.json",
            r#"{"scripts":{"run":"rm -f host-only.txt; docker run alpine sh -c 'rm -f guest-only.txt'"}}"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "package.json:scripts.run")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects;

    assert!(effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effect.realm == ExecutionRealm::Host
            && effinterp_proto::display_resource_with_scope(&effect.resource) == "fs:host-only.txt"
    }));
    assert!(effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && matches!(
                &effect.realm,
                ExecutionRealm::Container { runtime, name }
                    if runtime == "docker" && name == "alpine"
            )
            && matches!(
                &effect.resource,
                ResourceExpr::Join { parts }
                    if matches!(parts.as_slice(), [
                        ResourceExpr::Parameter { name },
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        }
                    ] if name == "cwd" && path == "guest-only.txt")
            )
    }));
}

#[test]
fn local_launch_paths_cannot_escape_the_repository_root() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-parent-escape",
        &[
            ("run.sh", "#!/bin/sh\npython3 ../job.py\n"),
            (
                "job.py",
                "import os\nos.remove('/p7a/escaped-parent-alias')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "run.sh")
            .unwrap()
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
                == "job.py")
    );
}

#[test]
fn crawl_file_cap_also_bounds_the_registry_and_launch_resolver() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-shared-crawl-cap",
        &[
            ("00/run.sh", "#!/bin/sh\npython3 ../99_job.py\n"),
            ("01/package.json", "{}\n"),
            ("02_noise.txt", "not analyzed\n"),
            (
                "99_job.py",
                "import os\nos.remove('/p7a/over-cap-source')\n",
            ),
        ],
    );
    let index = build_index(
        &root,
        IndexLimits {
            crawl: effinterp_repo::CrawlLimits {
                max_files: 2,
                ..Default::default()
            },
            ..IndexLimits::default()
        },
    );
    assert!(
        index
            .skipped
            .iter()
            .any(|skip| skip.reason.contains("crawl truncated"))
    );
    assert_eq!(
        index.dependency_manifest.source_paths().count(),
        2,
        "{:?}",
        index.dependency_manifest
    );
    assert!(
        index
            .dependency_manifest
            .source_digest("99_job.py")
            .is_none()
    );
    assert!(index.launch_edges.is_empty(), "{:?}", index.launch_edges);
    assert!(
        !effects_of(&index, "00/run.sh")
            .unwrap()
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
                == "99_job.py")
    );
}
#[test]
fn go_file_launch_excludes_unselected_package_siblings() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-go-selected-file",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"go run cmd/main.go token"}}"#,
            ),
            ("cmd/main.go", "package main\nfunc main() {}\n"),
            (
                "cmd/wrong.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(\"/p7a/go-unselected\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.launch_edges.iter().any(|edge| {
        edge.wrapper == "package.json:scripts.run" && edge.launched == "cmd/main.go"
    }));
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
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
                == "cmd/wrong.go"),
        "go run of one file must not add an unselected sibling: {:?}",
        surface.payload.as_effects().unwrap().effects
    );
}
#[test]
fn local_launch_repeats_byte_stably() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-repeat",
        &[
            ("run.sh", "#!/bin/sh\npython3 task.py stable\n"),
            ("task.py", "import os\nos.remove('/p7a/stable')\n"),
        ],
    );
    let first = build_index(&root, IndexLimits::default());
    let second = build_index(&root, IndexLimits::default());
    assert_eq!(
        serde_json::to_string(&first.launch_edges).unwrap(),
        serde_json::to_string(&second.launch_edges).unwrap()
    );
    let rows = |index: &effinterp_repo::RepoIndex| {
        effects_of(index, "run.sh")
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects
            .into_iter()
            .map(|effect| {
                (
                    effect.operation,
                    effect.resource,
                    effect.origin.expect("effect origin").source_file,
                    effect.provenance_roots,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(rows(&first), rows(&second));
}

#[test]
fn repeated_exact_launch_does_not_stack_provenance() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7a-launch-repeat-provenance",
        &[
            (
                "package.json",
                r#"{"scripts":{"run":"python3 task.py\necho between\npython3 task.py"}}"#,
            ),
            ("task.py", "import os\nos.remove('/p7a/repeated')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effects_of(&index, "package.json:scripts.run").unwrap();
    let effect = surface
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "task.py"
        })
        .unwrap();
    assert_eq!(effect.provenance_roots.len(), 1, "{effect:?}");
}

#[test]
fn audited_scripts_use_repository_root_launch_evidence() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-audited-root-launch",
        &[
            (
                "package.json",
                r#"{"scripts":{"just":"./bin/package","cli":"./script/pkgmacos","zx":"node scripts/build-js.mjs","coverage":"bash scripts/coverage.sh","xcompile":"bash scripts/xcompile.sh","black":"python3 scripts/migrate-black.py"}}"#,
            ),
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
            ("scripts/xcompile.sh", "#!/bin/sh\ncd build\nrm yq.1\n"),
            (
                "scripts/migrate-black.py",
                "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run(['git', 'apply', '-h'])\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    for (script, operation, resource) in [
        ("just", "filesystem.read", "fs:Cargo.lock"),
        ("cli", "filesystem.delete", "fs:dist/pkg"),
        ("zx", "filesystem.write", "fs:build/deno.js"),
        ("coverage", "filesystem.read", "fs:coverage_sorted.txt"),
        ("xcompile", "filesystem.delete", "fs:build/yq.1"),
    ] {
        let effects = effects_of(&index, &format!("package.json:scripts.{script}"))
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        assert!(
            effects
                .iter()
                .any(|effect| effect.operation.as_str() == operation
                    && effinterp_proto::display_resource_with_scope(&effect.resource) == resource),
            "{script}: {effects:?}"
        );
    }

    for (script, executable) in [("just", "rustup"), ("black", "git")] {
        let effects = effects_of(&index, &format!("package.json:scripts.{script}"))
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        assert!(
            effects.iter().any(|effect| {
                effect.operation.as_str() == "process.exec"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable: actual, cwd: Some(cwd), .. }
                } if actual == executable && matches!(cwd.as_ref(), ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "."))
            }),
            "{script}: {effects:?}"
        );
    }
}

#[test]
fn unavailable_launched_surface_retains_launch_provenance() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "launch-missing-surface",
        &[
            ("package.json", r#"{"bin":{"demo":"bin/demo.mjs"}}"#),
            (
                "bin/demo.mjs",
                "#!/usr/bin/env node\nimport '../dist/demo.mjs'\n",
            ),
            (
                "src/demo.ts",
                "import fs from 'fs'; fs.rmSync('/launched');\n",
            ),
        ],
    );
    let mut index = build_index(&root, IndexLimits::default());
    let launch = index
        .launch_edges
        .iter()
        .find(|edge| edge.wrapper == "bin/demo.mjs")
        .unwrap()
        .clone();
    index
        .entrypoints
        .retain(|entry| entry.entrypoint.id != launch.launch_entrypoint);
    let surface = effinterp_repo::effective_surface(&index, "bin/demo.mjs").unwrap();
    assert!(
        surface
            .boundaries
            .iter()
            .any(|b| b.reason == "uncomposed_subprocess"
                && b.provenance
                    .iter()
                    .any(|p| p.render().contains("src/demo.ts"))),
        "{surface:?}"
    );
    assert_ne!(
        surface.coverage.get("filesystem"),
        Some(&effinterp_proto::CoverageLevel::Full)
    );
}

#[test]
fn launched_javascript_dependencies_remain_owned_by_repository_linker() {
    // An extensionless dependency must not bypass the index resolver's module
    // ownership rule and acquire a second invocation-plane execution.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "launched-extensionless-dependency",
        &[
            ("package.json", r#"{"scripts":{"run":"node bin/tool"}}"#),
            ("bin/tool", "#!/usr/bin/env node\nrequire('../lib/cli');"),
            (
                "lib/cli",
                "#!/usr/bin/env node\nrequire('fs').unlinkSync('/index-dependency');",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let execution = plan_execution(&index, "package.json:scripts.run").unwrap();
    let inputs = execution
        .graph
        .nodes
        .iter()
        .filter_map(|node| node.input.as_ref())
        .filter(|input| input.role == effinterp_proto::ExecutionInputRole::DependencyRequest)
        .collect::<Vec<_>>();
    assert!(!inputs.is_empty());
    assert!(inputs.iter().all(|input| matches!(
        input.content,
        effinterp_proto::ExecutionContent::Unobserved {
            reason: effinterp_proto::ExecutionInputReason::DependencyNotTraversed,
        }
    )));
}
