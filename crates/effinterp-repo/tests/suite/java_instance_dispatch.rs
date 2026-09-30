//! Typed instance flow for Java composition: main discovery in a Maven
//! layout, same-package static calls without imports, declared-type and
//! constructor-typed receivers dispatching across files, instances carried
//! through constructor arguments into fields (the maven-wrapper
//! Installer/Downloader shape), and the negative: an untyped receiver never
//! dispatches on a method-name match alone.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_engine::Assurance;
use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn interface_repo(tag: &str, implementations: usize) -> PathBuf {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[
            (
                "src/main/java/a/Worker.java",
                "package a;\npublic interface Worker { void run(); }\n",
            ),
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App { public static void main(String[] args) { Worker worker; worker.run(); } }\n",
            ),
        ],
    );
    for index in 0..implementations {
        std::fs::write(
            root.join(format!("src/main/java/a/W{index}.java")),
            format!(
                "package a;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\npublic class W{index} implements Worker {{ public void run() {{ try {{ Files.delete(Path.of(\"/java-{index}\")); }} catch (Exception e) {{}} }} }}\n"
            ),
        )
        .unwrap();
    }
    root
}

/// The named operations on the entry's merged surface, as (op, resource,
/// origin) triples.
fn effects(root: &Path, entry: &str) -> Vec<(String, String, String)> {
    let idx = build_index(root, IndexLimits::default());
    let report = effects_of(&idx, entry)
        .expect("entry analyzed")
        .payload
        .into_effects()
        .unwrap();
    report
        .effects
        .iter()
        .map(|e| {
            (
                e.operation.as_str().to_string(),
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

/// A `public static void main` class in the Maven `src/main/java` layout is
/// discovered as an entrypoint and its own modeled effects surface.
#[test]
fn maven_layout_main_is_discovered_with_effects() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jdisp-maven-main",
        &[(
            "proj/src/main/java/com/x/App.java",
            "package com.x;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\n\
             public class App {\n  public static void main(String[] a) throws Exception {\n\
             Files.delete(Path.of(\"/main-disc\"));\n  }\n}\n",
        )],
    );
    let got = effects(&root, "proj/src/main/java/com/x/App.java");
    assert!(
        got.iter()
            .any(|(op, res, _)| op == "filesystem.delete" && res.contains("/main-disc")),
        "main discovered and executed: {got:?}"
    );
}

/// A static call on a same-package class needs no import statement: the
/// synthesized same-package binding resolves it across files.
#[test]
fn same_package_static_call_composes_without_import() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jdisp-samepkg",
        &[
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App {\n  public static void main(String[] x) {\n\
                 Helper.wipe(\"/same-pkg\");\n  }\n}\n",
            ),
            (
                "src/main/java/a/Helper.java",
                "package a;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\n\
                 public class Helper {\n  public static void wipe(String p) throws Exception {\n\
                 Files.delete(Path.of(p));\n  }\n}\n",
            ),
        ],
    );
    let got = effects(&root, "src/main/java/a/App.java");
    assert!(
        got.iter().any(|(op, res, origin)| op == "filesystem.delete"
            && res.contains("/same-pkg")
            && origin.ends_with("Helper.java")),
        "same-package static call composes: {got:?}"
    );
}

#[test]
fn same_package_class_wins_over_a_colliding_wildcard_import() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jdisp-samepkg-wildcard",
        &[
            (
                "src/main/java/a/App.java",
                "package a;\nimport java.util.*;\npublic class App {\n  public static void main(String[] x) {\n                 Optional.of(\"/same-package-optional\");\n  }\n}\n",
            ),
            (
                "src/main/java/a/Optional.java",
                "package a;\npublic class Optional {\n  public static void of(String path) {\n    new java.io.File(path).delete();\n  }\n}\n",
            ),
        ],
    );
    let got = effects(&root, "src/main/java/a/App.java");
    assert!(
        got.iter().any(|(op, res, origin)| op == "filesystem.delete"
            && res.contains("/same-package-optional")
            && origin.ends_with("Optional.java")),
        "same-package class wins over wildcard import: {got:?}"
    );
}

/// A local with a declared class type, initialized from a static factory,
/// dispatches its instance methods into the class's file (the
/// `WrapperExecutor.forWrapperPropertiesFile(...).execute()` shape).
#[test]
fn declared_type_local_dispatches_across_files() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jdisp-declared",
        &[
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App {\n  public static void main(String[] x) {\n\
                 Exec e = Exec.forThing(\"/decl\");\n    e.run();\n  }\n}\n",
            ),
            (
                "src/main/java/a/Exec.java",
                "package a;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\n\
                 public class Exec {\n  private final String p;\n\
                 Exec(String p) { this.p = p; }\n\
                 public static Exec forThing(String p) { return new Exec(p); }\n\
                 public void run() { try { Files.delete(Path.of(\"/decl\")); } catch (Exception e) {} }\n}\n",
            ),
        ],
    );
    let got = effects(&root, "src/main/java/a/App.java");
    assert!(
        got.iter().any(|(op, res, origin)| op == "filesystem.delete"
            && res.contains("/decl")
            && origin.ends_with("Exec.java")),
        "declared-type local dispatches run(): {got:?}"
    );
}

/// An instance passed as a constructor argument, stored on a field, then
/// dispatched through the field in a method entered via a parameter-typed
/// receiver — the maven-wrapper Installer/DefaultDownloader chain.
#[test]
fn instance_through_constructor_field_dispatches() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jdisp-ctor-field",
        &[
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App {\n  public static void main(String[] x) {\n\
                 Exec e = new Exec();\n    e.execute(new Installer(new Downloader()));\n  }\n}\n",
            ),
            (
                "src/main/java/a/Exec.java",
                "package a;\npublic class Exec {\n\
                 public void execute(Installer install) { install.createDist(); }\n}\n",
            ),
            (
                "src/main/java/a/Installer.java",
                "package a;\npublic class Installer {\n  private final Downloader download;\n\
                 public Installer(Downloader download) { this.download = download; }\n\
                 public void createDist() { download.fetch(\"/dist\"); }\n}\n",
            ),
            (
                "src/main/java/a/Downloader.java",
                "package a;\nimport java.net.URL;\n\
                 public class Downloader {\n  public void fetch(String p) {\n\
                 try { new URL(p).openConnection(); } catch (Exception e) {}\n  }\n}\n",
            ),
        ],
    );
    let got = effects(&root, "src/main/java/a/App.java");
    assert!(
        got.iter()
            .any(|(op, _, origin)| op == "network.request" && origin.ends_with("Downloader.java")),
        "field-carried instance dispatches fetch(): {got:?}"
    );
}

/// The negative: a receiver with no declared type must not dispatch, even
/// when exactly one class in the repo defines a method of that name.
#[test]
fn untyped_receiver_does_not_dispatch_on_name_match() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jdisp-untyped",
        &[
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App {\n  public static void main(String[] x) {\n\
                 var w = Factory.make();\n    w.wipe(\"/no-dispatch\");\n  }\n}\n",
            ),
            (
                "src/main/java/a/Decoy.java",
                "package a;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\n\
                 public class Decoy {\n  public void wipe(String p) throws Exception {\n\
                 Files.delete(Path.of(p));\n  }\n}\n",
            ),
        ],
    );
    let got = effects(&root, "src/main/java/a/App.java");
    assert!(
        got.iter().all(|(op, _, _)| op != "filesystem.delete"),
        "an untyped receiver never dispatches on a name match: {got:?}"
    );
}

#[test]
fn interface_candidate_sets_preserve_cardinality_and_cap() {
    let root = interface_repo("java-interface-one", 1);
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main/java/a/App.java").unwrap();
    assert_eq!(composition.effects.len(), 1);
    assert_eq!(
        composition.occurrence_effects[0].assurance,
        Assurance::Heuristic
    );

    let root = interface_repo("java-interface-two", 2);
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "src/main/java/a/App.java")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = report
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(resources, ["fs:/java-0", "fs:/java-1"]);
    assert!(
        index
            .composition("src/main/java/a/App.java")
            .unwrap()
            .occurrence_effects
            .iter()
            .all(|effect| effect.assurance == Assurance::Alternatives)
    );

    let root = interface_repo("java-interface-cap", 5);
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main/java/a/App.java").unwrap();
    assert!(composition.effects.is_empty());
    assert!(composition.boundaries.iter().any(|boundary| {
        boundary.reason == "dynamic_dispatch"
            && boundary.detail.contains("interface Worker")
            && boundary.detail.contains("5 typed candidates")
    }));
}

#[test]
fn static_wildcard_import_does_not_steal_inherited_bare_call() {
    const BASE: &str = "package a;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\npublic class Base {\n  public void wipe() {\n    try { Files.delete(Path.of(\"/base-wipe\")); } catch (Exception e) {}\n  }\n}\n";
    for (tag, static_import) in [
        ("java-static-wc-arrays", "import static java.util.Arrays.*;"),
        ("java-static-wc-junit", "import static org.junit.Assert.*;"),
        (
            "java-static-aslist",
            "import static java.util.Arrays.asList;",
        ),
    ] {
        let app = format!(
            "package a;\n{static_import}\npublic class App extends Base {{\n  public static void main(String[] args) {{ new App().run(); }}\n  public void run() {{ wipe(); }}\n}}\n"
        );
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[
                ("src/main/java/a/Base.java", BASE),
                ("src/main/java/a/App.java", &app),
            ],
        );
        let got = effects(&root, "src/main/java/a/App.java");
        assert!(
            got.iter().any(|(operation, resource, origin)| {
                operation == "filesystem.delete"
                    && resource.contains("/base-wipe")
                    && origin.ends_with("Base.java")
            }),
            "{static_import} hid inherited wipe: {got:?}"
        );
    }
}

#[test]
fn inherited_method_requires_the_extends_edge() {
    let files = |extends: bool| {
        vec![
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App {\npublic static void main(String[] x) { new Child().run(); }\n}",
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
                "package a; import java.nio.file.Files; import java.nio.file.Path; public class Base { public void run() throws Exception { Files.delete(Path.of(\"/inherited\")); } }",
            ),
        ]
    };
    let positive = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "java-inheritance-positive",
        &files(true),
    );
    assert!(
        effects(&positive, "src/main/java/a/App.java")
            .iter()
            .any(|(operation, resource, _)| operation == "filesystem.delete"
                && resource.contains("/inherited"))
    );

    let negative = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "java-inheritance-negative",
        &files(false),
    );
    assert!(effects(&negative, "src/main/java/a/App.java").is_empty());
}

#[test]
fn generic_interface_dispatch_requires_nominal_implementation_evidence() {
    let files = |implements: bool| {
        vec![
            (
                "src/main/java/a/Worker.java",
                "package a; public interface Worker<T> { void run(T value); }",
            ),
            (
                "src/main/java/a/App.java",
                "package a;\npublic class App {\npublic static void main(String[] x) { Worker<String> worker; worker.run(\"x\"); }\n}",
            ),
            (
                "src/main/java/a/StringWorker.java",
                if implements {
                    "package a; import java.nio.file.Files; import java.nio.file.Path; public class StringWorker implements Worker<String> { public void run(String value) { try { Files.delete(Path.of(\"/generic\")); } catch (Exception e) {} } }"
                } else {
                    "package a; import java.nio.file.Files; import java.nio.file.Path; public class StringWorker { public void run(String value) { try { Files.delete(Path.of(\"/generic\")); } catch (Exception e) {} } }"
                },
            ),
        ]
    };
    let positive = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "java-generic-interface-positive",
        &files(true),
    );
    assert!(
        effects(&positive, "src/main/java/a/App.java")
            .iter()
            .any(|(operation, resource, _)| operation == "filesystem.delete"
                && resource.contains("/generic"))
    );

    let negative = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "java-generic-interface-negative",
        &files(false),
    );
    assert!(effects(&negative, "src/main/java/a/App.java").is_empty());
}

#[test]
fn gradle_source_layout_main_is_discovered() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "java-gradle-main",
        &[
            ("settings.gradle", "rootProject.name = 'app'\n"),
            (
                "src/main/java/app/Main.java",
                "package app;\npublic class Main {\npublic static void main(String[] a) { new java.io.File(\"/gradle\").delete(); }\n}",
            ),
        ],
    );
    assert!(
        effects(&root, "src/main/java/app/Main.java")
            .iter()
            .any(|(operation, resource, _)| operation == "filesystem.delete"
                && resource.contains("/gradle"))
    );
}
