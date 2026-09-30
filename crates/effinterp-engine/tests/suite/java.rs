use effinterp_engine::{
    ALL_DOMAINS, Engine, ExternalCall, Lang, ObjectIdentity, ScopeKey, classify_java_call,
    module_summaries,
};
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, ResourceExpr, ResourceFamily,
    ResourceIdentity, Subject, validate_plan,
};

fn java_module_summary(source: &str, lang: Lang) -> effinterp_engine::ModuleSummary {
    module_summaries(
        source,
        lang,
        "src/App.java",
        ScopeKey::Module {
            key: "src/App.java".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Java),
    )
}

#[test]
fn summaries_retain_control_and_call_slots() {
    let summary = java_module_summary(
        r#"import java.nio.file.Files; import java.nio.file.Path;
        class App {
            static void proof(boolean flag) throws Exception {
                Files.delete(Path.of("/before"));
                if (flag) { Files.delete(Path.of("/arm")); } else { Files.delete(Path.of("/arm")); }
                Other.helper(); Files.delete(Path.of("/after"));
            }
            static void never() throws Exception { Files.delete(Path.of("/never")); while (true) {} }
            static void leaf() throws Exception { Files.delete(Path.of("/local")); }
            static void local(boolean flag) throws Exception { leaf(); if (flag) { leaf(); } }
        }"#,
        Lang::Java,
    );
    let summary: effinterp_engine::ModuleSummary =
        serde_json::from_slice(&serde_json::to_vec(&summary).unwrap()).unwrap();
    let proof = summary
        .functions
        .iter()
        .find(|function| function.name == "App.proof")
        .unwrap();
    assert_eq!(proof.summary.effects.len(), 4);
    assert_eq!(proof.calls.len(), 1);
    for (returns, expected) in [
        (None, [true, false, false, false]),
        (
            Some(effinterp_engine::CallContract::from_flags(
                true, false, false,
            )),
            [true, false, false, true],
        ),
        (
            Some(effinterp_engine::CallContract::from_flags(
                false, false, false,
            )),
            [false; 4],
        ),
    ] {
        let required = proof.summary.control_flow.requirements(
            &mut |_| false,
            &mut |_| returns.clone(),
            &mut |_, _| true,
        );
        for (slot, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                required
                    .on_success
                    .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
                expected,
                "slot {slot}, return {returns:?}"
            );
        }
    }
    let never = summary
        .functions
        .iter()
        .find(|function| function.name == "App.never")
        .unwrap();
    let required =
        never
            .summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(!required.succeeds);
    assert!(required.on_success.is_empty());
    assert_eq!(never.summary.effects.len(), 1);
    let local = summary
        .functions
        .iter()
        .find(|function| function.name == "App.local")
        .unwrap();
    assert_eq!(local.summary.effects.len(), 2);
    let required =
        local
            .summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(
        required
            .on_success
            .contains(&effinterp_engine::ControlFact::Effect(0))
    );
    assert!(
        !required
            .on_success
            .contains(&effinterp_engine::ControlFact::Effect(1))
    );
    let initialized = java_module_summary(
        r#"import java.nio.file.Files; import java.nio.file.Path;
        class Initialized { static { Other.helper(); }
            static void run() throws Exception { Files.delete(Path.of("/initialized")); }
        }"#,
        Lang::Java,
    );
    let run = initialized
        .functions
        .iter()
        .find(|function| function.name == "Initialized.run")
        .unwrap();
    assert_eq!(run.summary.effects.len(), 1);
    let required =
        run.summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(required.on_success.is_empty());
}

fn analyze(code: &str) -> effinterp_proto::Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "java".into(),
            source: code.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}\ncode:\n{code}"));
    plan
}

fn ops(plan: &effinterp_proto::Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn deletes(plan: &effinterp_proto::Plan, path: &str) -> bool {
    plan.effects.iter().any(|e| {
        e.operation.0 == "filesystem.delete"
            && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)
    })
}

fn fs(path: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: path.to_string(),
        },
    }
}

fn effect_resource(plan: &effinterp_proto::Plan, operation: &str, resource: &ResourceExpr) -> bool {
    plan.effects
        .iter()
        .any(|effect| effect.operation.0 == operation && &effect.resource == resource)
}

const CLASS: &str = "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A {";

#[test]
fn required_deletes_need_a_proven_call_continuation() {
    for (body, expected) in [
        (
            "static void f() { Files.delete(Path.of(\"/tmp/out\")); }",
            effinterp_proto::Modality::MustOnSuccess,
        ),
        (
            "static void f() { f(); Files.delete(Path.of(\"/tmp/out\")); }",
            effinterp_proto::Modality::May,
        ),
        (
            "static void f() { g(); } static void g() { f(); Files.delete(Path.of(\"/tmp/out\")); }",
            effinterp_proto::Modality::May,
        ),
    ] {
        let plan = analyze(&format!(
            "{CLASS} public static void main(String[] args) {{ f(); }} {body} }}"
        ));
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert!(!effects.is_empty(), "possible deletes must survive: {body}");
        assert!(
            effects.iter().all(|effect| effect.modality == expected),
            "unproved recursive return cannot establish necessity: {body}"
        );
        if expected == effinterp_proto::Modality::May {
            assert!(plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::RECURSIVE_CALL
            }));
        }
    }

    let mut deep = format!(
        "{CLASS} public static void main(String[] args) {{ f0(); Files.delete(Path.of(\"/tmp/out\")); }}"
    );
    for i in 0..65 {
        deep.push_str(&format!("static void f{i}() {{ f{}(); }}", i + 1));
    }
    deep.push_str("static void f65() {} }");
    let plan = analyze(&deep);
    let effect = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("the possible delete after the bounded call must survive");
    assert_eq!(effect.modality, effinterp_proto::Modality::May);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::LIMIT_SATURATED
            && boundary.limit.as_deref() == Some("max_java_call_depth")
    }));
}

#[test]
fn no_entry_point_distinguishes_unreached_java_callables() {
    let declarations = "import java.nio.file.Files; import java.nio.file.Path; class Storage { void sweep() { Files.delete(Path.of(\"/tmp/storage\")); } }";
    let plan = analyze(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only Java has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some("no execution root reached; declared callables not executed: Storage.sweep")
    );
    for domain in [
        "environment",
        "filesystem",
        "network",
        "process",
        "database",
    ] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }

    let reached = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; class Storage { void sweep() { Files.delete(Path.of(\"/tmp/reached\")); } public static void main(String[] args) { new Storage().sweep(); } }",
    );
    assert!(deletes(&reached, "/tmp/reached"));
    assert!(
        reached
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let executed = analyze(
        "class App { void stale() { new java.io.File(\"/stale\").delete(); } public static void main(String[] args) { new java.io.File(\"/top\").delete(); } }",
    );
    assert!(deletes(&executed, "/top"));
    assert!(
        executed
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
    assert!(
        analyze("")
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
}

#[test]
fn only_path_receivers_form_filesystem_joins() {
    for source in [
        "import java.nio.file.Files; import java.nio.file.Path; import java.util.Map; public class A { public static void main(String[] args) throws Exception { Map cfg = null; Files.delete(Path.of(cfg.get(\"cache\"))); } }",
        "import java.nio.file.Files; import java.nio.file.Path; import java.util.Properties; public class A { public static void main(String[] args) throws Exception { Properties cfg = null; Files.delete(Path.of(cfg.get(\"cache\"))); } }",
        "import java.nio.file.Files; import java.nio.file.Path; import java.util.Map; public class A { public static void main(String[] args) throws Exception { Map<String, String> cfg = null; String path = cfg.get(\"cache\"); Files.delete(Path.of(path)); } }",
    ] {
        let plan = analyze(source);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete");
        assert!(
            matches!(
                &delete.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            ),
            "{source}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn file_parent_and_child_are_both_retained() {
    let plan = analyze(
        "import java.io.File; public class A { public static void main(String[] args) { new File(\"/tmp/d\", \"child.txt\").delete(); } }",
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("filesystem delete");
    assert_eq!(delete.resource, fs("/tmp/d/child.txt"));
}

#[test]
fn files_copy_does_not_read_an_input_stream_as_a_path() {
    for call in ["Files.copy", "copy"] {
        let plan = analyze(&format!(
            "import static java.nio.file.Files.copy; import java.io.InputStream; import java.net.URL; import java.nio.file.Files; import java.nio.file.Paths; public class A {{ public static void main(String[] args) throws Exception {{ InputStream in = new URL(\"https://example.com/x\").openStream(); {call}(in, Paths.get(\"/opt/tool/x\")); }} }}",
        ));
        assert!(effect_resource(
            &plan,
            "filesystem.write",
            &fs("/opt/tool/x")
        ));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{:?}",
            plan.effects
        );
    }
}

#[test]
fn local_overloads_are_followed_by_arity() {
    let plan = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; public class A { static void rm(String path) throws Exception { Files.delete(Path.of(path)); } static void rm(String path, boolean force) throws Exception { Files.delete(Path.of(\"/wrong\")); } public static void main(String[] args) throws Exception { rm(\"/one\"); } }",
    );
    assert!(deletes(&plan, "/one"), "{:?}", plan.effects);
    assert!(!deletes(&plan, "/wrong"), "{:?}", plan.effects);

    for arguments in ["\"/one\"", "\"/one\", true, false"] {
        let plan = analyze(&format!(
            "import java.nio.file.Files; import java.nio.file.Path; public class A {{ static void rm(String path, boolean... flags) throws Exception {{ Files.delete(Path.of(path)); }} static void rm(String path, boolean force) throws Exception {{ Files.delete(Path.of(\"/wrong\")); }} public static void main(String[] args) throws Exception {{ rm({arguments}); }} }}",
        ));
        assert!(deletes(&plan, "/one"), "{arguments}: {:?}", plan.effects);
        assert!(!deletes(&plan, "/wrong"), "{arguments}: {:?}", plan.effects);
    }

    let unmatched = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; public class A { static void rm(String path) throws Exception { Files.delete(Path.of(\"/first\")); } static void rm(String path, boolean force) throws Exception { Files.delete(Path.of(\"/second\")); } public static void main(String[] args) throws Exception { rm(); } }",
    );
    for path in ["/first", "/second"] {
        assert!(deletes(&unmatched, path), "{:?}", unmatched.effects);
    }
}

// Regression: framework containers invoke these methods without a Java call
// expression in the source file.
#[test]
fn framework_annotations_and_bases_create_execution_roots() {
    let cases = [
        "import org.junit.jupiter.api.Test; class Check { @Test void verifies() { new java.io.File(\"/test\").delete(); } }",
        "import org.gradle.api.tasks.TaskAction; class Build { @TaskAction void build() { new java.io.File(\"/task\").delete(); } }",
        "import org.springframework.scheduling.annotation.Scheduled; class Job { @Scheduled void sweep() { new java.io.File(\"/scheduled\").delete(); } }",
        "import jakarta.annotation.PostConstruct; class Service { @PostConstruct void start() { new java.io.File(\"/post-construct\").delete(); } }",
        "import org.apache.maven.plugin.AbstractMojo; class Build extends AbstractMojo { public void execute() { new java.io.File(\"/mojo\").delete(); } }",
        "import picocli.CommandLine.Command; import java.util.concurrent.Callable; @Command class Cli implements Callable<Integer> { public Integer call() { new java.io.File(\"/picocli\").delete(); return 0; } }",
        "import org.bukkit.plugin.java.JavaPlugin; class Plugin extends JavaPlugin { public void onEnable() { new java.io.File(\"/plugin\").delete(); } }",
        "import org.springframework.boot.CommandLineRunner; class Startup implements CommandLineRunner { public void run(String... args) { new java.io.File(\"/runner\").delete(); } }",
        "import org.springframework.boot.ApplicationRunner; class Startup implements ApplicationRunner { public void run(Object args) { new java.io.File(\"/application-runner\").delete(); } }",
    ];
    for (source, path) in cases.into_iter().zip([
        "/test",
        "/task",
        "/scheduled",
        "/post-construct",
        "/mojo",
        "/picocli",
        "/plugin",
        "/runner",
        "/application-runner",
    ]) {
        let plan = analyze(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && match &effect.resource {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: actual },
                        } => actual == path,
                        ResourceExpr::Parameter { name } => format!("<{name}>") == path,
                        _ => false,
                    }
            }),
            "missing {path}: {plan:?}"
        );
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.reason.as_str() != "no_entry_point")
        );
    }

    let shadowed = analyze(
        "@interface Scheduled {} class Job { @Scheduled void sweep() { new java.io.File(\"/dormant\").delete(); } }",
    );
    assert!(shadowed.effects.is_empty());
    assert!(
        shadowed
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "no_entry_point")
    );
}

#[test]
fn files_delete_in_main() {
    let plan = analyze(&format!(
        "{CLASS} public static void main(String[] a) {{ Files.deleteIfExists(Path.of(\"/data\")); }} }}"
    ));
    assert!(deletes(&plan, "/data"), "ops={:?}", ops(&plan));
}

#[test]
fn runtime_exec_nests_shell() {
    let plan = analyze(
        "public class A { public static void main(String[] a) throws Exception { Runtime.getRuntime().exec(\"rm -rf /tmp/x\"); } }",
    );
    assert!(ops(&plan).contains(&"process.exec"), "ops={:?}", ops(&plan));
    assert!(
        deletes(&plan, "/tmp/x"),
        "nested rm delete; ops={:?}",
        ops(&plan)
    );
}

#[test]
fn process_builder_nests_exec() {
    let plan = analyze(
        "public class A { public static void main(String[] a) throws Exception { new ProcessBuilder(\"rm\", \"-rf\", \"/tmp/y\").start(); } }",
    );
    assert!(deletes(&plan, "/tmp/y"), "ops={:?}", ops(&plan));
}

#[test]
fn jdbc_execute_nests_sql() {
    let plan = analyze(
        "import java.sql.Statement; public class A { public static void main(String[] a) throws Exception { Statement s = null; s.executeUpdate(\"DELETE FROM users\"); } }",
    );
    assert!(
        ops(&plan).contains(&"database.write"),
        "ops={:?}",
        ops(&plan)
    );
}

#[test]
fn uncalled_method_is_not_executed() {
    let plan = analyze(&format!(
        "{CLASS} public static void main(String[] a) {{ System.out.println(\"hi\"); }} static void danger() {{ try {{ Files.delete(Path.of(\"/important\")); }} catch (Exception e) {{}} }} }}"
    ));
    assert!(
        !deletes(&plan, "/important"),
        "uncalled danger() must not execute; ops={:?}",
        ops(&plan)
    );
}

#[test]
fn helper_call_substitutes_argument() {
    let plan = analyze(&format!(
        "{CLASS} public static void main(String[] a) throws Exception {{ wipe(Path.of(\"/var/cache\")); }} static void wipe(Path p) throws Exception {{ Files.delete(p); }} }}"
    ));
    assert!(
        deletes(&plan, "/var/cache"),
        "arg substituted through wipe; ops={:?}",
        ops(&plan)
    );
}

#[test]
fn java_locals_formats_arrays_and_environment_values_flow_to_filesystem_sinks() {
    let plan = analyze(
        "import java.io.File; import java.io.FileInputStream; import java.nio.file.Files; import java.nio.file.Path; import java.nio.file.Paths; public class A { public static void main(String[] args) throws Exception { String p = \"/tmp/x\"; Files.delete(Path.of(p)); final Path out = Paths.get(\"/var/reports\", \"daily.txt\"); Files.newBufferedWriter(out); String formatted = String.format(\"%s/build/%s\", \"/srv\", \"out\"); Files.delete(Path.of(formatted)); String[] paths = {\"/x\", \"/y\"}; new File(paths[0]).delete(); new File(paths[args.length]).delete(); new FileInputStream(System.getenv(\"KEYSTORE_PATH\")); String home = System.getProperty(\"user.home\"); Files.delete(Path.of(home + \"/.cache/tool\")); } }",
    );
    for path in ["/tmp/x", "/var/reports/daily.txt", "/srv/build/out", "/x"] {
        assert!(
            plan.effects.iter().any(|effect| {
                matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)
            }),
            "missing local value {path}: {:?}",
            plan.effects
        );
    }
    assert!(effect_resource(
        &plan,
        "filesystem.delete",
        &ResourceExpr::Union {
            alternatives: vec![fs("/x"), fs("/y")],
        }
    ));
    assert!(effect_resource(
        &plan,
        "filesystem.read",
        &ResourceExpr::Environment {
            name: "KEYSTORE_PATH".to_string(),
        }
    ));
    assert!(effect_resource(
        &plan,
        "filesystem.delete",
        &ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Environment {
                    name: "user.home".to_string(),
                },
                fs("/.cache/tool"),
            ],
        }
    ));
}

#[test]
fn reassigned_and_unsupported_formatted_locals_emit_dynamic_giveup_boundaries() {
    let plan = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; public class A { public static void main(String[] args) throws Exception { String p = \"/first\"; if (args.length > 0) { p = \"/second\"; } Files.delete(Path.of(p)); String padded = String.format(\"%08d\", args.length); Files.delete(Path.of(padded)); } }",
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && effect.resource
                        == ResourceExpr::Unresolved {
                            family: ResourceFamily::new("filesystem"),
                        }
            })
            .count(),
        2
    );
    let giveups: Vec<_> = plan
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
        .collect();
    assert_eq!(giveups.len(), 2);
    assert!(giveups.iter().all(|boundary| {
        boundary.class == BoundaryClass::Unresolved
            && boundary.affected_resource
                == Some(ResourceExpr::Unresolved {
                    family: ResourceFamily::new("filesystem"),
                })
    }));
}

#[test]
fn assigned_array_elements_poison_tracked_values_in_plans_and_summaries() {
    let source = "import java.io.File; public class A { static void wipe() { final String[] paths = {\"/x\", \"/y\"}; paths[0] = \"/danger\"; new File(paths[0]).delete(); } public static void main(String[] args) { wipe(); } }";
    let plan = analyze(source);
    assert!(effect_resource(
        &plan,
        "filesystem.delete",
        &unresolved_fs()
    ));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );

    let summary = java_module_summary(source, Lang::Java);
    let wipe = summary
        .functions
        .iter()
        .find(|function| function.name == "A.wipe")
        .unwrap();
    assert!(wipe.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && effect.resource == unresolved_fs()
    }));
    assert_eq!(
        wipe.summary
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn nested_array_element_assignments_poison_tracked_values_in_plans_and_summaries() {
    for source in [
        "import java.io.File; public class A { static void wipe() { final String[] paths = {\"/x\", \"/y\"}; Runnable mutation = () -> { paths[0] = \"/danger\"; }; mutation.run(); new File(paths[0]).delete(); } public static void main(String[] args) { wipe(); } }",
        "import java.io.File; public class A { static void wipe() { final String[] paths = {\"/x\", \"/y\"}; Runnable mutation = new Runnable() { public void run() { paths[0] = \"/danger\"; } }; mutation.run(); new File(paths[0]).delete(); } public static void main(String[] args) { wipe(); } }",
    ] {
        let plan = analyze(source);
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].resource, unresolved_fs());
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            1
        );

        let summary = java_module_summary(source, Lang::Java);
        let wipe = summary
            .functions
            .iter()
            .find(|function| function.name == "A.wipe")
            .unwrap();
        let deletes: Vec<_> = wipe
            .summary
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].resource, unresolved_fs());
        assert_eq!(
            wipe.summary
                .boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            1
        );
    }
}

#[test]
fn unsupported_creation_arities_and_collection_calls_stay_symbolic() {
    let plan = analyze(
        "import java.io.File; import java.net.URL; import java.nio.file.Files; import java.nio.file.Path; import java.util.List; import java.util.Map; import java.util.Optional; public class A { public static void main(String[] args) throws Exception { File file = new File(\"/var\", \"tmp\"); file.delete(); URL url = new URL(\"https://api.example.com/base\", \"/health\"); url.openStream(); Map<String, String> values = null; String mapValue = values.get(\"key\"); Files.delete(Path.of(mapValue)); var listValue = List.of(\"/tmp/x\", \"/tmp/y\"); Files.delete(Path.of(listValue)); String optionalValue = Optional.of(\"/tmp/z\").get(); Files.delete(Path.of(optionalValue)); } }",
    );
    assert!(effect_resource(&plan, "filesystem.delete", &fs("/var/tmp")));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(effect.resource, ResourceExpr::Unresolved { .. })
            })
            .count(),
        3
    );
    assert!(effect_resource(
        &plan,
        "network.request",
        &ResourceExpr::Parameter {
            name: "url".to_string(),
        }
    ));
}

#[test]
fn constructor_arguments_flow_into_stable_instance_fields() {
    let plan = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; import java.nio.file.Paths; class Store { private final Path root; private final Path index; Store(Path root) { this.root = root; this.index = root.resolve(\"index.db\"); } void purge() throws Exception { Files.delete(index); Files.readAllBytes(root.resolve(\"blobs\")); } } public class A { public static void main(String[] args) throws Exception { String home = System.getenv(\"HOME\"); new Store(Paths.get(home, \".acme\")).purge(); Store store = new Store(Paths.get(\"/srv/acme\")); store.purge(); } }",
    );
    assert!(effect_resource(
        &plan,
        "filesystem.delete",
        &ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Environment {
                    name: "HOME".to_string(),
                },
                fs(".acme"),
                fs("index.db"),
            ],
        }
    ));
    assert!(effect_resource(
        &plan,
        "filesystem.read",
        &ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Environment {
                    name: "HOME".to_string(),
                },
                fs(".acme"),
                fs("blobs"),
            ],
        }
    ));
    assert!(deletes(&plan, "/srv/acme/index.db"));
    assert!(effect_resource(
        &plan,
        "filesystem.read",
        &fs("/srv/acme/blobs")
    ));
}

#[test]
fn constructor_site_is_rebound_for_each_method_execution() {
    let plan = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; class Store { private final Path root; Store(Path root) throws Exception { this.root = root; Files.createDirectories(root); } void purge() throws Exception { Files.delete(root); } } public class A { static void run(Path root) throws Exception { new Store(root).purge(); } public static void main(String[] args) throws Exception { run(Path.of(\"/a\")); run(Path.of(\"/b\")); } }",
    );
    for path in ["/a", "/b"] {
        assert!(effect_resource(&plan, "filesystem.create", &fs(path)));
        assert!(effect_resource(&plan, "filesystem.delete", &fs(path)));
    }
}

#[test]
fn guarded_constructor_field_assignments_give_up_in_plans_and_summaries() {
    let source = "import java.nio.file.Files; import java.nio.file.Path; class Cache { private final Path dir; Cache(String override) { if (override == null) { this.dir = Path.of(\"/var/cache/app\"); } else { this.dir = Path.of(\"/tmp/override\"); } } void clear() throws Exception { Files.delete(dir); } } public class A { public static void main(String[] args) throws Exception { new Cache(null).clear(); } }";
    let plan = analyze(source);
    assert!(effect_resource(
        &plan,
        "filesystem.delete",
        &unresolved_fs()
    ));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );

    let summary = java_module_summary(source, Lang::Java);
    let clear = summary
        .functions
        .iter()
        .find(|function| function.name == "Cache.clear")
        .unwrap();
    assert!(clear.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && effect.resource == unresolved_fs()
    }));
    assert_eq!(
        clear
            .summary
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn fields_mutated_outside_the_constructor_are_not_treated_as_stable_values() {
    let plan = analyze(
        "import java.nio.file.Files; import java.nio.file.Path; class Store { private Path index; Store(Path index) { this.index = index; } void reset(Path index) { this.index = index; } void purge() throws Exception { Files.delete(index); } } public class A { public static void main(String[] args) throws Exception { new Store(Path.of(\"/old\")).purge(); } }",
    );
    assert!(effect_resource(
        &plan,
        "filesystem.delete",
        &ResourceExpr::Parameter {
            name: "index".to_string(),
        }
    ));
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "unmodeled_dynamic")
    );
}

#[test]
fn enhanced_for_file_elements_retain_their_parent_directory() {
    let plan = analyze(
        "import java.io.File; import java.nio.file.Files; import java.nio.file.Path; public class A { public static void main(String[] args) throws Exception { File dir = new File(\"/var/tmp/acme\"); for (File file : dir.listFiles()) { file.delete(); } for (Path path : Files.list(Path.of(\"/var/cache/acme\")).toList()) { Files.delete(path); } Files.walk(Path.of(\"/srv/tree\")).forEach(path -> { try { Files.delete(path); } catch (Exception ignored) {} }); } }",
    );
    for directory in ["/var/tmp/acme", "/var/cache/acme", "/srv/tree"] {
        assert!(effect_resource(
            &plan,
            "filesystem.delete",
            &ResourceExpr::Join {
                parts: vec![fs(directory), unresolved_fs()],
            }
        ));
    }
    assert!(effect_resource(
        &plan,
        "filesystem.read",
        &fs("/var/tmp/acme")
    ));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "external_unmodeled")
            .count(),
        1,
        "{:?}",
        plan.boundaries
    );
}

fn unresolved_fs() -> ResourceExpr {
    ResourceExpr::Unresolved {
        family: ResourceFamily::new("filesystem"),
    }
}

#[test]
fn java_url_and_http_client_sinks_keep_endpoint_text_and_verbs() {
    let plan = analyze(
        "import java.net.HttpURLConnection; import java.net.URI; import java.net.URL; import java.net.http.HttpClient; import java.net.http.HttpRequest; import java.net.http.HttpResponse.BodyHandlers; import java.nio.file.Path; public class A { public static void main(String[] args) throws Exception { HttpURLConnection request = (HttpURLConnection) new URL(\"https://api.example.com/v1/items\").openConnection(); request.setRequestMethod(\"DELETE\"); HttpURLConnection upload = (HttpURLConnection) new URL(\"https://api.example.com/v1/upload\").openConnection(); upload.setRequestMethod(\"POST\"); HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(\"https://api.example.com/upload\")).POST(HttpRequest.BodyPublishers.ofString(\"x\")).build(), BodyHandlers.ofFile(Path.of(\"/tmp/out.bin\"))); String base = \"https://api.example.com\"; new URL(base + \"/health\").openStream(); } }",
    );
    let endpoint = |path: &str| ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host: "api.example.com".to_string(),
            scheme: Some("https".to_string()),
            port: None,
            path: Some(path.to_string()),
        },
    };
    assert!(effect_resource(
        &plan,
        "network.request",
        &endpoint("/v1/items")
    ));
    assert!(effect_resource(
        &plan,
        "network.upload",
        &endpoint("/v1/upload")
    ));
    assert!(effect_resource(
        &plan,
        "network.upload",
        &endpoint("/upload")
    ));
    assert!(effect_resource(
        &plan,
        "network.request",
        &endpoint("/health")
    ));
    assert!(effect_resource(
        &plan,
        "filesystem.write",
        &fs("/tmp/out.bin")
    ));
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "external_unmodeled")
    );
}

#[test]
fn java_summary_locals_keep_resolved_values() {
    let summary = java_module_summary(
        "import java.nio.file.Files; import java.nio.file.Path; public class A { static void wipe() throws Exception { String path = \"/summary\"; Files.delete(Path.of(path)); } }",
        Lang::Java,
    );
    let wipe = summary
        .functions
        .iter()
        .find(|function| function.name == "A.wipe")
        .unwrap();
    assert!(wipe.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && effect.resource == fs("/summary")
    }));

    let summary = java_module_summary(
        "import java.nio.file.Files; import java.nio.file.Path; class Store { private final Path root; private final Path index; Store(Path root) { this.root = root; this.index = root.resolve(\"index.db\"); } void purge() throws Exception { Files.delete(index); } }",
        Lang::Java,
    );
    let store = summary
        .classes
        .iter()
        .find(|class| class.name == "Store")
        .unwrap();
    assert!(
        store
            .attr_params
            .contains(&("root".to_string(), "root".to_string()))
    );
    let purge = summary
        .functions
        .iter()
        .find(|function| function.name == "Store.purge")
        .unwrap();
    assert!(purge.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.resource
                == ResourceExpr::Parameter {
                    name: "index".to_string(),
                }
    }));

    let summary = java_module_summary(
        "import java.nio.file.Files; import java.nio.file.Path; import java.util.List; import java.util.Map; import java.util.Optional; public class A { static void wipe(Map<String, String> values) throws Exception { String mapValue = values.get(\"key\"); Files.delete(Path.of(mapValue)); var listValue = List.of(\"/tmp/x\", \"/tmp/y\"); Files.delete(Path.of(listValue)); String optionalValue = Optional.of(\"/tmp/z\").get(); Files.delete(Path.of(optionalValue)); } }",
        Lang::Java,
    );
    let wipe = summary
        .functions
        .iter()
        .find(|function| function.name == "A.wipe")
        .unwrap();
    assert_eq!(
        wipe.summary
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(effect.resource, ResourceExpr::Unresolved { .. })
            })
            .count(),
        3
    );
}

#[test]
fn java_summary_constructor_fields_do_not_alias_method_parameters() {
    let summary = java_module_summary(
        "import java.nio.file.Files; import java.nio.file.Path; class Store { private final Path index; Store(Path root) { this.index = root.resolve(\"i.db\"); } void purge(Path root) throws Exception { Files.delete(index); } }",
        Lang::Java,
    );
    let purge = summary
        .functions
        .iter()
        .find(|function| function.name == "Store.purge")
        .unwrap();
    let deletes: Vec<_> = purge
        .summary
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(|effect| effect.resource.clone())
        .collect();
    assert_eq!(
        deletes,
        vec![ResourceExpr::Parameter {
            name: "index".to_string(),
        }]
    );
}

#[test]
fn java_summary_constructor_fields_do_not_alias_same_class_caller_parameters() {
    let summary = java_module_summary(
        "import java.nio.file.Files; import java.nio.file.Path; class Store { private final Path index; Store(Path root) { this.index = root.resolve(\"i.db\"); } void purge() throws Exception { Files.delete(index); } void run(Path root) throws Exception { purge(); } }",
        Lang::Java,
    );
    for method in ["Store.purge", "Store.run"] {
        let function = summary
            .functions
            .iter()
            .find(|function| function.name == method)
            .unwrap();
        let deletes: Vec<_> = function
            .summary
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| effect.resource.clone())
            .collect();
        assert_eq!(
            deletes,
            vec![ResourceExpr::Parameter {
                name: "index".to_string(),
            }],
            "{method}"
        );
    }
}

#[test]
fn malformed_source_is_a_boundary_not_a_panic() {
    let plan = analyze("this is not { valid java )(");
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| {
            boundary.reason.as_str() == "parse_error"
                && boundary.class == BoundaryClass::ParseFailure
        })
        .expect("malformed Java carries parse uncertainty");
    assert!(!boundary.domains.is_empty());
    for domain in &boundary.domains {
        assert_ne!(
            plan.coverage.0.get(domain).map(|claim| &claim.level),
            Some(&CoverageLevel::Full),
            "parse-affected domain {domain:?} remained full"
        );
    }
    assert!(
        plan.effects
            .iter()
            .all(|e| e.operation.0 != "filesystem.delete")
    );
    let damaged_class = "class App { String path; } )";
    assert!(analyze(damaged_class).boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "parse_error" && boundary.class == BoundaryClass::ParseFailure
    }));
    assert!(
        java_module_summary(damaged_class, Lang::Java)
            .classes
            .iter()
            .any(|class| class.name == "App")
    );
}

#[test]
fn deterministic() {
    let code = format!(
        "{CLASS} public static void main(String[] a) throws Exception {{ Files.delete(Path.of(\"/x\")); Files.write(Path.of(\"/y\")); }} }}"
    );
    let a = effinterp_proto::canonical_json(&analyze(&code));
    let b = effinterp_proto::canonical_json(&analyze(&code));
    assert_eq!(a, b);
}

#[test]
fn module_summaries_expose_parameterized_effect() {
    // A helper's summary references its parameter, ready for cross-file
    // argument substitution.
    let code =
        format!("{CLASS} static void wipe(Path p) throws Exception {{ Files.delete(p); }} }}");
    let plan = analyze(&code);
    // main-less class: execution yields no delete, but it is a valid plan.
    validate_plan(&plan).unwrap();
    assert!(!deletes(&plan, "anything"));
}

/// `System.getProperty` reads a JVM property, not a process environment
/// variable: same environment family, distinguished by the `jvm_property`
/// attribute. `System.getenv` stays unmarked.
#[test]
fn get_property_is_marked_jvm_property() {
    let plan = analyze(
        "public class A { public static void main(String[] a) { System.getProperty(\"os.version\"); System.getenv(\"HOME\"); } }",
    );
    let attr_of = |name: &str| {
        plan.effects
            .iter()
            .find(|e| {
                matches!(&e.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: actual }
            } if actual == name)
            })
            .map(|e| e.attributes.get("jvm_property").cloned())
            .unwrap_or_else(|| panic!("no environment effect for {name}"))
    };
    assert_eq!(
        attr_of("os.version"),
        Some(effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(attr_of("HOME"), None);
}

#[test]
fn property_mutations_are_environment_writes() {
    let source = "public class A { static void configure() { System.setProperty(\"java.io.tmpdir\", \"/x\"); System.clearProperty(\"legacy.key\"); } public static void main(String[] a) { configure(); } }";
    let plan = analyze(source);
    fn effect_for<'a>(
        effects: &'a [effinterp_proto::Effect],
        name: &str,
    ) -> &'a effinterp_proto::Effect {
        effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "environment.write"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name: actual }
                    } if actual == name)
            })
            .unwrap_or_else(|| panic!("no environment write for {name}"))
    }
    let set = effect_for(&plan.effects, "java.io.tmpdir");
    assert_eq!(
        set.attributes.get("jvm_property"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(!set.attributes.contains_key("unset"));
    let clear = effect_for(&plan.effects, "legacy.key");
    for attribute in ["jvm_property", "unset"] {
        assert_eq!(
            clear.attributes.get(attribute),
            Some(&effinterp_proto::AttrValue::Bool(true))
        );
    }

    let summary = java_module_summary(source, Lang::Java);
    let configure = summary
        .functions
        .iter()
        .find(|function| function.name == "A.configure")
        .unwrap();
    assert!(["java.io.tmpdir", "legacy.key"].iter().all(|name| {
        effect_for(&configure.summary.effects, name)
            .attributes
            .contains_key("jvm_property")
    }));
}

#[test]
fn nonliteral_and_empty_environment_names_widen_to_the_environment_family() {
    for argument in ["args[0]", "\"\""] {
        let plan = analyze(&format!(
            "public class A {{ public static void main(String[] args) {{ System.getenv({argument}); }} }}"
        ));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "environment")
        }));
    }
}

/// Stat-flavored `Files`/`File` probes are metadata reads (the fsutils
/// ls/stat attribute); content reads stay unmarked.
#[test]
fn stat_flavored_reads_carry_metadata_attribute() {
    let plan = analyze(&format!(
        "{CLASS} public static void main(String[] a) throws Exception {{ Files.exists(Path.of(\"/p\")); Files.readAllBytes(Path.of(\"/q\")); }} }}"
    ));
    let read_attr = |path: &str| {
        plan.effects
            .iter()
            .find(|e| {
                e.operation.0 == "filesystem.read"
                    && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)
            })
            .map(|e| e.attributes.get("metadata").cloned())
            .unwrap_or_else(|| panic!("no read of {path}"))
    };
    assert_eq!(
        read_attr("/p"),
        Some(effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(read_attr("/q"), None);
}

/// Left-deep `+` chains are one CST node per operator. Recursive walks used
/// to overflow the process stack around 20k concatenations — before the node
/// cap could fire — which is how checkstyle's string-concat fixture aborted
/// the first hidden evaluation.
fn java_concat_source(ops: usize) -> String {
    let mut src = String::from(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A { public static void main(String[] a) throws Exception { Files.delete(Path.of(\"/data\")); String s = \"x\"",
    );
    for _ in 0..ops {
        src.push_str(" + \"x\"");
    }
    src.push_str("; } }\n");
    src
}

#[test]
fn deep_string_concat_does_not_overflow_analyze() {
    let plan = analyze(&java_concat_source(25_000));
    assert!(deletes(&plan, "/data"), "ops={:?}", ops(&plan));
}

#[test]
fn deep_string_concat_does_not_overflow_summaries() {
    let _ = java_module_summary(&java_concat_source(25_000), Lang::Java);
}

#[test]
fn exhausted_java_analysis_weakens_every_domain() {
    let mut limits = effinterp_engine::default_limits();
    limits.insert("max_java_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&Subject::Source {
            dialect: None,
            language: "java".into(),
            source: "public class A { public static void main(String[] a) { int x = 1; } }".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "partial_analysis")
        .expect("the exhausted walk stays explicit");
    let affected: std::collections::BTreeSet<&str> = boundary
        .domains
        .iter()
        .map(|domain| domain.0.as_str())
        .collect();
    let expected: std::collections::BTreeSet<&str> = ALL_DOMAINS.iter().copied().collect();
    assert_eq!(affected, expected);
    for domain in ALL_DOMAINS {
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new(*domain))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Partial),
            "missing partial coverage for {domain}"
        );
    }
}

#[test]
fn invoked_lambdas_and_method_references_execute_but_stored_lambdas_do_not() {
    let plan = analyze(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\nimport java.util.stream.Stream;\npublic class A {\n  static void wipe() throws Exception { Files.delete(Path.of(\"/method-ref\")); }\n  public static void main(String[] a) {\n    Runnable dormant = () -> { try { Files.delete(Path.of(\"/dormant\")); } catch (Exception e) {} };\n    Runnable active = () -> { try { Files.delete(Path.of(\"/active\")); } catch (Exception e) {} };\n    active.run();\n    Stream.of(1).forEach(value -> { try { Files.delete(Path.of(\"/lambda\")); } catch (Exception e) {} });\n    Stream.of(1).forEach(value -> wipe());\n    Stream.of(1).forEach(A::wipe);\n  }\n}\n",
    );
    for path in ["/active", "/lambda", "/method-ref"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }
    assert!(!deletes(&plan, "/dormant"), "stored lambda ran eagerly");
}

#[test]
fn mutually_recursive_lambdas_terminate_in_live_and_summary_analysis() {
    let source = "public class A { public static void main(String[] args) { Runnable left = () -> { new java.io.File(\"/left\").delete(); right.run(); }; Runnable right = () -> { new java.io.File(\"/right\").delete(); left.run(); }; left.run(); } }";
    let plan = analyze(source);
    for path in ["/left", "/right"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }
    let _ = java_module_summary(source, Lang::Java);
}

#[test]
fn lambda_rebinding_replaces_the_previous_callback() {
    let source = "public class A { static void run() { Runnable callback = () -> new java.io.File(\"/stale\").delete(); callback = () -> new java.io.File(\"/active\").delete(); callback.run(); } public static void main(String[] args) { run(); } }";
    let plan = analyze(source);
    assert!(deletes(&plan, "/active"), "ops={:?}", ops(&plan));
    assert!(!deletes(&plan, "/stale"), "ops={:?}", ops(&plan));

    let summary = java_module_summary(source, Lang::Java);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "A.run")
        .unwrap();
    assert!(run.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/active")
    }));
    assert!(!run.summary.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/stale")
    }));
}

#[test]
fn guarded_rebindings_preserve_every_reachable_callback_and_receiver() {
    let source = "class Base { void act() {} } class First extends Base { void act() { new java.io.File(\"/receiver-first\").delete(); } } class Second extends Base { void act() { new java.io.File(\"/receiver-second\").delete(); } } class A { static void run(String[] args) { Runnable callback = () -> new java.io.File(\"/callback-first\").delete(); if (args.length > 0) { callback = () -> new java.io.File(\"/callback-second\").delete(); } else { callback = () -> new java.io.File(\"/callback-third\").delete(); } callback.run(); Runnable looped = () -> new java.io.File(\"/loop-first\").delete(); for (String arg : args) { looped = () -> new java.io.File(\"/loop-second\").delete(); } looped.run(); Base receiver = new First(); if (args.length > 0) { receiver = new Second(); } receiver.act(); } public static void main(String[] args) { run(args); } }";
    let plan = analyze(source);
    for path in [
        "/callback-first",
        "/callback-second",
        "/callback-third",
        "/loop-first",
        "/loop-second",
        "/receiver-first",
        "/receiver-second",
    ] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }

    let summary = java_module_summary(source, Lang::Java);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "A.run")
        .unwrap();
    for path in [
        "/callback-first",
        "/callback-second",
        "/callback-third",
        "/loop-first",
        "/loop-second",
    ] {
        assert!(run.summary.effects.iter().any(|effect| {
            matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)
        }), "missing summary effect {path}: {:?}", run.summary.effects);
    }
    let receiver_classes: Vec<&str> = run
        .calls
        .iter()
        .filter(|edge| edge.callee == "receiver.act")
        .filter_map(|edge| match edge.receiver_identity() {
            Some(ObjectIdentity::Class { name, .. }) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(receiver_classes.contains(&"First"), "{receiver_classes:?}");
    assert!(receiver_classes.contains(&"Second"), "{receiver_classes:?}");
}

#[test]
fn exception_guarded_rebindings_preserve_every_reachable_candidate() {
    let source = "class Base { void act() {} } class First extends Base { void act() { new java.io.File(\"/receiver-first\").delete(); } } class Second extends Base { void act() { new java.io.File(\"/receiver-second\").delete(); } } class Third extends Base { void act() { new java.io.File(\"/receiver-third\").delete(); } } class Fourth extends Base { void act() { new java.io.File(\"/receiver-fourth\").delete(); } } class A { static void run(String[] args) { Runnable callback = () -> new java.io.File(\"/callback-first\").delete(); try { callback = () -> new java.io.File(\"/callback-second\").delete(); } catch (RuntimeException error) { callback = () -> new java.io.File(\"/callback-third\").delete(); } finally { callback = () -> new java.io.File(\"/callback-fourth\").delete(); } callback.run(); Base receiver = new First(); try { receiver = new Second(); } catch (RuntimeException error) { receiver = new Third(); } finally { receiver = new Fourth(); } receiver.act(); } public static void main(String[] args) { run(args); } }";
    let plan = analyze(source);
    for path in [
        "/callback-first",
        "/callback-second",
        "/callback-third",
        "/callback-fourth",
        "/receiver-first",
        "/receiver-second",
        "/receiver-third",
        "/receiver-fourth",
    ] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }

    let summary = java_module_summary(source, Lang::Java);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "A.run")
        .unwrap();
    for path in [
        "/callback-first",
        "/callback-second",
        "/callback-third",
        "/callback-fourth",
    ] {
        assert!(
            run.summary.effects.iter().any(|effect| {
                matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)
            }),
            "missing summary effect {path}: {:?}",
            run.summary.effects
        );
    }
}

#[test]
fn callback_candidate_cap_emits_a_dynamic_dispatch_boundary() {
    let rebindings: String = (0..17)
        .map(|i| {
            format!(
                "if (args.length > {i}) {{ callback = () -> new java.io.File(\"/candidate-{i}\").delete(); }}"
            )
        })
        .collect();
    let source = format!(
        "class A {{ static void run(String[] args) {{ Runnable callback = () -> new java.io.File(\"/initial\").delete(); {rebindings} callback.run(); }} public static void main(String[] args) {{ run(args); }} }}"
    );
    let plan = analyze(&source);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
            && boundary.detail.as_deref()
                == Some("java callback or receiver candidate limit exceeded")
    }));

    let summary = java_module_summary(&source, Lang::Java);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "A.run")
        .unwrap();
    assert!(run.summary.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
            && boundary.detail.as_deref()
                == Some("java callback or receiver candidate limit exceeded")
    }));
}

#[test]
fn future_callbacks_preserve_try_catch_and_finally_effects() {
    let plan = analyze(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\nimport java.util.concurrent.CompletableFuture;\npublic class A { public static void main(String[] a) { CompletableFuture.runAsync(() -> { try { Files.delete(Path.of(\"/future\")); } catch (Exception e) { Files.deleteIfExists(Path.of(\"/caught\")); } finally { Files.deleteIfExists(Path.of(\"/finally\")); } }).join(); } }",
    );
    for path in ["/future", "/caught", "/finally"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }
}

#[test]
fn stream_callbacks_require_a_terminal_operation_and_bind_source_values() {
    let plan = analyze(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\nimport java.util.List;\nimport java.util.function.Consumer;\nimport java.util.stream.Stream;\npublic class A { public static void main(String[] a) {\n  Stream.of(\"/used\").map(path -> { try { Files.delete(Path.of(path)); } catch (Exception e) {} return path; }).count();\n  Stream.of(\"/lazy\").map(path -> { try { Files.delete(Path.of(path)); } catch (Exception e) {} return path; });\n  List.of(\"/via-stream\").stream().forEach(path -> new java.io.File(path).delete());\n  Stream.of(Path.of(\"/method-reference\")).forEach(Files::delete);\n  Consumer<Path> stored = path -> { try { Files.delete(path); } catch (Exception e) {} };\n  stored.accept(Path.of(\"/stored\"));\n} }",
    );
    for path in ["/used", "/via-stream", "/method-reference", "/stored"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }
    assert!(!deletes(&plan, "/lazy"), "lazy stream callback executed");
}

#[test]
fn callback_collections_preserve_every_bounded_literal_value() {
    let source = "import java.util.*; import java.util.stream.Stream; class A { static void run() { Stream.of(\"/first\", \"/second\", \"/third\").forEach(path -> new java.io.File(path).delete()); List.of(\"/wildcard\").forEach(path -> new java.io.File(path).delete()); } public static void main(String[] args) { run(); } }";
    let plan = analyze(source);
    for path in ["/first", "/second", "/third", "/wildcard"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }

    let summary = java_module_summary(source, Lang::Java);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "A.run")
        .unwrap();
    for path in ["/first", "/second", "/third", "/wildcard"] {
        assert!(run.summary.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)
        }), "missing {path}: {:?}", run.summary.effects);
    }
}

#[test]
fn jdk_wildcard_imports_resolve_modeled_types() {
    let plan = analyze(
        "import java.nio.file.*; import java.io.*; class A { public static void main(String[] args) throws Exception { Files.delete(Paths.get(\"/delete\")); Path p = Paths.get(\"/typed\"); Files.delete(p); Files.copy(Paths.get(\"/copy-src\"), Paths.get(\"/copy-dst\")); Files.move(Paths.get(\"/move-src\"), Paths.get(\"/move-dst\")); new File(\"/file\").delete(); new FileWriter(\"/writer\"); } }",
    );
    for path in ["/delete", "/typed", "/file"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }
    assert!(effect_resource(&plan, "filesystem.read", &fs("/copy-src")));
    assert!(effect_resource(&plan, "filesystem.write", &fs("/copy-dst")));
    assert!(effect_resource(&plan, "filesystem.move", &fs("/move-src")));
    assert!(effect_resource(&plan, "filesystem.write", &fs("/writer")));
}

#[test]
fn java_static_imports_resolve_after_same_file_methods() {
    let single = analyze(
        "import java.nio.file.Paths; import static java.nio.file.Files.delete; class A { public static void main(String[] args) { delete(Paths.get(\"/single\")); } }",
    );
    assert!(deletes(&single, "/single"));

    let wildcard = analyze(
        "import java.nio.file.Paths; import static java.nio.file.Files.*; class A { public static void main(String[] args) { delete(Paths.get(\"/wildcard-static\")); } }",
    );
    assert!(deletes(&wildcard, "/wildcard-static"));

    let local = analyze(
        "import java.nio.file.Paths; import static java.nio.file.Files.delete; class A { static void delete(Object path) {} public static void main(String[] args) { delete(Paths.get(\"/local\")); } }",
    );
    assert!(!deletes(&local, "/local"));
}

#[test]
fn java_static_wildcard_does_not_steal_inherited_bare_call() {
    for static_import in [
        "import static java.util.Arrays.*;",
        "import static org.junit.Assert.*;",
    ] {
        let source = format!(
            "{static_import}\npublic class App extends Base {{\n  public void run() {{ wipe(); }}\n}}\n"
        );
        let summary = java_module_summary(&source, Lang::Java);
        let run = summary
            .functions
            .iter()
            .find(|function| function.name == "App.run")
            .unwrap_or_else(|| panic!("App.run missing for {static_import}"));
        assert!(
            run.calls.iter().any(|edge| edge.callee == "this.wipe"),
            "{static_import} stole inherited dispatch: {:?}",
            run.calls
                .iter()
                .map(|edge| edge.callee.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn java_wildcards_do_not_invent_shadowed_or_unimported_jdk_types() {
    let same_file = analyze(
        "import java.nio.file.*; class Files { static void delete(Object path) {} } class A { public static void main(String[] args) { Files.delete(Paths.get(\"/shadowed\")); } }",
    );
    assert!(!deletes(&same_file, "/shadowed"));

    let unimported = analyze(
        "class A { public static void main(String[] args) { Files.delete(java.nio.file.Paths.get(\"/unimported\")); } }",
    );
    assert!(!deletes(&unimported, "/unimported"));
}

#[test]
fn callback_values_require_identity_preserving_jdk_chains() {
    let source = "import java.util.Arrays; import java.util.stream.Stream; class A { static void run() { Stream.of(\"/mapped\").map(path -> path + \"/sub\").forEach(path -> new java.io.File(path).delete()); MyFactory.of(\"/factory-input\").getPaths().forEach(path -> new java.io.File(path).delete()); MyFactory.of(\"/factory-direct\").forEach(path -> new java.io.File(path).delete()); String[] paths = {\"/array-first\", \"/array-second\"}; Arrays.stream(paths).forEach(path -> new java.io.File(path).delete()); Arrays.stream(\"/array-literal\").forEach(path -> new java.io.File(path).delete()); } public static void main(String[] args) { run(); } }";
    let plan = analyze(source);
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Unresolved { .. })),
        "callback effects were lost: {:?}",
        ops(&plan)
    );
    for path in [
        "/mapped",
        "/factory-input",
        "/factory-direct",
        "/array-literal",
    ] {
        assert!(!deletes(&plan, path), "fabricated callback value {path}");
    }
    assert!(
        !plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Parameter { name } if name == "paths")
        }),
        "array container was bound as a callback element"
    );

    let summary = java_module_summary(source, Lang::Java);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "A.run")
        .unwrap();
    assert!(
        run.summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Unresolved { .. })),
        "callback summary effects were lost"
    );
    for path in [
        "/mapped",
        "/factory-input",
        "/factory-direct",
        "/array-literal",
    ] {
        assert!(
            !run.summary.effects.iter().any(|effect| {
                matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)
            }),
            "fabricated summary callback value {path}"
        );
    }
    assert!(
        !run.summary.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Parameter { name } if name == "paths")
        }),
        "summary bound an array container as a callback element"
    );
}

#[test]
fn method_references_require_the_written_receiver() {
    let plan = analyze(
        "import java.util.stream.Stream; public class A { static void wipe(String path) { new java.io.File(path).delete(); } public static void main(String[] a) { Stream.of(\"/wrong\").forEach(Other::wipe); } } class Other {}",
    );
    assert!(
        !deletes(&plan, "/wrong"),
        "wrong receiver dispatched A.wipe"
    );
}

#[test]
fn same_file_inheritance_and_interface_receivers_dispatch_exactly() {
    let plan = analyze(
        "class Base { void helper() { new java.io.File(\"/inherited\").delete(); } }\nclass Child extends Base { void run() { helper(); } }\ninterface Work { void go(); }\nclass Impl implements Work { public void go() { new java.io.File(\"/interface\").delete(); } }\nclass App { public static void main(String[] args) { new Child().run(); Work work = new Impl(); work.go(); } }",
    );
    for path in ["/inherited", "/interface"] {
        assert!(deletes(&plan, path), "missing {path}: {:?}", ops(&plan));
    }
}

#[test]
fn receiver_reassignment_replaces_concrete_class_evidence() {
    let source = "class Base { void act() {} } class Derived extends Base { void act() { new java.io.File(\"/derived\").delete(); } } class Other extends Base { void act() { new java.io.File(\"/other\").delete(); } } class App { static Object unknown() { return null; } static void run() { Base value = new Derived(); value = new Other(); value.act(); { var sibling = new Derived(); } { var sibling = unknown(); sibling.act(); } } public static void main(String[] args) { run(); } }";
    let plan = analyze(source);
    assert!(
        deletes(&plan, "/other"),
        "missing reassigned receiver effect"
    );
    assert!(!deletes(&plan, "/derived"), "stale receiver dispatched");

    let summary = java_module_summary(source, Lang::Java);
    let edge = summary
        .functions
        .iter()
        .find(|function| function.name == "App.run")
        .and_then(|function| {
            function
                .calls
                .iter()
                .find(|edge| edge.callee == "value.act")
        })
        .expect("typed receiver edge");
    assert!(matches!(
        edge.receiver_identity(),
        Some(ObjectIdentity::Class { name, .. }) if name == "Other"
    ));
}

#[test]
fn an_unmodeled_jdk_call_is_scoped_by_exact_receiver_and_member() {
    // These exact receiver/member pairs cannot escape their respective
    // network and filesystem surfaces.
    for (code, expected) in [
        (
            "import java.net.Socket;\npublic class App { public static void main(String[] a) throws Exception { new Socket(\"h\", 1).getInputStream(); } }\n",
            "network",
        ),
        (
            "import java.io.RandomAccessFile;\npublic class App { public static void main(String[] a) throws Exception { new RandomAccessFile(\"/x\", \"rw\").setLength(0); } }\n",
            "filesystem",
        ),
    ] {
        let plan = analyze(code);
        let boundary = plan
            .boundaries
            .iter()
            .find(|b| b.reason.as_str() == "external_unmodeled")
            .unwrap_or_else(|| panic!("no external_unmodeled boundary for {code}"));
        let domains: Vec<&str> = boundary.domains.iter().map(|d| d.0.as_str()).collect();
        assert_eq!(domains, vec![expected], "{code}");
    }
}

#[test]
fn package_and_process_type_defaults_do_not_narrow_unknown_members() {
    for (receiver, member) in [
        ("java.lang.ProcessBuilder", "command"),
        ("java.sql.Connection", "prepareStatement"),
    ] {
        assert_eq!(
            classify_java_call(receiver, member),
            Some(ExternalCall::Unmodeled(ALL_DOMAINS)),
            "{receiver}.{member}"
        );
    }
}

fn java_main(body: &str) -> String {
    format!(
        "import java.util.*; public class A {{ public static void main(String[] a) throws Exception {{ {body} }} }}"
    )
}

#[test]
fn in_function_process_builder_git_push_composes() {
    let plan = analyze(
        "import java.util.*; public class A { static void push() throws Exception { new ProcessBuilder(\"git\", \"push\", \"--force\", \"origin\", \"main\").start(); } public static void main(String[] a) throws Exception { push(); } }",
    );
    let sync = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.remote_sync")
        .expect("in-function git push composes");
    assert_eq!(sync.attributes.get("force"), Some(&AttrValue::Bool(true)));
    assert_eq!(sync.attributes.get("push"), Some(&AttrValue::Bool(true)));
}

#[test]
fn process_builder_array_list_typed_command_varargs_delete() {
    let sources = [
        "Runtime.getRuntime().exec(new String[]{\"rm\", \"-rf\", \"/tmp/z\"});",
        "new ProcessBuilder(List.of(\"rm\", \"-rf\", \"/tmp/z\")).start();",
        "ProcessBuilder pb = new ProcessBuilder(\"rm\", \"-rf\", \"/tmp/z\"); pb.start();",
        "ProcessBuilder pb = new ProcessBuilder(); pb.command(\"rm\", \"-rf\", \"/tmp/z\"); pb.start();",
        "String[] cmd = {\"rm\", \"-rf\", \"/tmp/z\"}; Runtime.getRuntime().exec(cmd);",
    ];
    for body in sources {
        let plan = analyze(&java_main(body));
        assert!(deletes(&plan, "/tmp/z"), "body={body} ops={:?}", ops(&plan));
    }
    let varargs = analyze(
        "import java.util.*; public class A { static void run(String... cmd) throws Exception { new ProcessBuilder(cmd).start(); } public static void main(String[] a) throws Exception { run(\"rm\", \"-rf\", \"/tmp/z\"); } }",
    );
    assert!(deletes(&varargs, "/tmp/z"), "ops={:?}", ops(&varargs));
}

#[test]
fn process_builder_unknown_argv_stays_unresolved_call() {
    let sources = [
        java_main("ProcessBuilder pb = unknown(); pb.start();"),
        "import java.util.*; class A { static void run(List<String> argv) throws Exception { new ProcessBuilder(argv).start().waitFor(); } public static void main(String[] a) throws Exception { run(List.of(\"git\", \"gc\", \"--prune=now\")); } }".to_string(),
        "record Entry(java.util.List<String> argv) {} class A { static void run(Entry e) throws Exception { new ProcessBuilder(e.argv()).start(); } public static void main(String[] a) throws Exception { run(new Entry(java.util.List.of(\"git\"))); } }".to_string(),
        java_main("String[] cmd = new String[3]; cmd[0] = \"rm\"; cmd[1] = \"-rf\"; cmd[2] = \"/tmp/z\"; new ProcessBuilder(cmd).start();"),
    ];
    for source in sources {
        let plan = analyze(&source);
        assert_eq!(
            plan.effects.iter().filter(|effect| {
                effect.operation.0 == "process.exec"
                    && effect.modality == effinterp_proto::Modality::May
                    && matches!(&effect.resource, ResourceExpr::Unresolved { family } if family.0 == "process")
            }).count(),
            1,
            "{source}: {:?}",
            plan.effects
        );
        assert_eq!(
            plan.coverage
                .level(&effinterp_proto::Domain::new("process")),
            Some(effinterp_proto::CoverageLevel::Partial)
        );

        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unresolved_call"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("unknown argv"))
            }),
            "boundaries={:?}",
            plan.boundaries
        );
        assert!(!plan.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. }
                } if executable == "?"
            )
        }));
    }
}

fn has_git_read(plan: &effinterp_proto::Plan) -> bool {
    plan.effects
        .iter()
        .any(|effect| effect.operation.0 == "git.read")
}

#[test]
fn reassigned_process_argv_uses_last_write() {
    let pb = analyze(&java_main(
        "ProcessBuilder pb = new ProcessBuilder(\"git\",\"status\"); pb = new ProcessBuilder(\"rm\",\"-rf\",\"/tmp/x\"); pb.start();",
    ));
    assert!(deletes(&pb, "/tmp/x"), "ops={:?}", ops(&pb));
    assert!(!has_git_read(&pb), "ops={:?}", ops(&pb));

    let cmd = analyze(&java_main(
        "String[] cmd = {\"git\",\"status\"}; cmd = new String[]{\"rm\",\"-rf\",\"/tmp/y\"}; Runtime.getRuntime().exec(cmd);",
    ));
    assert!(deletes(&cmd, "/tmp/y"), "ops={:?}", ops(&cmd));
    assert!(!has_git_read(&cmd), "ops={:?}", ops(&cmd));
}

#[test]
fn conditionally_reassigned_process_argv_is_not_stale() {
    let cmd = analyze(&java_main(
        "String[] cmd = {\"git\",\"status\"}; if (a.length>0) { cmd = new String[]{\"rm\",\"-rf\",\"/var/www/current\"}; } Runtime.getRuntime().exec(cmd);",
    ));
    assert!(!has_git_read(&cmd), "ops={:?}", ops(&cmd));
    assert!(!deletes(&cmd, "/var/www/current"), "ops={:?}", ops(&cmd));
    assert!(
        cmd.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
        "boundaries={:?}",
        cmd.boundaries
    );

    let pb = analyze(&java_main(
        "ProcessBuilder pb = new ProcessBuilder(\"git\",\"status\"); if (a.length>0) { pb = new ProcessBuilder(\"rm\",\"-rf\",\"/var/www/current\"); } pb.start();",
    ));
    assert!(!has_git_read(&pb), "ops={:?}", ops(&pb));
    assert!(!deletes(&pb, "/var/www/current"), "ops={:?}", ops(&pb));
    assert!(
        pb.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
        "boundaries={:?}",
        pb.boundaries
    );
}

#[test]
fn conditionally_mutated_process_command_is_not_taken_as_fact() {
    let command = analyze(&java_main(
        "ProcessBuilder pb = new ProcessBuilder(\"rm\",\"-rf\",\"/var/www/current\"); if (a.length>0) { pb.command(\"git\",\"status\"); } pb.start();",
    ));
    assert!(!has_git_read(&command), "ops={:?}", ops(&command));
    assert!(
        !deletes(&command, "/var/www/current"),
        "ops={:?}",
        ops(&command)
    );
    assert!(
        command
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
        "boundaries={:?}",
        command.boundaries
    );

    let echo = analyze(&java_main(
        "ProcessBuilder pb = new ProcessBuilder(\"rm\",\"-rf\",\"/var/www/current\"); if (a.length>0) { pb.command(\"echo\",\"noop\"); } pb.start();",
    ));
    assert!(!deletes(&echo, "/var/www/current"), "ops={:?}", ops(&echo));
    assert!(
        !echo.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { executable, .. }
                    } if executable == "echo"
                )
        }),
        "ops={:?}",
        ops(&echo)
    );
    assert!(
        echo.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
        "boundaries={:?}",
        echo.boundaries
    );

    let directory = analyze(
        "import java.io.File; public class A { public static void main(String[] a) throws Exception { ProcessBuilder pb = new ProcessBuilder(\"git\",\"status\"); if (a.length>0) { pb.directory(new File(\"/srv/other\")); } pb.start(); } }",
    );
    assert!(
        !format!("{:?}", directory.effects).contains("/srv/other"),
        "ops={:?}",
        ops(&directory)
    );
}
