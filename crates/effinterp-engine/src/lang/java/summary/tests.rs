use crate::module_summary::ModuleSummary;
use crate::value::fs_path_resource;
use crate::{ObjectIdentity, ScopeKey, TypeRef, ValueOrigin};
use effinterp_proto::{ResourceExpr, ResourceIdentity};

fn summaries(source: &str) -> ModuleSummary {
    crate::module_summary::module_summaries(
        source,
        crate::module_summary::Lang::Java,
        "App.java",
        ScopeKey::Module {
            key: "App.java".into(),
        },
        &crate::SummaryBudget::for_lang(
            &crate::default_limits(),
            crate::module_summary::Lang::Java,
        ),
    )
}

#[test]
fn call_on_imported_type_is_a_main_call_edge() {
    let src = "package a; import a.util.Helper; \
         public class App { public static void main(String[] x) { \
         Helper.wipe(\"/var/cache/app\"); } }";
    let summary = summaries(src);
    let edge = summary
        .main_calls
        .iter()
        .find(|e| e.callee == "Helper.wipe")
        .expect("Helper.wipe recorded as a type-qualified call edge");
    assert_eq!(
        edge.resource_arguments(),
        vec![fs_path_resource("/var/cache/app")]
    );
}

#[test]
fn call_on_an_untyped_receiver_is_not_an_edge() {
    // `logger` is an unknown value — no declared type, no import — so no
    // edge and no false cross-file resolution.
    let src = "package a; \
         public class App { public static void main(String[] x) { \
         logger.info(\"hi\"); } }";
    let summary = summaries(src);
    assert!(
        summary.main_calls.iter().all(|e| e.callee != "logger.info"),
        "a call on an untyped value is not recorded as an edge: {:?}",
        summary.main_calls
    );
}

#[test]
fn overloaded_main_chain_reaches_instance_dispatch_edge() {
    // main(String[]) -> main(int) -> new App().run(p): the merged
    // `App.main` entry carries the typed dispatch edge.
    let src = "package a; \
         public class App { \
           public static void main(String[] x) { main(1); } \
           static int main(int y) { App app = new App(); app.run(\"/p\"); return y; } \
           void run(String p) {} }";
    let summary = summaries(src);
    let edge = summary
        .main_calls
        .iter()
        .find(|e| e.callee == "app.run")
        .expect("instance dispatch edge from overloaded main");
    assert!(matches!(
        edge.receiver_identity(),
        Some(ObjectIdentity::Class { name, .. }) if name == "App"
    ));
    assert!(matches!(
        edge.receiver.as_ref().and_then(|value| value.evidence.origin.as_ref()),
        Some(ValueOrigin::Site { function, .. }) if function == "App.main"
    ));
    assert!(matches!(
        edge.receiver.as_ref().and_then(|value| value.evidence.ty.as_ref()),
        Some(TypeRef::Repo { file, .. }) if file == "App.java"
    ));
}

#[test]
fn same_package_class_gets_an_implicit_import_binding() {
    let src = "package org.acme; \
         public class App { public static void main(String[] x) { \
         Helper.wipe(\"/x\"); } }";
    let summary = summaries(src);
    let binding = summary
        .imports
        .iter()
        .find(|b| b.local == "Helper")
        .expect("implicit same-package binding");
    assert_eq!(binding.module, "org.acme.Helper");
    assert_eq!(binding.imported, None);
}

#[test]
fn local_call_effects_are_inlined_with_constant_resolution() {
    // notify() reads $HOME via a private helper with the env-var name held
    // in a static final constant; the summary of `App.notify` carries the
    // inlined, constant-resolved environment read.
    let src = "package a; \
         public class App { \
           static final String HOME_KEY = \"HOME\"; \
           void notify_() { read(HOME_KEY); } \
           String read(String key) { return System.getenv(key); } }";
    let summary = summaries(src);
    let f = summary
        .functions
        .iter()
        .find(|f| f.name == "App.notify_")
        .expect("App.notify_ summarized");
    assert!(
        f.summary.effects.iter().any(|e| {
            e.operation.0 == "environment.read"
                && e.resource
                    == ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable {
                            name: "HOME".to_string(),
                        },
                    }
        }),
        "inlined constant-resolved env read: {:?}",
        f.summary.effects
    );
}

#[test]
fn files_and_streams_and_env_models() {
    let src = "package a; \
         import java.nio.file.Files; import java.nio.file.Path; \
         import java.io.FileWriter; \
         public class App { \
           void go(Path p) throws Exception { \
             Files.copy(p, Path.of(\"/dst\")); \
             Files.deleteIfExists(p); \
             new FileWriter(\"/log\").close(); \
             System.getProperty(\"user.home\"); } }";
    let summary = summaries(src);
    let f = summary
        .functions
        .iter()
        .find(|f| f.name == "App.go")
        .unwrap();
    let ops: Vec<&str> = f
        .summary
        .effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect();
    assert!(ops.contains(&"filesystem.read"), "copy reads: {ops:?}");
    assert!(
        ops.contains(&"filesystem.write"),
        "copy/FileWriter write: {ops:?}"
    );
    assert!(ops.contains(&"filesystem.delete"), "delete: {ops:?}");
    assert!(ops.contains(&"environment.read"), "getProperty: {ops:?}");
}

#[test]
fn network_via_typed_local_url() {
    let src = "package a; import java.net.URL; import java.net.URLConnection; \
         public class App { void fetch(String u) throws Exception { \
         URL url = new URL(u); URLConnection c = url.openConnection(); } }";
    let summary = summaries(src);
    let f = summary
        .functions
        .iter()
        .find(|f| f.name == "App.fetch")
        .unwrap();
    assert!(
        f.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "network.request"),
        "openConnection on a typed local: {:?}",
        f.summary.effects
    );
}

#[test]
fn reflection_is_a_boundary_not_silent() {
    let src = "package a; import java.lang.reflect.Method; \
         public class App { void go(ClassLoader loader) throws Exception { \
           Method m = loader.loadClass(\"x.Y\").getMethod(\"main\"); \
           m.invoke(null); } }";
    let summary = summaries(src);
    let f = summary
        .functions
        .iter()
        .find(|f| f.name == "App.go")
        .unwrap();
    assert!(
        f.summary
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_dynamic_code"),
        "reflection boundary: {:?}",
        f.summary.boundaries
    );
}

#[test]
fn unmodeled_effectful_jdk_call_is_loud_and_inert_is_quiet() {
    let src = "package a; import java.util.zip.ZipFile; import java.util.Locale; \
         public class App { void go(String p) throws Exception { \
           new ZipFile(p); Locale.getDefault(); } }";
    let summary = summaries(src);
    let f = summary
        .functions
        .iter()
        .find(|f| f.name == "App.go")
        .unwrap();
    assert!(
        f.summary
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "external_unmodeled"),
        "ZipFile stays loud: {:?}",
        f.summary.boundaries
    );
    assert!(
        !f.summary
            .boundaries
            .iter()
            .any(|b| b.detail.as_deref().is_some_and(|d| d.contains("Locale"))),
        "Locale stays quiet: {:?}",
        f.summary.boundaries
    );
}

#[test]
fn constructor_and_class_table() {
    let src = "package a; import a.dl.Downloader; \
         public class Installer { \
           private final Downloader download; \
           private final Config config = new Config(); \
           public Installer(Downloader download) { this.download = download; } \
           void run() { download.fetch(\"/x\"); } }";
    let summary = summaries(src);
    let cls = summary
        .classes
        .iter()
        .find(|c| c.name == "Installer")
        .expect("class table entry");
    assert!(
        cls.attr_params
            .contains(&("download".to_string(), "download".to_string()))
    );
    assert!(
        cls.attr_classes
            .contains(&("config".to_string(), "Config".to_string()))
    );
    let run = summary
        .functions
        .iter()
        .find(|f| f.name == "Installer.run")
        .unwrap();
    let edge = run
        .calls
        .iter()
        .find(|e| e.callee == "download.fetch")
        .expect("field-typed dispatch edge");
    assert!(matches!(
        edge.receiver_identity(),
        Some(ObjectIdentity::ReceiverProperty(name)) if name == "download"
    ));
}

#[test]
fn self_referential_constructor_argument_is_bounded() {
    let src = "class App { void go() { Value value = make(); \
               value = new Value(value); } Value make() { return null; } } \
               class Value { Value(Value prior) {} }";
    let summary = summaries(src);
    let go = summary
        .functions
        .iter()
        .find(|function| function.name == "App.go")
        .expect("App.go summarized");
    assert!(go.calls.iter().any(|edge| edge.callee == "Value"));
}
