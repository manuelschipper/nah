#![allow(clippy::disallowed_types)]

use effinterp_engine::{
    Engine, Lang, ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef,
    canonical_rust_std_type, module_summaries, rust_inert_receiver_method,
};
use effinterp_proto::{
    BoundaryClass, CoverageLevel, Domain, Plan, ResourceExpr, ResourceIdentity, Subject,
    canonical_json, validate_plan,
};

fn rust_module_summary(source: &str, lang: Lang) -> effinterp_engine::ModuleSummary {
    module_summaries(
        source,
        lang,
        "src/main.rs",
        ScopeKey::RustModule { key: "app".into() },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
    )
}

fn analyze(src: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "rust".to_string(),
            source: src.to_string(),
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

#[test]
fn required_delete_follows_normal_control_flow() {
    use effinterp_proto::Modality::{May, MustOnSuccess};

    for (body, definitions, expected) in [
        ("std::fs::remove_file(\"/out\");", "", MustOnSuccess),
        ("if flag { std::fs::remove_file(\"/out\"); }", "", May),
        (
            "if flag { return; } std::fs::remove_file(\"/out\");",
            "",
            May,
        ),
        (
            "if flag {} else {} std::fs::remove_file(\"/out\");",
            "",
            MustOnSuccess,
        ),
        ("while flag { std::fs::remove_file(\"/out\"); }", "", May),
        (
            "for _ in [1, 2] { std::fs::remove_file(\"/out\"); }",
            "",
            MustOnSuccess,
        ),
        (
            "loop { std::fs::remove_file(\"/out\"); break; }",
            "",
            MustOnSuccess,
        ),
        (
            "loop { if flag { break; } std::fs::remove_file(\"/out\"); }",
            "",
            May,
        ),
        ("loop { std::fs::remove_file(\"/out\"); }", "", May),
        (
            "f();",
            "fn f() { std::fs::remove_file(\"/out\"); }",
            MustOnSuccess,
        ),
        (
            "f();",
            "fn f() { f(); std::fs::remove_file(\"/out\"); }",
            May,
        ),
        (
            "let f = || { std::fs::remove_file(\"/out\"); }; f();",
            "",
            MustOnSuccess,
        ),
        ("opaque(); std::fs::remove_file(\"/out\");", "", May),
        ("std::fs::remove_file(\"/out\"); panic!(\"stop\");", "", May),
        (
            "std::fs::remove_file(\"/before\")?; std::fs::remove_file(\"/out\");",
            "",
            May,
        ),
    ] {
        let source = format!("fn main() {{ {body} }} {definitions}");
        let plan = analyze(&source);
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && fs_path(&effect.resource) == Some("/out")
            })
            .collect();
        assert!(
            !deletes.is_empty(),
            "possible effects must survive: {source}"
        );
        assert!(
            deletes.iter().all(|effect| effect.modality == expected),
            "{source}: {deletes:?}"
        );
        let summaries = rust_module_summary(&source, Lang::Rust);
        let summaries: effinterp_engine::ModuleSummary =
            serde_json::from_slice(&serde_json::to_vec(&summaries).unwrap()).unwrap();
        let main = summaries
            .functions
            .iter()
            .find(|function| function.name == "main")
            .unwrap();
        let required =
            main.summary
                .control_flow
                .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
        let slots: Vec<_> = main
            .summary
            .effects
            .iter()
            .enumerate()
            .filter(|(_, effect)| {
                effect.operation.0 == "filesystem.delete"
                    && fs_path(&effect.resource) == Some("/out")
            })
            .collect();
        assert!(!slots.is_empty(), "summary effects must survive: {source}");
        for (slot, _) in slots {
            assert_eq!(
                required
                    .on_success
                    .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
                expected == MustOnSuccess,
                "summary slot {slot}: {source}"
            );
        }
    }
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn fs_path(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn fs_path_of<'a>(plan: &'a Plan, operation: &str) -> Option<&'a str> {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == operation)
        .and_then(|effect| fs_path(&effect.resource))
}

fn property_literals(value: &SemanticValue, property: &str) -> Vec<String> {
    match &value.kind {
        SemanticValueKind::Object(object) => object
            .properties
            .get(property)
            .map(|value| match &value.kind {
                SemanticValueKind::Literal(value) => vec![value.clone()],
                _ => property_literals(value, property),
            })
            .unwrap_or_else(|| {
                object
                    .properties
                    .values()
                    .flat_map(|value| property_literals(value, property))
                    .collect()
            }),
        SemanticValueKind::Union(alternatives) => alternatives
            .iter()
            .flat_map(|value| property_literals(value, property))
            .collect(),
        SemanticValueKind::Alias { value, .. } => match &value.kind {
            SemanticValueKind::Literal(value) => vec![value.clone()],
            _ => property_literals(value, property),
        },
        _ => Vec::new(),
    }
}

#[test]
fn no_entry_point_distinguishes_unreached_rust_callables() {
    let declarations = "pub fn purge(path: &str) { std::fs::remove_dir_all(path).unwrap(); }\n";
    let plan = analyze(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only Rust has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some("no execution root reached; declared callables not executed: purge")
    );
    for domain in ["environment", "filesystem", "git", "network", "process"] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }

    let reached = analyze(&format!(
        "{declarations}fn main() {{ purge(\"/tmp/reached\"); }}\n"
    ));
    assert_eq!(
        fs_path_of(&reached, "filesystem.delete"),
        Some("/tmp/reached")
    );
    assert!(
        reached
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let executed = analyze(
        "fn stale() { std::fs::remove_file(\"/stale\").unwrap(); }\nfn main() { std::fs::remove_file(\"/top\").unwrap(); }\n",
    );
    assert_eq!(fs_path_of(&executed, "filesystem.delete"), Some("/top"));
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
fn fs_remove_dir_all_in_main_is_a_recursive_delete() {
    let plan =
        analyze("use std::fs;\nfn main() {\n    fs::remove_dir_all(\"/data\").unwrap();\n}\n");
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("a delete");
    assert_eq!(fs_path(&del.resource), Some("/data"));
    assert_eq!(
        del.attributes["recursive"],
        effinterp_proto::AttrValue::Bool(true)
    );
}

#[test]
fn fully_qualified_path_resolves() {
    let plan = analyze("fn main() {\n    std::fs::remove_file(\"/etc/x\");\n}\n");
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn rust_value_facts_resolve_const_static_and_local_paths() {
    let plan = analyze(
        r#"
use std::{fs, path::Path};
const LOG: &str = "/var/log/x";
static ROOT: &'static str = "/var/lib/app";

fn main() {
    fs::write(LOG, "");
    fs::create_dir_all(Path::new(ROOT).join("cache"));
    let local = "/data/app";
    fs::remove_dir_all(Path::new(local).join("s"));
}
"#,
    );
    assert_eq!(fs_path_of(&plan, "filesystem.write"), Some("/var/log/x"));
    assert_eq!(
        fs_path_of(&plan, "filesystem.create"),
        Some("/var/lib/app/cache")
    );
    assert_eq!(fs_path_of(&plan, "filesystem.delete"), Some("/data/app/s"));
    assert!(!plan.boundaries.iter().any(|boundary| matches!(
        boundary.reason.as_str(),
        "unexpanded_macro" | "unmodeled_dynamic"
    )));
}

#[test]
fn rust_environment_values_flow_through_join_and_push() {
    let plan = analyze(
        r#"
use std::{env, fs, path::PathBuf};

fn main() {
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("x.rs"),
        "",
    );
    let mut cache = PathBuf::from(env::var_os("HOME").unwrap());
    cache.push(".cache");
    cache.push("app");
    fs::create_dir_all(cache);
}
"#,
    );
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("filesystem write");
    assert!(matches!(&write.resource, ResourceExpr::Join { parts }
        if matches!(parts.as_slice(), [
            ResourceExpr::Environment { name },
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } },
        ] if name == "OUT_DIR" && path == "x.rs")));
    let create = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.create")
        .expect("filesystem create");
    assert!(matches!(&create.resource, ResourceExpr::Join { parts }
        if matches!(parts.as_slice(), [
            ResourceExpr::Environment { name },
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: cache } },
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: app } },
        ] if name == "HOME" && cache == ".cache" && app == "app")));
}

#[test]
fn rust_format_and_literal_path_methods_resolve_filesystem_resources() {
    let plan = analyze(
        r#"
use std::{fs, path::Path};

fn main() {
    let root = "/srv/app";
    fs::write(format!("{}/cache", root), "");
    fs::read(Path::new("/etc/app/app.toml").parent().unwrap().join("old.toml"));
    fs::create_dir_all(Path::new("/etc/app/app.toml").with_extension("bak"));
}
"#,
    );
    assert_eq!(
        fs_path_of(&plan, "filesystem.write"),
        Some("/srv/app/cache")
    );
    assert_eq!(
        fs_path_of(&plan, "filesystem.read"),
        Some("/etc/app/old.toml")
    );
    assert_eq!(
        fs_path_of(&plan, "filesystem.create"),
        Some("/etc/app/app.bak")
    );
}

#[test]
fn rust_sink_give_ups_emit_domain_scoped_boundaries() {
    let plan = analyze(
        r#"
use std::{env, fs, path::PathBuf};

fn main() {
    let root = "/srv/app";
    fs::write(format!("{:?}", root), "");
    let cfg = PathBuf::from(env::var("HOME").unwrap()).join("app.toml");
    fs::read(cfg.parent().unwrap());
}
"#,
    );
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unexpanded_macro")
            .count(),
        1
    );
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
    for boundary in plan.boundaries.iter().filter(|boundary| {
        matches!(
            boundary.reason.as_str(),
            "unexpanded_macro" | "unmodeled_dynamic"
        )
    }) {
        assert_eq!(
            boundary.domains,
            vec![effinterp_proto::Domain::new("filesystem")]
        );
        assert!(matches!(
            boundary.affected_resource,
            Some(ResourceExpr::Unresolved { ref family }) if family.0 == "filesystem"
        ));
        assert_eq!(boundary.provenance.len(), 1);
    }
}

#[test]
fn rust_unwalked_sink_calls_emit_give_up_boundaries() {
    let plan = analyze(
        r#"
use std::{fs, process::Command};

fn main() {
    fs::read(format!("/base/{}", helper()));
    reqwest::blocking::get(format!("https://{}/x", helper()));
    fs::read(helper());
    Command::new("git")
        .arg("pull")
        .current_dir(helper())
        .status();
}
"#,
    );
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        3
    );
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_call")
            .count(),
        1
    );
    for boundary in plan.boundaries.iter().filter(|boundary| {
        boundary.reason.as_str() == "unmodeled_dynamic"
            && boundary.domains == vec![effinterp_proto::Domain::new("filesystem")]
    }) {
        assert!(matches!(
            boundary.affected_resource,
            Some(ResourceExpr::Unresolved { ref family }) if family.0 == "filesystem"
        ));
    }
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| {
                boundary.reason.as_str() == "unmodeled_dynamic"
                    && boundary.domains == vec![effinterp_proto::Domain::new("filesystem")]
            })
            .count(),
        2
    );
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unmodeled_dynamic"
            && boundary.domains == vec![effinterp_proto::Domain::new("network")]
            && matches!(
                boundary.affected_resource,
                Some(ResourceExpr::Unresolved { ref family }) if family.0 == "network"
            )
    }));
    assert!(plan.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { cwd: Some(cwd), .. }
        } if effect.operation.0 == "process.exec"
            && matches!(cwd.as_ref(), ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
    )));
}

#[test]
fn rust_branch_values_union_and_loop_values_give_up() {
    let plan = analyze(
        r#"
use std::fs;

fn main() {
    let mut branch = "/a";
    if true {
        branch = "/b";
    }
    fs::write(branch, "");

    let mut widened = "/start";
    while true {
        widened = "/loop";
    }
    fs::read(widened);
}
"#,
    );
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("filesystem write");
    assert!(
        matches!(&write.resource, ResourceExpr::Union { alternatives }
        if matches!(alternatives.as_slice(), [
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: a } },
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: b } },
        ] if a == "/a" && b == "/b"))
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
    }));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn rust_loop_body_sinks_widen_changed_values() {
    let plan = analyze(
        r#"
use std::{fs, path::PathBuf};

fn main() {
    let mut path = PathBuf::from("/root");
    for part in [".cache", "app"] {
        fs::create_dir_all(&path);
        path.push(part);
    }

    let mut file = "/first";
    while true {
        fs::write(file, "");
        file = "/later";
    }
}
"#,
    );
    for operation in ["filesystem.create", "filesystem.write"] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == operation
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "filesystem")
        }));
    }
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        2
    );
}

#[test]
fn rust_path_methods_require_a_std_path_receiver() {
    let plan = analyze(
        r#"
use std::fs;

fn main() {
    let mut text = String::from("/root");
    text.push('x');
    fs::write(text, "");
}
"#,
    );
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("filesystem write");
    assert!(matches!(
        &write.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn rust_command_summary_keeps_parameterized_current_dir() {
    let summary = rust_module_summary(
        r#"
use std::process::Command;

pub fn run(repo: &str) {
    Command::new("git")
        .arg("pull")
        .current_dir(repo)
        .status();
}
"#,
        Lang::Rust,
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .expect("run summary");
    assert!(run.summary.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { cwd: Some(cwd), .. }
        } if effect.operation.0 == "process.exec"
            && matches!(cwd.as_ref(), ResourceExpr::Parameter { name } if name == "repo")
    )));
}

#[test]
fn rust_inert_receiver_methods_require_exact_std_type_and_arity() {
    assert!(rust_inert_receiver_method("Vec", "len", 0));
    assert!(rust_inert_receiver_method("alloc::vec::Vec", "push", 1));
    assert!(rust_inert_receiver_method(
        "core::primitive::str",
        "trim",
        0
    ));
    assert!(!rust_inert_receiver_method("std::vec::Vec", "len", 1));
    assert!(!rust_inert_receiver_method(
        "std::string::String",
        "trim",
        0
    ));
    assert!(!rust_inert_receiver_method("third_party::Vec", "len", 0));
    assert!(!rust_inert_receiver_method("std::vec::Vec", "last", 0));
}

#[test]
fn rust_receiver_methods_preserve_canonical_outer_type_evidence() {
    let summary = rust_module_summary(
        r#"
use alloc::vec::Vec as ImportedVec;
use core::time::Duration;
struct Input;
struct Holder { values: Vec<Input> }
impl Holder { fn inspect(&self) { self.values.is_empty(); } }
fn inspect(
    prelude: Vec<Input>,
    imported: ImportedVec<Input>,
    slice: &[Input],
    string: String,
    text: &str,
    duration: Duration,
) {
    prelude.len();
    imported.push(Input);
    slice.get(0);
    string.len();
    text.trim();
    duration.as_secs();
    Vec::<Input>::new().len();
}
"#,
        Lang::Rust,
    );
    let calls: Vec<_> = summary
        .functions
        .iter()
        .flat_map(|function| &function.calls)
        .filter_map(|call| {
            let TypeRef::External { path } = call.receiver.as_ref()?.evidence.ty.as_ref()? else {
                return None;
            };
            Some((
                call.callee.rsplit('.').next().unwrap_or(&call.callee),
                path.as_str(),
                call.arguments
                    .iter()
                    .filter(|argument| argument.name.is_none())
                    .count(),
            ))
        })
        .collect();
    for expected in [
        ("len", "std::vec::Vec", 0),
        ("push", "std::vec::Vec", 1),
        ("get", "std::primitive::slice", 1),
        ("len", "std::string::String", 0),
        ("trim", "std::primitive::str", 0),
        ("as_secs", "std::time::Duration", 0),
        ("is_empty", "std::vec::Vec", 0),
    ] {
        assert!(
            calls.contains(&expected),
            "missing {expected:?} in {calls:?}"
        );
    }
    assert_eq!(
        calls
            .iter()
            .filter(|call| **call == ("len", "std::vec::Vec", 0))
            .count(),
        2,
        "parameter and direct-constructor receivers both retain Vec evidence"
    );
}

#[test]
fn rust_receiver_type_evidence_respects_local_and_external_shadowing() {
    let summary = rust_module_summary(
        r#"
use third_party::String;
struct Input;
struct Vec<T>(T);
fn local(value: Vec<Input>) { value.len(); }
fn external(value: String) { value.len(); }
fn generic<String>(value: String) { value.len(); }
"#,
        Lang::Rust,
    );
    let local = summary
        .functions
        .iter()
        .find(|function| function.name == "local")
        .and_then(|function| function.calls.first())
        .expect("local Vec receiver call");
    assert!(local.receiver.as_ref().unwrap().evidence.ty.is_none());

    let external = summary
        .functions
        .iter()
        .find(|function| function.name == "external")
        .and_then(|function| function.calls.first())
        .expect("third-party String receiver call");
    let Some(TypeRef::External { path }) = external
        .receiver
        .as_ref()
        .and_then(|receiver| receiver.evidence.ty.as_ref())
    else {
        panic!("third-party String keeps its external identity")
    };
    assert_eq!(path, "third_party::String");
    assert!(canonical_rust_std_type(path).is_none());

    let generic = summary
        .functions
        .iter()
        .find(|function| function.name == "generic")
        .and_then(|function| function.calls.first())
        .expect("generic receiver call");
    assert!(generic.receiver.as_ref().unwrap().evidence.ty.is_none());

    let glob = rust_module_summary(
        "use third_party::*;\nfn external(value: String) { value.len(); }\n",
        Lang::Rust,
    );
    assert!(
        glob.functions[0].calls[0]
            .receiver
            .as_ref()
            .unwrap()
            .evidence
            .ty
            .is_none()
    );
}

#[test]
fn command_chain_nests_a_subprocess() {
    let plan = analyze(
        "use std::process::Command;\nfn main() {\n    Command::new(\"rm\").arg(\"-rf\").arg(\"/tmp/x\").status().unwrap();\n}\n",
    );
    // process.exec rm from the nested exec, plus the inner rm model's delete.
    assert!(
        ops(&plan).contains(&"process.exec"),
        "ops: {:?}",
        ops(&plan)
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete");
    assert!(del.is_some(), "nested rm delete: {:?}", ops(&plan));
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| matches!(&n.subject, Subject::Exec { .. }))
    );
}

// Regression: the execution walker previously ignored all same-file
// multi-segment and receiver-typed calls even though summaries knew them.
#[test]
fn same_file_associated_module_and_typed_receiver_calls_are_entered() {
    let plan = analyze(
        r#"
use std::fs;
struct Storage { root: &'static str }
impl Storage {
    fn new(root: &'static str) -> Self { Self { root } }
    fn prep(path: &'static str) { fs::remove_dir_all(path).unwrap(); }
    fn purge(self) { fs::remove_dir_all(self.root).unwrap(); }
}
mod jobs {
    pub fn clean() { std::fs::remove_dir_all("/module").unwrap(); }
}
fn main() {
    (Storage { root: "/literal" }).purge();
    Storage::new("/chained").purge();
    Storage::prep("/associated");
    jobs::clean();
}
"#,
    );
    for path in ["/literal", "/chained", "/associated", "/module"] {
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete" && fs_path(&effect.resource) == Some(path)
            }),
            "missing {path}: {plan:?}"
        );
    }

    let unresolved = analyze("fn main() { local::missing(); }");
    assert!(unresolved.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unresolved_call"
            && boundary.detail.as_deref() == Some("call to unmodeled local::missing")
    }));
}

#[test]
fn external_return_identity_comes_from_the_declared_value_type() {
    let summaries = rust_module_summary(
        "use std::process::Command;\nfn command() -> Result<Command, ()> { Ok(Command::new(\"echo\")) }\nfn commands() -> Vec<Command> { Vec::new() }\n",
        Lang::Rust,
    );
    let command = summaries
        .functions
        .iter()
        .find(|function| function.name == "command")
        .unwrap();
    assert_eq!(command.returns_instances, [Some("Command".to_string())]);
    assert!(matches!(
        command.return_types.as_slice(),
        [Some(effinterp_engine::TypeRef::External { path })]
            if path == "std::process::Command"
    ));
    let commands = summaries
        .functions
        .iter()
        .find(|function| function.name == "commands")
        .unwrap();
    assert!(commands.returns_instances.is_empty());
    assert!(commands.return_types.is_empty());
}

#[test]
fn finite_struct_returns_keep_fields_through_wrappers_and_matches() {
    let summaries = rust_module_summary(
        r#"
struct Pager { bin: String, args: Vec<String> }

fn get_pager() -> Result<Option<Pager>, ()> {
    let pager = match std::env::var("PAGER") {
        Ok(bin) => Pager { bin, args: vec!["--env".to_string()] },
        Err(_) => Pager { bin: "less".to_string(), args: vec!["-R".to_string()] },
    };
    Ok(Some(pager))
}

fn identity(bin: &str) -> Result<String, ()> {
    Ok(bin.to_owned())
}
"#,
        Lang::Rust,
    );
    let pager = summaries
        .functions
        .iter()
        .find(|function| function.name == "get_pager")
        .and_then(|function| function.summary.returns.as_ref())
        .expect("finite pager return");
    assert!(
        property_literals(pager, "bin")
            .iter()
            .any(|bin| bin == "less")
    );

    let identity = summaries
        .functions
        .iter()
        .find(|function| function.name == "identity")
        .and_then(|function| function.summary.returns.as_ref())
        .expect("identity return");
    assert!(matches!(
        &identity.kind,
        SemanticValueKind::Object(object)
            if matches!(&object.identity, ObjectIdentity::Class { name, .. } if name == "Ok")
                && matches!(object.properties.get("0").map(|value| &value.kind), Some(SemanticValueKind::Parameter(name)) if name == "bin")
    ));
}

#[test]
fn overwrites_do_not_retain_obsolete_struct_field_values() {
    let summaries = rust_module_summary(
        r#"
struct Pager { bin: String }
fn unknown() -> String { external() }
fn pager() -> Pager {
    let mut pager = Pager { bin: "less".to_string() };
    pager = Pager { bin: unknown() };
    pager
}
"#,
        Lang::Rust,
    );
    let returned = summaries
        .functions
        .iter()
        .find(|function| function.name == "pager")
        .and_then(|function| function.summary.returns.as_ref())
        .expect("pager return");
    assert!(property_literals(returned, "bin").is_empty());
}

#[test]
fn rust_value_analysis_is_reused_across_function_summaries() {
    let depth = 12;
    let callers = 24;
    let mut source = format!("fn helper{depth}(value: &str) -> String {{ value.to_owned() }}\n");
    for index in (0..depth).rev() {
        let next = index + 1;
        source.push_str(&format!(
            "fn helper{index}(value: &str) -> String {{ let first = helper{next}(value); let second = helper{next}(&first); if value.is_empty() {{ first }} else {{ second }} }}\n"
        ));
    }
    for index in 0..callers {
        source.push_str(&format!(
            "pub fn caller{index}() {{ std::process::Command::new(helper0(\"less\")).status(); }}\n"
        ));
    }

    let budget =
        effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Rust);
    let summaries = module_summaries(
        &source,
        Lang::Rust,
        "src/main.rs",
        ScopeKey::RustModule { key: "app".into() },
        &budget,
    );
    assert_eq!(summaries.functions.len(), depth + callers + 1);
    // Inferring each function's value facts once is linear in the function
    // count. Re-inferring the helper chain for every summary repeats it per
    // function and per nested callee summary.
    assert!(
        budget.value_steps.get() <= 64 * summaries.functions.len() as u64,
        "Rust value analysis was repeated for each function summary: {} steps",
        budget.value_steps.get()
    );
}

#[test]
fn uncalled_function_is_not_executed() {
    let plan = analyze(
        "use std::fs;\nfn danger() {\n    fs::remove_dir_all(\"/important\");\n}\nfn main() {\n    println!(\"hi\");\n}\n",
    );
    assert!(
        !ops(&plan).contains(&"filesystem.delete"),
        "uncalled danger must not execute: {:?}",
        ops(&plan)
    );
}

#[test]
fn called_function_arg_is_substituted() {
    let plan = analyze(
        "use std::fs;\nuse std::path::Path;\nfn wipe(p: &Path) {\n    fs::remove_dir_all(p);\n}\nfn main() {\n    wipe(Path::new(\"/var/cache\"));\n}\n",
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("cross-call delete");
    assert_eq!(fs_path(&del.resource), Some("/var/cache"));
}

#[test]
fn generic_path_parameter_join_preserves_relative_tail_after_substitution() {
    let plan = analyze(
        r#"
use std::{fs, path::Path};

fn read<P: AsRef<Path>>(path: P) {
    fs::read(path.as_ref().join("x"));
}

fn main() {
    read("/var/cache");
}
"#,
    );
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/var/cache/x"));
}

#[test]
fn module_summaries_exposes_parameterized_summary_and_imports() {
    let src = "use std::fs;\nfn wipe(p: &std::path::Path) {\n    fs::remove_dir_all(p);\n}\n";
    let ms = rust_module_summary(src, Lang::Rust);
    let wipe = ms
        .functions
        .iter()
        .find(|f| f.name == "wipe")
        .expect("wipe summarized");
    assert_eq!(wipe.summary.params, vec!["p".to_string()]);
    let del = wipe
        .summary
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("parameterized delete");
    assert_eq!(del.resource, ResourceExpr::Parameter { name: "p".into() });
    assert!(ms.imports.iter().any(|i| i.module == "std::fs"));
    let ms = rust_module_summary(
        "fn run() { other::prepare(); std::fs::remove_file(\"/after\"); }",
        Lang::Rust,
    );
    let run = ms
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    assert_eq!(run.calls.len(), 1);
    for (returns, required) in [
        (None, false),
        (
            Some(effinterp_engine::CallContract::from_flags(
                true, false, false,
            )),
            true,
        ),
        (
            Some(effinterp_engine::CallContract::from_flags(
                false, false, false,
            )),
            false,
        ),
    ] {
        let proof = run.summary.control_flow.requirements(
            &mut |_| false,
            &mut |_| returns.clone(),
            &mut |_, _| true,
        );
        assert_eq!(
            proof
                .on_success
                .contains(&effinterp_engine::ControlFact::Effect(0)),
            required
        );
    }
}

#[test]
fn module_summaries_distinguish_public_from_private_definitions() {
    let ms = rust_module_summary(
        "fn private_wipe() {}\npub(self) fn self_wipe() {}\npub fn public_wipe() {}\npub(crate) struct PublicType;\nstruct PrivateType;\n",
        Lang::Rust,
    );
    assert_eq!(
        ms.exported_definitions,
        [
            ("PublicType".to_string(), "PublicType".to_string()),
            ("public_wipe".to_string(), "public_wipe".to_string()),
        ]
    );
}

#[test]
fn module_calls_record_main_qualified_call_edge_with_synthetic_import() {
    // `fn main` calling a path-qualified in-crate function records the bare fn
    // name as an execution-root edge plus a synthetic whole-path import so the
    // repo layer can resolve it to a file.
    let ms = rust_module_summary("fn main() { crate::util::wipe(); }\n", Lang::Rust);
    assert!(
        ms.module_calls.iter().any(|e| e.callee == "wipe"),
        "module_calls: {:?}",
        ms.module_calls
    );
    assert!(
        ms.imports
            .iter()
            .any(|i| i.module == "crate::util::wipe" && i.imported.as_deref() == Some("wipe")),
        "imports: {:?}",
        ms.imports
    );
}

#[test]
fn bare_module_qualified_call_synthesizes_whole_path_import() {
    // A bare module qualifier (`util::wipe`) synthesizes a whole-path import;
    // the repo layer resolves it as a sibling module or workspace crate.
    let ms = rust_module_summary("fn run() { util::wipe(); }\n", Lang::Rust);
    assert!(
        ms.imports
            .iter()
            .any(|i| i.module == "util::wipe" && i.imported.as_deref() == Some("wipe")),
        "imports: {:?}",
        ms.imports
    );
}

#[test]
fn extern_crate_rename_exports_module_alias_and_resolves_calls() {
    let exported = rust_module_summary(
        "pub extern crate a as b;\nfn main() { b::f(); }\n",
        Lang::Rust,
    );
    assert!(
        exported.exports.iter().any(|binding| {
            binding.local == "b" && binding.module == "a" && binding.imported.is_none()
        }),
        "exports: {:?}",
        exported.exports
    );
    assert!(
        exported.imports.iter().any(|binding| {
            binding.module == "a::f" && binding.imported.as_deref() == Some("f")
        }),
        "imports: {:?}",
        exported.imports
    );
    assert!(
        exported.module_calls.iter().any(|edge| edge.callee == "f"),
        "module_calls: {:?}",
        exported.module_calls
    );

    let private = rust_module_summary("extern crate a as b;\nfn main() { b::f(); }\n", Lang::Rust);
    assert!(
        !private.exports.iter().any(|binding| binding.local == "b"),
        "private extern crate must not export: {:?}",
        private.exports
    );
    assert!(
        private.imports.iter().any(|binding| {
            binding.module == "a::f" && binding.imported.as_deref() == Some("f")
        }),
        "imports: {:?}",
        private.imports
    );
}

#[test]
fn env_and_network_are_modeled() {
    let plan = analyze(
        "use std::env;\nfn main() {\n    env::set_var(\"X\", \"1\");\n    let _ = env::var(\"\");\n    reqwest::blocking::get(\"https://evil.example.com/x\");\n}\n",
    );
    assert!(ops(&plan).contains(&"environment.write"));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
    assert!(ops(&plan).contains(&"network.request"));
}

#[test]
fn malformed_source_is_a_boundary_not_a_panic() {
    let plan = analyze("fn main( { this is not rust ###");
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "parse_error")
    );
    assert!(plan.effects.is_empty());
}

#[test]
fn analysis_is_deterministic() {
    let src = "use std::fs;\nfn main() {\n    fs::remove_file(\"/a\");\n    fs::write(\"/b\", \"x\");\n}\n";
    let a = canonical_json(&analyze(src));
    let b = canonical_json(&analyze(src));
    assert_eq!(a, b);
}

#[test]
fn real_rust_snippet_does_not_panic() {
    // A nod to self-hosting: a chunk of realistic Rust must analyze cleanly.
    let src = r#"
use std::fs;
use std::process::Command;
use std::path::PathBuf;

fn build(dir: &PathBuf) {
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    Command::new("cargo").arg("build").arg("--release").status().unwrap();
}

fn main() {
    let root = PathBuf::from("/workspace");
    build(&root);
    fs::remove_dir_all("/tmp/scratch").ok();
}
"#;
    let plan = analyze(src);
    // create_dir_all (via build), cargo exec, and the scratch delete all show.
    assert!(ops(&plan).contains(&"filesystem.create"));
    assert!(ops(&plan).contains(&"process.exec"));
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn effectless_constructors_do_not_degrade_coverage() {
    // Free and associated known-effectless calls produce no unresolved_call
    // boundary, while a real fs delete in the same body still shows.
    let plan = analyze(
        r#"
use std::fs;
fn main() {
    let x = Ok::<i32, i32>(1);
    let _y = Err::<i32, i32>(2);
    let _boxed = Box::new(1);
    let _string = String::from("value");
    let _bytes = String::from_utf8(Vec::new());
    let _reserved = Vec::<u32>::with_capacity(4);
    let _default = Default::default();
    let _hasher = blake3::Hasher::new();
    drop(x);
    fs::remove_file("/etc/x");
}
"#,
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unresolved_call"),
        "boundaries: {:?}",
        plan.boundaries
    );
    assert!(
        plan.coverage
            .0
            .values()
            .all(|l| l.level == effinterp_proto::CoverageLevel::Full),
        "coverage degraded: {:?}",
        plan.coverage
    );
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn bin_macro_is_a_crate_handoff_not_a_silent_empty_file() {
    // `path::bin!(crate_ident)` expands to `fn main` calling `crate_ident::uumain`.
    let ms = rust_module_summary("uucore::bin!(uu_cat);\n", Lang::Rust);
    assert!(
        ms.functions.iter().any(|f| f.name == "main"),
        "bin! synthesizes a main: {:?}",
        ms.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
    );
    assert!(
        ms.module_calls.iter().any(|e| e.callee == "uumain"),
        "module_calls: {:?}",
        ms.module_calls
    );
    assert!(
        ms.imports
            .iter()
            .any(|i| { i.module == "uu_cat::uumain" && i.imported.as_deref() == Some("uumain") }),
        "imports: {:?}",
        ms.imports
    );
}

#[test]
fn bin_macro_with_option_still_handoffs_the_first_ident() {
    let ms = rust_module_summary("uucore::bin!(uu_cat, no_flush);\n", Lang::Rust);
    assert!(
        ms.imports.iter().any(|i| i.module == "uu_cat::uumain"),
        "imports: {:?}",
        ms.imports
    );
}

#[test]
fn main_and_entry_macros_use_conventional_crate_entries() {
    let main = rust_module_summary("cli::main!(app);\n", Lang::Rust);
    assert!(
        main.module_calls.iter().any(|e| e.callee == "main")
            && main.imports.iter().any(|i| i.module == "app::main"),
        "main! handoff: calls={:?} imports={:?}",
        main.module_calls,
        main.imports
    );
    let entry = rust_module_summary("cli::entry!(cmds);\n", Lang::Rust);
    assert!(
        entry.module_calls.iter().any(|e| e.callee == "run")
            && entry.imports.iter().any(|i| i.module == "cmds::run"),
        "entry! handoff: calls={:?} imports={:?}",
        entry.module_calls,
        entry.imports
    );
}

#[test]
fn unrecognized_item_macro_is_not_an_entry_handoff() {
    let ms = rust_module_summary("trace!(uu_cat);\nprintln!(\"hi\");\n", Lang::Rust);
    assert!(
        ms.module_calls.is_empty() && !ms.functions.iter().any(|f| f.name == "main"),
        "trace!/println! must not invent main: calls={:?} fns={:?}",
        ms.module_calls,
        ms.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
    );
}

#[test]
fn match_arm_struct_literal_types_the_receiver() {
    // A `let exa = Exa { .. }` inside a match arm must type `exa.run()` as
    // `Exa.run`, not an untyped `exa` / `?.run`.
    let ms = rust_module_summary(
        concat!(
            "pub struct Exa;\n",
            "impl Exa {\n",
            "    pub fn run(&self) {}\n",
            "}\n",
            "fn main() {\n",
            "    match 0 {\n",
            "        0 => {\n",
            "            let exa = Exa {};\n",
            "            exa.run();\n",
            "        }\n",
            "        _ => {}\n",
            "    }\n",
            "}\n",
        ),
        Lang::Rust,
    );
    assert!(
        ms.module_calls.iter().any(|e| e.callee == "Exa.run"),
        "match-arm struct literal types the receiver: {:?}",
        ms.module_calls
    );
}

#[test]
fn associated_constructor_types_the_receiver_method() {
    // `Type::from_args()` (not only `Type::new`) types the local so a later
    // method call is `File.wipe`, not an opaque `?.wipe`.
    let ms = rust_module_summary(
        concat!(
            "pub struct File;\n",
            "impl File {\n",
            "    pub fn from_args() -> File { File }\n",
            "    pub fn filename() -> String { String::new() }\n",
            "    pub fn wipe(&self) { std::fs::remove_file(\"/x\"); }\n",
            "}\n",
            "fn main() {\n",
            "    let f = File::from_args();\n",
            "    f.wipe();\n",
            "}\n",
        ),
        Lang::Rust,
    );
    assert!(
        ms.module_calls.iter().any(|e| e.callee == "File.wipe"),
        "from_args types the receiver: {:?}",
        ms.module_calls
    );
}

#[test]
fn non_constructor_assoc_fn_does_not_type_the_local() {
    // A same-file helper that returns String must not type the local as File.
    let ms = rust_module_summary(
        concat!(
            "pub struct File;\n",
            "impl File {\n",
            "    pub fn filename() -> String { String::new() }\n",
            "    pub fn wipe(&self) { std::fs::remove_file(\"/x\"); }\n",
            "}\n",
            "fn main() {\n",
            "    let name = File::filename();\n",
            "    name.wipe();\n",
            "}\n",
        ),
        Lang::Rust,
    );
    assert!(
        !ms.module_calls.iter().any(|e| e.callee == "File.wipe"),
        "filename must not type the local as File: {:?}",
        ms.module_calls
    );
}

#[test]
fn renamed_type_assoc_fn_keeps_the_alias() {
    // `use theme::Options as ThemeOptions; ThemeOptions::deduce()` must not
    // collapse to `Options.deduce` and collide with a local Options type.
    let ms = rust_module_summary(
        concat!(
            "use crate::theme::Options as ThemeOptions;\n",
            "pub struct Options;\n",
            "impl Options {\n",
            "    pub fn deduce() {}\n",
            "}\n",
            "fn main() {\n",
            "    ThemeOptions::deduce();\n",
            "}\n",
        ),
        Lang::Rust,
    );
    assert!(
        ms.module_calls
            .iter()
            .any(|e| e.callee == "ThemeOptions.deduce"),
        "alias must stay on the edge: {:?}",
        ms.module_calls
    );
    assert!(
        !ms.module_calls.iter().any(|e| e.callee == "Options.deduce"),
        "must not collapse to the local Options: {:?}",
        ms.module_calls
    );
}

#[test]
fn imported_bare_call_is_not_an_unresolved_boundary() {
    // `use options::parser::get_command; get_command()` is a cross-file call,
    // not an unmodeled local — composition follows the import.
    let plan = analyze("use options::parser::get_command;\nfn main() {\n    get_command();\n}\n");
    assert!(
        !plan.boundaries.iter().any(|b| {
            b.reason.as_str() == "unresolved_call"
                && b.detail.as_deref().unwrap_or("").contains("get_command")
        }),
        "imported get_command must not be unresolved_call: {:?}",
        plan.boundaries
    );
}

#[test]
fn generated_include_is_a_loud_unexpanded_macro_boundary() {
    let plan = analyze("include!(concat!(env!(\"OUT_DIR\"), \"/dispatch.rs\"));\nfn main() {}\n");
    assert!(
        plan.boundaries.iter().any(|b| {
            b.reason.as_str() == "unexpanded_macro"
                && b.detail.as_deref().unwrap_or("").contains("OUT_DIR")
        }),
        "include! of generated source must stay loud: {:?}",
        plan.boundaries
    );
    assert!(
        plan.coverage
            .0
            .values()
            .any(|l| l.level == effinterp_proto::CoverageLevel::Partial),
        "unexpanded include degrades coverage: {:?}",
        plan.coverage
    );
}

#[test]
fn called_closure_executes_but_unused_closure_does_not() {
    let plan = analyze(
        "fn main() {\n    let unused = || std::fs::remove_file(\"/unused-closure\");\n    let called = || std::fs::remove_file(\"/called-closure\");\n    called();\n}\n",
    );
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/called-closure"]);
}

#[test]
fn called_closure_processes_local_statements() {
    let source = "fn main() {\n    let nested = || std::fs::remove_file(\"/outer-closure\");\n    let called = || {\n        let mut command = std::process::Command::new(\"echo\");\n        command.status();\n        let nested = || std::fs::remove_file(\"/nested-closure\");\n        nested();\n    };\n    called();\n    nested();\n}\n";
    let plan = analyze(source);
    assert!(ops(&plan).contains(&"process.exec"));
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/nested-closure", "/outer-closure"]);

    let summaries = rust_module_summary(source, Lang::Rust);
    let main = summaries
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main summary");
    assert!(
        main.summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    );
    let paths: Vec<_> = main
        .summary
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/nested-closure", "/outer-closure"]);
    assert!(
        main.summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "uncomposed_subprocess")
    );
}

#[test]
fn awaited_futures_execute_but_unpolled_futures_do_not() {
    let plan = analyze(
        "async fn wipe(path: &str) { std::fs::remove_file(path); }\nasync fn main() {\n    wipe(\"/unused-future\");\n    async { std::fs::remove_file(\"/unused-block\"); };\n    wipe(\"/awaited-future\").await;\n    async { std::fs::remove_file(\"/awaited-block\"); }.await;\n    let stored = wipe(\"/stored-future\");\n    stored.await;\n    let stored_block = async { std::fs::remove_file(\"/stored-block\"); };\n    stored_block.await;\n}\n",
    );
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(
        paths,
        [
            "/awaited-future",
            "/awaited-block",
            "/stored-future",
            "/stored-block"
        ]
    );
}

#[test]
fn stored_future_arguments_execute_eagerly() {
    let source = "async fn hold(_: ()) {}\nfn main() {\n    let _future = hold(std::fs::remove_dir_all(\"/eager-argument\").unwrap());\n}\n";
    let plan = analyze(source);
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/eager-argument"]);

    let summaries = rust_module_summary(source, Lang::Rust);
    let main = summaries
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main summary");
    let paths: Vec<_> = main
        .summary
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/eager-argument"]);

    let source = "async fn hold(_: ()) { std::fs::remove_file(\"/future-body\"); }\nfn main() {\n    let future = hold(std::fs::remove_dir_all(\"/eager-argument\").unwrap());\n    futures::executor::block_on(future);\n}\n";
    let plan = analyze(source);
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/eager-argument", "/future-body"]);

    let summaries = rust_module_summary(source, Lang::Rust);
    let main = summaries
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main summary");
    let paths: Vec<_> = main
        .summary
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(paths, ["/eager-argument", "/future-body"]);
}

#[test]
fn known_future_drivers_execute_async_arguments() {
    let plan = analyze(
        "async fn wipe(path: &str) { std::fs::remove_file(path); }\nfn main() {\n    tokio::spawn(wipe(\"/spawned-future\"));\n    futures::executor::block_on(wipe(\"/blocked-future\"));\n    let stored = wipe(\"/stored-future\");\n    tokio::spawn(stored);\n    let aliased = wipe(\"/aliased-future\");\n    let driver = aliased;\n    futures::executor::block_on(driver);\n    wipe(\"/unpolled-future\");\n}\n",
    );
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .collect();
    assert_eq!(
        paths,
        [
            "/spawned-future",
            "/blocked-future",
            "/stored-future",
            "/aliased-future"
        ]
    );
    for (driver, argument) in [
        (
            "tokio::task::spawn_blocking",
            r#"|| std::fs::write("/driver", "x")"#,
        ),
        (
            "tokio::task::spawn_local",
            r#"async { std::fs::remove_file("/driver"); }"#,
        ),
        (
            "tokio::spawn",
            r#"async { std::fs::remove_file("/driver"); }"#,
        ),
        ("rayon::spawn", r#"|| std::fs::remove_file("/driver")"#),
        (
            "std::thread::scope",
            r#"|s| { s.spawn(|| std::fs::remove_file("/driver")); }"#,
        ),
    ] {
        let plan = analyze(&format!("fn main() {{ {driver}({argument}); }}"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| fs_path(&effect.resource) == Some("/driver")),
            "{driver}: {:?}",
            plan
        );
        assert!(
            !plan.boundaries.iter().any(|boundary| boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains(driver))),
            "{driver}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn unmodeled_future_drivers_remain_loud() {
    let plan = analyze(
        "async fn wipe() { std::fs::remove_file(\"/runtime\"); }\nfn main() {\n    let rt = tokio::runtime::Runtime::new().unwrap();\n    let future = wipe();\n    rt.block_on(future);\n}\n",
    );
    assert!(
        plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unresolved_call"
                && boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("not known to be polled"))
        }),
        "unmodeled future drivers must remain explicit: {:?}",
        plan.boundaries
    );
    assert!(
        plan.coverage
            .0
            .values()
            .any(|level| level.level == effinterp_proto::CoverageLevel::Partial),
        "an unmodeled future driver degrades coverage: {:?}",
        plan.coverage
    );
}

#[test]
fn unpolled_async_blocks_remain_loud() {
    let plan = analyze(
        "fn make() -> impl std::future::Future<Output = ()> { async { std::fs::remove_file(\"/async-block\"); } }\nfn main() { let future = make(); futures::executor::block_on(future); }\n",
    );
    assert!(
        plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unresolved_call"
                && boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("async block"))
        }),
        "an unpolled async block must remain explicit: {:?}",
        plan.boundaries
    );
    assert!(
        plan.coverage
            .0
            .values()
            .any(|level| level.level == effinterp_proto::CoverageLevel::Partial),
        "an unpolled async block degrades coverage: {:?}",
        plan.coverage
    );
}

#[test]
fn indirect_callable_expressions_remain_loud() {
    let plan = analyze(
        "struct Handler { call: fn() }\nfn main() {\n    let handler = Handler { call: || std::fs::remove_file(\"/struct-closure\") };\n    (handler.call)();\n    let tuple = (\"unused\", || std::fs::remove_file(\"/tuple-closure\"));\n    (tuple.1)();\n}\n",
    );
    assert!(
        plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unresolved_call"
                && boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("indirect callable expression"))
        }),
        "indirect closure calls must remain explicit: {:?}",
        plan.boundaries
    );
    assert!(
        plan.coverage
            .0
            .values()
            .any(|level| level.level == effinterp_proto::CoverageLevel::Partial),
        "an unresolved indirect call degrades coverage: {:?}",
        plan.coverage
    );
}

#[test]
fn helpers_in_proven_unreachable_match_arms_do_not_abort_analysis() {
    let plan = analyze(
        "enum Mode { Fast, Slow }\nfn mode() -> Mode { Mode::Fast }\nfn slow_path() { std::fs::remove_file(\"/unreachable\"); }\nfn main() {\n    std::fs::remove_file(\"/kept\");\n    match mode() {\n        Mode::Slow => slow_path(),\n        Mode::Fast => {}\n    }\n}\n",
    );
    assert_eq!(fs_path_of(&plan, "filesystem.delete"), Some("/kept"));
}

#[test]
fn distinct_local_call_chain_at_depth_limit_does_not_abort_analysis() {
    let mut source = String::new();
    for index in 0..63 {
        source.push_str(&format!("fn f{index}() {{ f{}(); }}\n", index + 1));
    }
    source.push_str("fn f63() {}\n");
    source.push_str("fn main() { std::fs::remove_file(\"/kept\"); f0(); }\n");

    let plan = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || analyze(&source))
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(fs_path_of(&plan, "filesystem.delete"), Some("/kept"));
}

#[test]
fn trait_and_generic_dispatch_evidence_is_typed() {
    let summary = rust_module_summary(
        "trait Sink { fn send(&self, path: &str) -> Result<(), ()>; }\nfn run<T: Sink>(sink: T) { sink.send(\"/x\"); }\n",
        Lang::Rust,
    );
    let contract = summary.dispatch_contracts.first().expect("trait contract");
    assert_eq!(contract.name, "Sink");
    assert_eq!(contract.method_signatures.len(), 1);
    assert_eq!(contract.method_signatures[0].1.params, ["&self", "&str"]);
    assert_eq!(contract.method_signatures[0].1.results, ["Result<(),()>"]);
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .expect("generic function");
    let call = run
        .calls
        .iter()
        .find(|call| call.callee == "Sink.send")
        .expect("generic bound types receiver");
    assert!(matches!(
        call.receiver_identity(),
        Some(effinterp_engine::ObjectIdentity::Class { name, .. }) if name == "Sink"
    ));
}
