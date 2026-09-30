use effinterp_bench::nah::{
    goldens::{Req, ResourceMatch},
    mutate::measure_symbolic_mutations,
};
use effinterp_engine::Engine;
use effinterp_proto::Subject;

fn check(subject: Subject, operation: &str) {
    let engine = Engine::new().with_causality_detail(true);
    let plan = engine.analyze(&subject).unwrap();
    let result = measure_symbolic_mutations(
        &engine,
        &plan,
        &[Req {
            attributes: Default::default(),
            op: operation.into(),
            resource: ResourceMatch::Any(true),
        }],
        None,
        None,
    );
    assert!(result.exercised > 0, "{subject:?}: {result:?}");
    assert!(result.findings.is_empty(), "{subject:?}: {result:?}");
}

#[test]
fn mandatory_families_exercise_unknown_filename_and_network_operands() {
    for (json, operation) in [
        (
            r#"{"kind":"shell","source":"rm /file"}"#,
            "filesystem.delete",
        ),
        (
            r#"{"kind":"exec","argv":["curl","https://example.test"]}"#,
            "network.request",
        ),
        (
            r#"{"kind":"source","language":"js","dialect":"js","source":"require('fs').unlinkSync('/file')"}"#,
            "filesystem.delete",
        ),
        (
            r#"{"kind":"source","language":"js","dialect":"js","source":"fetch('https://example.test')"}"#,
            "network.request",
        ),
        (
            r#"{"kind":"source","language":"rust","source":"fn main() { let _ = std::fs::read(\"/file\"); }"}"#,
            "filesystem.read",
        ),
        (
            r#"{"kind":"source","language":"rust","source":"fn main() { let _ = std::net::TcpStream::connect(\"example.test:80\"); }"}"#,
            "network.connect",
        ),
    ] {
        check(serde_json::from_str(json).unwrap(), operation);
    }
}

#[test]
fn budget_and_unsupported_subjects_are_visible() {
    let engine = Engine::new().with_causality_detail(true);
    let subject = Subject::Exec {
        argv: std::iter::once("rm".into())
            .chain((0..17).map(|i| format!("/file{i}")))
            .collect(),
        cwd: None,
        context: Default::default(),
    };
    let result = measure_symbolic_mutations(
        &engine,
        &engine.analyze(&subject).unwrap(),
        &[Req {
            attributes: Default::default(),
            op: "filesystem.delete".into(),
            resource: ResourceMatch::Any(true),
        }],
        None,
        None,
    );
    assert_eq!(result.attempted, 16);
    assert_eq!(result.exercised, 16);
    assert_eq!(result.reasons["mutant_budget"], 1);
    let subject: Subject =
        serde_json::from_str(r#"{"kind":"tool_call","tool":"file.read","args":{"path":"/file"}}"#)
            .unwrap();
    let result =
        measure_symbolic_mutations(&engine, &engine.analyze(&subject).unwrap(), &[], None, None);
    assert_eq!(result.exercised, 0);
    assert_eq!(
        result.reasons["native_fields_have_no_symbolic_transform"],
        1
    );
}

#[test]
fn source_frontends_without_operand_transforms_report_unsupported() {
    let engine = Engine::new().with_causality_detail(true);
    for (language, source) in [
        ("python", "import os\nos.remove('/file')"),
        (
            "go",
            "package main; import \"os\"; func main(){ os.Remove(\"/file\") }",
        ),
        (
            "java",
            "class App { public static void main(String[] a) throws Exception { java.nio.file.Files.delete(java.nio.file.Path.of(\"/file\")); } }",
        ),
        ("ruby", "File.delete('/file')"),
        ("php", "<?php unlink('/file');"),
    ] {
        let subject = Subject::Source {
            dialect: None,
            language: language.into(),
            source: source.into(),
            cwd: None,
            context: Default::default(),
        };
        let plan = engine.analyze(&subject).unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{language}"
        );
        let result = measure_symbolic_mutations(
            &engine,
            &plan,
            &[Req {
                attributes: Default::default(),
                op: "filesystem.delete".into(),
                resource: ResourceMatch::Any(true),
            }],
            None,
            None,
        );
        assert_eq!(result.exercised, 0, "{language}: {result:?}");
        assert!(
            result.reasons["source_language_transform_unsupported"] > 0,
            "{language}: {result:?}"
        );
    }
}
