use effinterp_repo::{Selector, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use super::{json, live};

#[test]
fn reach_dataflow_boundary_reports_indeterminate_without_effect_coverage() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "repo-suite-query-reach-dataflow",
        &[("run.sh", "#!/bin/sh\nrm -f \"${TARGET:-$(date +%s)}\"\n")],
    );
    let envelope = reach(&live(&root), &Selector::parse("dataflow:x").unwrap(), None);
    assert_eq!(json(&envelope)["status"]["kind"], "partial");
    let payload = envelope.payload.as_reach().unwrap();
    assert!(payload.matches.is_empty());
    assert!(!payload.indeterminate.is_empty());
    for row in &payload.indeterminate {
        let effinterp_proto::Indeterminate::Boundary { evidence: hit } = row else {
            panic!("expected boundary evidence");
        };
        assert_eq!(hit.domain, "dataflow");
        assert_eq!(hit.coverage, effinterp_proto::CoverageLevel::None);
        assert!(
            envelope
                .boundaries
                .iter()
                .any(|b| b.id == hit.boundary_id.0)
        );
    }
    assert_eq!(
        envelope.coverage.causality.as_ref().unwrap().level,
        effinterp_proto::CoverageLevel::None
    );
}

fn fixture(tag: &str) -> std::path::PathBuf {
    repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[
            ("direct.sh", "#!/bin/sh\nrm -f /direct\n"),
            (
                "build.rs",
                "fn main() { let _ = std::env::current_dir(); }\n",
            ),
            (
                "heuristic.py",
                r#"#!/usr/bin/env python3
import argparse
import missing
import os
parser = argparse.ArgumentParser()
def command():
    os.remove("/dispatched")
    missing.opaque()
parser.set_defaults(func=command)
parser.parse_args()
"#,
            ),
        ],
    )
}

/// The single typed resource a fact carries, rendered the way the CLI does.
fn display(row: &serde_json::Value) -> String {
    let resource: effinterp_proto::ResourceExpr =
        serde_json::from_value(row["resource"].clone()).expect("typed resource");
    effinterp_proto::display_resource(&resource)
}

fn assert_dispatch_json(envelope: &serde_json::Value, row: &serde_json::Value) {
    assert_eq!(row["dispatch"]["model"], "argparse");
    for field in ["registration_roots", "dispatch_roots"] {
        let roots = row["dispatch"][field].as_array().unwrap();
        assert_eq!(roots.len(), 1);
        let root = roots[0].as_str().unwrap();
        let node = envelope["provenance"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["id"] == root)
            .unwrap();
        assert_eq!(node["occurrence"]["origin"], "heuristic.py");
        assert_eq!(node["evidence"]["kind"], "entrypoint");
        assert_eq!(node["evidence"]["entrypoint"], "heuristic.py");
    }
}

#[test]
fn unrelated_skipped_source_does_not_taint_an_independent_entrypoint() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "repo-suite-query-scoped-skipped-source",
        &[
            (
                "main.py",
                "#!/usr/bin/env python3\nimport skipped\nprint('main')\n",
            ),
            ("independent.sh", "#!/bin/sh\necho independent\n"),
        ],
    );
    std::fs::write(root.join("skipped.py"), [0xff, 0xfe]).unwrap();
    let index = live(&root);

    let independent = json(&effects_of(&index, "independent.sh").unwrap());
    assert_eq!(independent["status"]["kind"], "complete");
    let dependent = json(&effects_of(&index, "main.py").unwrap());
    assert_eq!(dependent["status"]["kind"], "partial");
    assert!(
        dependent["status"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason["kind"] == "unanalyzed_input" && reason["path"] == "skipped.py")
    );
}

#[test]
fn effect_and_boundary_facts_carry_metadata() {
    let root = fixture("repo-suite-effect-ir-assurance-live");
    let index = live(&root);

    let effects_json = json(&effects_of(&index, "heuristic.py").unwrap());
    assert_eq!(effects_json["status"]["kind"], "partial");
    let effect = effects_json["payload"]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| display(row) == "fs:/dispatched")
        .unwrap();
    assert_eq!(effect["assurance"], "heuristic");
    assert_dispatch_json(&effects_json, effect);

    let boundary = effects_json["payload"]["boundaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["reason"] == "cross_module")
        .unwrap();
    assert_eq!(boundary["dispatch"]["model"], "argparse");
    assert_eq!(boundary["occurrences"], 1);
    assert!(!boundary["exemplar_paths"].as_array().unwrap().is_empty());
    assert_dispatch_json(&effects_json, boundary);

    let direct_json = json(&effects_of(&index, "direct.sh").unwrap());
    assert_eq!(direct_json["status"]["kind"], "complete");
    let direct = direct_json["payload"]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| display(row) == "fs:/direct")
        .unwrap()
        .as_object()
        .unwrap();
    assert!(!direct.contains_key("assurance"));
    assert!(!direct.contains_key("dispatch"));

    let rust_json = json(&effects_of(&index, "build.rs").unwrap());
    assert_eq!(rust_json["status"]["kind"], "partial");
    let boundary = rust_json["payload"]["boundaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["reason"] == "external_unmodeled")
        .unwrap();
    // `std::env::current_dir` is unmodeled but exactly identified, so the
    // boundary clouds only the environment domain.
    assert_eq!(boundary["domains"], serde_json::json!(["environment"]));
}

#[test]
fn reach_and_forward_facts_carry_the_same_dispatch_metadata() {
    let root = fixture("repo-suite-effect-ir-assurance-reach");
    let index = live(&root);

    let reach_json = json(&reach(
        &index,
        &Selector::parse("fs:/dispatched").unwrap(),
        None,
    ));
    assert_eq!(reach_json["status"]["kind"], "partial");
    assert_dispatch_json(&reach_json, &reach_json["payload"]["matches"][0]["fact"]);
    assert_eq!(
        reach_json["payload"]["indeterminate"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["boundary_reason"] == "cross_module")
            .unwrap()["dispatch"]["model"],
        "argparse"
    );
    assert_eq!(
        reach_json["payload"]["matches"][0]["match"]["kind"],
        "satisfied"
    );

    // The reverse match is the same fact the forward query reports.
    let effects_json = json(&effects_of(&index, "heuristic.py").unwrap());
    let forward = effects_json["payload"]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| display(row) == "fs:/dispatched")
        .unwrap();
    assert_eq!(
        reach_json["payload"]["matches"][0]["fact"]["fact_id"],
        forward["fact_id"]
    );
}

#[test]
fn cross_file_effects_carry_the_complete_entrypoint_path() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "repo-suite-origins-complete-path",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom mid import go\ngo()\ngo()\n",
            ),
            ("mid.py", "from util import wipe\ndef go():\n    wipe()\n"),
            (
                "util.py",
                "import shutil\ndef wipe():\n    shutil.rmtree('/complete-path')\n",
            ),
        ],
    );
    let envelope = json(&effects_of(&live(&root), "app.py").unwrap());
    let effect = envelope["payload"]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["origin"]["source_file"] == "util.py")
        .unwrap();
    assert_eq!(effect["occurrences"], 2);
    assert_eq!(effect["exemplar_paths"].as_array().unwrap().len(), 1);
    let roots = effect["provenance_roots"].as_array().unwrap();
    let mut seen: std::collections::BTreeSet<String> = roots
        .iter()
        .map(|root| root.as_str().unwrap().to_string())
        .collect();
    let mut pending: Vec<String> = seen.iter().cloned().collect();
    while let Some(id) = pending.pop() {
        for edge in envelope["provenance"]["edges"].as_array().unwrap() {
            if edge["to"].as_str() == Some(id.as_str()) {
                let antecedent = edge["from"].as_str().unwrap().to_string();
                if seen.insert(antecedent.clone()) {
                    pending.push(antecedent);
                }
            }
        }
    }
    let expected: Vec<String> = envelope["provenance"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|node| seen.contains(node["id"].as_str().unwrap()))
        .filter_map(|node| match node["evidence"]["kind"].as_str() {
            Some("entrypoint") => {
                Some(node["evidence"]["entrypoint"].as_str().unwrap().to_string())
            }
            Some("cross_file_call") => Some(format!(
                "{} -> {}",
                node["evidence"]["from"].as_str().unwrap(),
                node["evidence"]["into"].as_str().unwrap(),
            )),
            _ => None,
        })
        .collect();
    assert!(expected.len() >= 2);
    let entrypoint = effect["entrypoint"].as_str().unwrap();
    assert!(expected.iter().any(|step| step.starts_with(entrypoint)));
}

#[test]
fn reach_keeps_provenance_distinct_compound_writes() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "repo-suite-reach-compound",
        &[(
            "run.sh",
            "#!/bin/sh\ngit -C /repo config user.name one\n. ./helper.sh\ngit -C /repo add .\ngit -C /repo checkout main\nmystery-command\nmystery-command\n",
        )],
    );
    std::fs::write(
        root.join("helper.sh"),
        "#!/bin/sh\ngit -C /repo config user.name two\n",
    )
    .unwrap();

    let envelope = reach(
        &live(&root),
        &Selector::parse("git:/repo").unwrap(),
        Some("write"),
    );
    json(&envelope);
    let hits = &envelope.payload.as_reach().unwrap().matches;
    for operation in ["git.config_write", "git.index_write", "git.worktree_write"] {
        assert!(
            hits.iter()
                .any(|hit| hit.fact.operation.as_str() == operation)
        );
    }
    assert!(
        hits.iter()
            .filter(|hit| hit.fact.operation.as_str() == "git.config_write")
            .count()
            >= 2
    );
    let boundary_rows = envelope
        .payload
        .as_reach()
        .unwrap()
        .indeterminate
        .iter()
        .filter(|row| matches!(row, effinterp_proto::Indeterminate::Boundary { .. }))
        .count();
    assert!(boundary_rows > 0);
}
