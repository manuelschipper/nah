use std::path::PathBuf;

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn surface_repo(tag: &str) -> PathBuf {
    repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[
            ("direct.sh", "#!/bin/sh\nrm -f /direct\nmystery-command\n"),
            (
                "exact.py",
                "#!/usr/bin/env python3\nfrom exact_util import wipe\nwipe()\n",
            ),
            (
                "exact_util.py",
                "import os\ndef wipe(): os.remove('/exact')\n",
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
            (
                "src/main.rs",
                "mod trait_def;\nmod impl_0;\nmod impl_1;\nmod impl_2;\nuse crate::trait_def::Wipe;\nfn main() { let value: &dyn Wipe = external(); value.wipe(); }\n",
            ),
            ("src/trait_def.rs", "pub trait Wipe { fn wipe(&self); }\n"),
            (
                "src/impl_0.rs",
                "use crate::trait_def::Wipe;\npub struct Type0;\nimpl Wipe for Type0 { fn wipe(&self) { std::fs::remove_file(\"/alternative-0\").ok(); } }\n",
            ),
            (
                "src/impl_1.rs",
                "use crate::trait_def::Wipe;\npub struct Type1;\nimpl Wipe for Type1 { fn wipe(&self) { std::fs::remove_file(\"/alternative-1\").ok(); } }\n",
            ),
            (
                "src/impl_2.rs",
                "use crate::trait_def::Wipe;\npub struct Type2;\nimpl Wipe for Type2 { fn wipe(&self) { std::fs::remove_file(\"/alternative-2\").ok(); } }\n",
            ),
        ],
    )
}

fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

fn assert_dispatch(value: &serde_json::Value) {
    let dispatch = &value["dispatch"];
    assert_eq!(dispatch["model"], "argparse", "{value}");
    assert!(dispatch.get("registration_path").is_none());
    assert!(dispatch.get("dispatch_path").is_none());
    for field in ["registration_roots", "dispatch_roots"] {
        let roots = dispatch[field].as_array().unwrap();
        assert_eq!(roots.len(), 1);
        assert!(roots[0].as_str().unwrap().starts_with("occurrence:blake3:"));
    }
}

fn assert_no_metadata(value: &serde_json::Value) {
    let object = value.as_object().unwrap();
    assert!(!object.contains_key("assurance"));
    assert!(!object.contains_key("dispatch"));
}

fn display(fact: &effinterp_proto::EffectFact) -> String {
    effinterp_proto::display_resource(&fact.resource)
}

#[test]
fn forward_and_reverse_queries_surface_canonical_metadata() {
    let index = build_index(&surface_repo("effect-ir-surface"), IndexLimits::default());

    let direct_report = effects_of(&index, "direct.sh").unwrap();
    let direct = direct_report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|fact| display(fact) == "fs:/direct")
        .unwrap();
    assert_no_metadata(&json(direct));
    let direct_id = direct.fact_id.clone();

    let direct_reach = reach(
        &index,
        &ResourceSelector::parse("fs:/direct").unwrap(),
        None,
    )
    .payload
    .into_reach()
    .unwrap()
    .matches
    .into_iter()
    .find(|row| row.fact.fact_id == direct_id)
    .unwrap();
    assert_eq!(direct_reach.fact, *direct);
    for obsolete in [
        "occurrence_id",
        "resource_expression",
        "resource_identity",
        "destructive",
        "origin_file",
        "via_dispatch",
        "explanation",
        "path",
    ] {
        assert!(!json(direct).as_object().unwrap().contains_key(obsolete));
    }

    let ordinary_indeterminate = reach(
        &index,
        &ResourceSelector::parse("fs:/not-present").unwrap(),
        None,
    )
    .payload
    .into_reach()
    .unwrap()
    .indeterminate
    .into_iter()
    .filter_map(|row| match row {
        effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
        _ => None,
    })
    .find(|row| row.entrypoint == "direct.sh")
    .unwrap();
    assert_no_metadata(&json(&ordinary_indeterminate));
    let exact = effects_of(&index, "exact.py").unwrap();
    let exact = exact
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|fact| display(fact) == "fs:/exact")
        .unwrap();
    assert_eq!(json(exact)["assurance"], "exact");
    assert!(exact.dispatch.is_none());

    let alternatives = effects_of(&index, "src/main.rs").unwrap();
    let alternative_rows: Vec<_> = alternatives
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|fact| display(fact).starts_with("fs:/alternative-"))
        .collect();
    assert_eq!(
        alternative_rows
            .iter()
            .map(|fact| display(fact))
            .collect::<Vec<_>>(),
        [
            "fs:/alternative-0".to_string(),
            "fs:/alternative-1".to_string(),
            "fs:/alternative-2".to_string()
        ]
    );
    assert!(alternative_rows.iter().all(|fact| {
        fact.assurance
            .is_some_and(|value| value.as_str() == "alternatives")
    }));

    let heuristic = effects_of(&index, "heuristic.py").unwrap();
    let effect = heuristic
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|fact| display(fact) == "fs:/dispatched")
        .unwrap();
    let effect_json = json(effect);
    assert_eq!(effect_json["assurance"], "heuristic");
    assert_dispatch(&effect_json);
    let effect_id = effect.fact_id.clone();

    let selector = ResourceSelector::parse("fs:/dispatched").unwrap();
    let reach_row = reach(&index, &selector, None)
        .payload
        .into_reach()
        .unwrap()
        .matches
        .into_iter()
        .find(|row| row.fact.fact_id == effect_id)
        .unwrap();
    assert_eq!(reach_row.fact, *effect);

    let dispatched_boundary = heuristic
        .payload
        .as_effects()
        .unwrap()
        .boundaries
        .iter()
        .find(|row| row.reason == "cross_module")
        .unwrap();
    assert_dispatch(&json(dispatched_boundary));

    let indeterminate = reach(
        &index,
        &ResourceSelector::parse("fs:/not-present").unwrap(),
        None,
    )
    .payload
    .into_reach()
    .unwrap()
    .indeterminate
    .into_iter()
    .filter_map(|row| match row {
        effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
        _ => None,
    })
    .find(|row| row.entrypoint == "heuristic.py" && row.boundary_reason == "cross_module")
    .unwrap();
    assert_dispatch(&json(&indeterminate));

    let ordinary_boundary = effects_of(&index, "direct.sh")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .boundaries
        .into_iter()
        .find(|row| row.dispatch.is_none())
        .unwrap();
    assert_no_metadata(&json(&ordinary_boundary));
}
