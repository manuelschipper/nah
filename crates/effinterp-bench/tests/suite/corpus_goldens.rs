#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use effinterp_bench::bench::score::Scoreboard;
use effinterp_bench::nah::corpus::{CaseLoad, corpus_digest, load_corpus};
use effinterp_bench::nah::goldens::{ResourceMatch, is_complete, load_goldens};
use effinterp_bench::nah::report::{Ceilings, Parity, check_ceilings, parity, run_corpus};
use effinterp_engine::Engine;
use effinterp_proto::AttrValue;
use nah_corpus_schema::{CaseInput, Expectation, ExpectedVerdict};

fn repo_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn committed_parity() -> Parity {
    let scoreboard: Scoreboard =
        serde_json::from_slice(&fs::read(repo_dir().join("bench/scoreboard.json")).unwrap())
            .unwrap();
    scoreboard
        .correctness
        .parity
        .expect("bench/scoreboard.json carries a parity section")
}

#[test]
fn every_expected_block_case_has_a_complete_golden() {
    let corpus = repo_dir().join("corpus");
    assert!(corpus.is_dir(), "nah corpus is required");

    let goldens = load_goldens();
    for golden in goldens.values() {
        for requirement in golden.require.iter().chain(
            golden
                .require_flow
                .iter()
                .flat_map(|flow| [&flow.from, &flow.to]),
        ) {
            assert!(
                requirement.op == "value"
                    || effinterp_proto::OPERATIONS.iter().any(|operation| {
                        operation.name == requirement.op
                            || operation.name.starts_with(&format!("{}.", requirement.op))
                    }),
                "{} requires unregistered operation {}",
                golden.id,
                requirement.op
            );
        }
    }
    let mut missing = Vec::new();
    let mut stale = Vec::new();
    let mut ids = BTreeSet::new();
    for load in load_corpus(&corpus).expect("nah corpus loads") {
        let CaseLoad::Ok(case) = load else {
            panic!("nah corpus contains a malformed row");
        };
        ids.insert(case.id.clone());
        if matches!(case.input, CaseInput::Command(_)) {
            assert!(case.cwd.is_some(), "{} has no analysis cwd", case.id);
        }
        let Expectation::Decision {
            verdict: ExpectedVerdict::Block,
            guard,
            ..
        } = &case.expected
        else {
            if goldens.contains_key(&case.id) {
                stale.push(case.id.clone());
            }
            continue;
        };
        let Some(golden) = goldens.get(&case.id) else {
            missing.push(case.id.clone());
            continue;
        };
        if golden.guard != *guard || !is_complete(golden) {
            missing.push(case.id.clone());
        }
    }
    let orphans: Vec<_> = goldens.keys().filter(|id| !ids.contains(*id)).collect();
    assert!(
        missing.is_empty() && stale.is_empty() && orphans.is_empty(),
        "incomplete corpus goldens: {missing:?}; stale goldens: {stale:?}; orphan goldens: {orphans:?}"
    );
}

#[test]
fn reviewed_protected_resource_requirements_are_exact() {
    let goldens = load_goldens();
    let mut weak = Vec::new();
    for golden in goldens.values() {
        let reviewed_guard = matches!(
            golden.guard.as_deref(),
            Some(
                "fs-home"
                    | "fs-raw-device"
                    | "fs-volume-destroy"
                    | "fs-system-tree"
                    | "fs-outside-workspace-delete"
                    | "fs-permission-weaken"
                    | "secrets-env"
                    | "secrets-exfil"
                    | "secrets-credentials"
            )
        );
        // A listening socket sends to whoever connects, so its upload has no
        // peer to name; the requirement pins the listener's address instead.
        let listener_upload = |req: &effinterp_bench::nah::goldens::Req| {
            req.op == "network.upload"
                && matches!(req.resource, ResourceMatch::Any(true))
                && req.attributes.get("listen") == Some(&AttrValue::Bool(true))
                && req.attributes.contains_key("address")
        };
        let self_protection = golden.id.starts_with("self-protection.")
            || golden.id == "windows.pwsh.attached-redirection-nah-config";
        if !reviewed_guard && !self_protection {
            continue;
        }
        // Credential stores have no filesystem identity; only their exfiltration
        // source is unconstrained. The upload sink remains exact. A set-valued
        // read (a literal loop over several paths) names each protected member
        // by its absolute path inside the set expression.
        let exact_requirement = |req: &effinterp_bench::nah::goldens::Req| {
            matches!(req.resource, ResourceMatch::Eq(_))
                || matches!(&req.resource, ResourceMatch::Contains(path) if path.starts_with('/'))
                || (golden.guard.as_deref() == Some("secrets-exfil")
                    && req.op == "credential.read"
                    && matches!(req.resource, ResourceMatch::Any(true)))
                || listener_upload(req)
        };
        // A credential disclosed from repository history has no working-tree
        // read; the historical object read is its source.
        let names_credential_source = |req: &effinterp_bench::nah::goldens::Req| {
            req.op.starts_with("filesystem.")
                || (req.op == "git.read"
                    && req.attributes.get("historical") == Some(&AttrValue::Bool(true)))
                || (req.op == "credential.read_request"
                    && matches!(req.resource, ResourceMatch::Eq(_)))
        };
        if golden
            .require
            .iter()
            .any(|requirement| !exact_requirement(requirement))
            || golden.require_flow.iter().any(|flow| {
                !exact_requirement(&flow.from)
                    || !(matches!(flow.to.resource, ResourceMatch::Eq(_))
                        || listener_upload(&flow.to))
            })
            || (golden.guard.as_deref() == Some("secrets-credentials")
                && !golden.require.iter().any(names_credential_source))
        {
            weak.push(golden.id.clone());
        }
    }
    assert!(weak.is_empty(), "weak corpus goldens: {weak:?}");
}

#[test]
fn committed_parity_is_fresh_and_measures_every_guard() {
    let corpus = repo_dir().join("corpus");
    let parity = committed_parity();
    assert_eq!(parity.corpus_digest, corpus_digest(&corpus).unwrap());
    let guards: BTreeSet<_> = load_corpus(&corpus)
        .unwrap()
        .into_iter()
        .filter_map(|load| {
            let CaseLoad::Ok(case) = load else {
                panic!("malformed corpus row")
            };
            let Expectation::Decision {
                verdict: ExpectedVerdict::Block,
                guard,
                ..
            } = case.expected
            else {
                return None;
            };
            Some(guard.unwrap_or_else(|| "(structural)".to_string()))
        })
        .collect();
    assert_eq!(
        parity.per_guard.into_keys().collect::<BTreeSet<_>>(),
        guards
    );
}

#[test]
fn committed_parity_matches_the_engine() {
    let corpus = repo_dir().join("corpus");
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        load_corpus(&corpus).unwrap(),
        corpus_digest(&corpus).unwrap(),
        // Reuse recorded provenance; corpus freshness is checked by digest.
        committed_parity().nah_commit,
    );
    assert_eq!(report.flow.depth_saturated_plans, 0);
    assert_eq!(report.flow.pair_saturated_plans, 0);
    assert_eq!(report.flow.producer_saturated_plans, 0);
    let live = parity(&report);
    assert_eq!(
        live,
        committed_parity(),
        "regenerate bench/scoreboard.json with effinterp-bench measure --group correctness, then publish RUN"
    );
}

#[test]
fn committed_parity_stays_within_ceilings() {
    let ceilings: Ceilings =
        serde_json::from_slice(&fs::read(repo_dir().join("bench/nah/ceilings.json")).unwrap())
            .unwrap();
    let exceeded = check_ceilings(&committed_parity(), &ceilings);
    assert!(exceeded.is_empty(), "{}", exceeded.join("\n"));
}
