#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use effinterp_bench::invocation::score::Scoreboard;
use effinterp_bench::nah::classify::ParityClass;
use effinterp_bench::nah::corpus::{CaseLoad, fixture_corpus_digest, load_corpus};
use effinterp_bench::nah::goldens::{ResourceMatch, is_complete, load_goldens};
use effinterp_bench::nah::report::{
    Ceilings, Parity, check_block_gaps, check_ceilings, check_guard_silent, parity, run_corpus,
};
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

fn committed_ceilings() -> Ceilings {
    serde_json::from_slice(&fs::read(repo_dir().join("bench/nah/ceilings.json")).unwrap()).unwrap()
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
            refusal,
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
        if golden.guard != *guard || golden.require_refusal != *refusal || !is_complete(golden) {
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
                "machine/outside-workspace-delete"
                    | "machine/home-folder-modify"
                    | "machine/disk-overwrite"
                    | "machine/system-files-modify"
                    | "machine/permissions-weaken"
                    | "secrets/env-files-read"
                    | "exfiltration/secret-upload"
                    | "secrets/key-files-access"
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
                || (golden.guard.as_deref() == Some("exfiltration/secret-upload")
                    && req.op == "credential.read"
                    && matches!(req.resource, ResourceMatch::Any(true)))
                || listener_upload(req)
        };
        // A credential disclosed from repository history has no working-tree
        // read; the historical object read is its source. One staged into Git
        // is named by the staging selection the host observes.
        let names_credential_source = |req: &effinterp_bench::nah::goldens::Req| {
            req.op.starts_with("filesystem.")
                || (req.op == "git.read"
                    && (req.attributes.get("historical") == Some(&AttrValue::Bool(true))
                        || req.attributes.contains_key("content_selection")
                            && req.attributes.get("access_purpose")
                                == Some(&AttrValue::String("program_input".into()))))
                || (req.op == "credential.read_request"
                    && matches!(req.resource, ResourceMatch::Eq(_)))
        };
        // A credential value typed out in the call has no read: the bridge
        // finds the hook environment's value in the call's own text, so the
        // requirement pins where the value goes instead.
        let typed_out_value = golden.id.starts_with("secrets-credentials.retyped-value-");
        if golden
            .require
            .iter()
            .any(|requirement| !exact_requirement(requirement))
            || golden.require_flow.iter().any(|flow| {
                !exact_requirement(&flow.from)
                    || !(matches!(flow.to.resource, ResourceMatch::Eq(_))
                        || listener_upload(&flow.to))
            })
            || (golden.guard.as_deref() == Some("secrets/key-files-access")
                && !typed_out_value
                && !golden.require.iter().any(names_credential_source))
        {
            weak.push(golden.id.clone());
        }
    }
    assert!(weak.is_empty(), "weak corpus goldens: {weak:?}");
}

#[test]
fn live_parity_does_not_regress() {
    let corpus = repo_dir().join("corpus");
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        load_corpus(&corpus).unwrap(),
        fixture_corpus_digest(&corpus).unwrap(),
        String::new(),
    );
    assert_eq!(report.flow.depth_saturated_plans, 0);
    assert_eq!(report.flow.pair_saturated_plans, 0);
    assert_eq!(report.flow.producer_saturated_plans, 0);
    let live = parity(&report);
    let baseline = committed_parity();
    let ceilings = committed_ceilings();
    let mut failures = check_block_gaps(&live, &ceilings);
    failures.extend(check_ceilings(&live, &ceilings));
    failures.extend(check_guard_silent(&live, &ceilings));
    let passes = |counts: &BTreeMap<ParityClass, usize>| {
        counts.get(&ParityClass::EffectMatch).copied().unwrap_or(0)
            + counts.get(&ParityClass::RefusalMatch).copied().unwrap_or(0)
    };
    for (guard, counts) in &baseline.per_guard {
        // guard_splits counts reviewed sibling rules toward the old rule's floor until publication.
        let current = std::iter::once(guard)
            .chain(ceilings.guard_splits.get(guard).into_iter().flatten())
            .filter_map(|guard| live.per_guard.get(guard));
        let before: usize = counts.values().sum();
        let after: usize = current.clone().flat_map(|counts| counts.values()).sum();
        if after < before {
            failures.push(format!("{guard}: block row count {before} -> {after}"));
        }
        let before = passes(counts);
        let after: usize = current.map(passes).sum();
        if after < before {
            failures.push(format!(
                "{guard}: passing block row count {before} -> {after}"
            ));
        }
    }
    for (guard, rows) in &live.guard_silent {
        for id in rows {
            let reviewed = baseline
                .guard_silent
                .get(guard)
                .is_some_and(|before| before.contains(id))
                || ceilings
                    .guard_silent
                    .get(guard)
                    .is_some_and(|rows| rows.contains(id));
            if !reviewed {
                failures.push(format!(
                    "{id}: golden passes but the query for {guard} cannot fire"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn committed_parity_stays_within_ceilings() {
    let ceilings = committed_ceilings();
    let exceeded = check_ceilings(&committed_parity(), &ceilings);
    assert!(exceeded.is_empty(), "{}", exceeded.join("\n"));
}
