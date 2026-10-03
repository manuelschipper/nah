//! Integrity of the committed invocation corpus: it matches its manifest, every
//! row loads with a fixture cwd under /corpus/, no secret or owner path leaked
//! through vendoring, and the directory stays small.
#![allow(clippy::disallowed_macros, clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use effinterp_bench::invocation::corpus::{
    INVOCATION_MANIFEST_SCHEMA, load_invocation_rows, read_invocation_manifest,
};
use effinterp_bench::nah::corpus::fixture_corpus_digest;

const MAX_BYTES: u64 = 30 * 1024 * 1024;
const SECRETS: &[&str] = &[
    "ghp_",
    "sk-",
    "AKIA",
    "xoxb-",
    "xoxa-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "-----BEGIN",
    "Bearer ",
    "token=",
    "password=",
    "api_key",
    "api-key",
    "apikey",
];
const OWNER_PATHS: &[&str] = &["/home/dev", "schipper", "badlogic"];

#[test]
fn corpus_matches_manifest_and_leaks_nothing() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/invocation");
    if !dir.join("MANIFEST.json").exists() {
        eprintln!("skipped: {} has no MANIFEST.json yet", dir.display());
        return;
    }
    let manifest = read_invocation_manifest(&dir).unwrap();
    assert_eq!(manifest.schema, INVOCATION_MANIFEST_SCHEMA);
    assert_eq!(manifest.corpus_digest, fixture_corpus_digest(&dir).unwrap());

    let mut bytes = 0;
    let mut listing = BTreeSet::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        bytes += entry.metadata().unwrap().len();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "MANIFEST.json" {
            listing.insert(name);
        }
    }
    assert!(bytes <= MAX_BYTES, "{bytes} bytes");
    assert_eq!(
        manifest.files.iter().cloned().collect::<BTreeSet<_>>(),
        listing
    );

    for name in listing.iter().filter(|name| name.ends_with(".jsonl")) {
        let text = fs::read_to_string(dir.join(name)).unwrap();
        for (index, line) in text.lines().enumerate() {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            let id = row["id"].as_str().unwrap();
            for needle in OWNER_PATHS {
                assert!(
                    !line.contains(needle),
                    "{name}:{} contains {needle:?}",
                    index + 1
                );
            }
            // The extractor scans command text only and records reviewed hits.
            if manifest.audit_allow.contains_key(id) {
                continue;
            }
            let command = row["command"].as_str().unwrap();
            for needle in SECRETS {
                assert!(
                    !command.contains(needle),
                    "{name}:{} ({id}) contains {needle:?}",
                    index + 1
                );
            }
        }
    }

    let rows = load_invocation_rows(&dir).unwrap();
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate id {}", row.id);
        let cwd = match &row.subject {
            effinterp_proto::Subject::Shell { cwd, .. }
            | effinterp_proto::Subject::Source { cwd, .. } => cwd.as_deref(),
            _ => None,
        };
        assert!(
            cwd.is_some_and(|cwd| cwd.starts_with("/corpus/")),
            "{}: cwd {cwd:?}",
            row.id
        );
    }
    for (source, entry) in &manifest.sources {
        let in_file: Vec<_> = rows
            .iter()
            .filter(|row| row.file == format!("{source}.jsonl"))
            .collect();
        assert_eq!(in_file.len(), entry.row_count, "{source} row_count");
        assert_eq!(
            in_file.iter().map(|row| row.weight).sum::<u64>(),
            entry.weight_sum,
            "{source} weight_sum"
        );
        assert!(in_file.iter().all(|row| row.source == *source), "{source}");
    }
}

// A session refresh must not reset correctness regression comparisons.
#[test]
fn session_refresh_preserves_correctness_scope() {
    use effinterp_bench::invocation::corpus::correctness_digest;
    let dir = tempfile::tempdir().unwrap();
    for name in ["FIXTURES.json", "adversarial.jsonl", "swe.jsonl"] {
        fs::write(dir.path().join(name), name).unwrap();
    }
    let before = correctness_digest(dir.path()).unwrap();
    fs::write(dir.path().join("swe.jsonl"), "new trajectories").unwrap();
    assert_eq!(before, correctness_digest(dir.path()).unwrap());
    fs::write(dir.path().join("adversarial.jsonl"), "new expectations").unwrap();
    assert_ne!(before, correctness_digest(dir.path()).unwrap());
}
