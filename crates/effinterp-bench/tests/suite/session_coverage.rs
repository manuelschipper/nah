#![allow(clippy::disallowed_methods)]

use std::fs;

use effinterp_bench::invocation::sessions;
use serde_json::json;
use sha2::{Digest, Sha256};

// External snapshots must not silently change scores, inflate duplicate cases,
// or expose the benchmark host through cwd/env taken from a recorded session.
#[test]
fn session_snapshots_preserve_weights_and_reject_changed_or_host_dependent_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let write = |rows: &[serde_json::Value]| {
        let text = rows
            .iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>();
        fs::write(dir.path().join("cases.jsonl"), &text).unwrap();
        fs::write(
            dir.path().join("MANIFEST.json"),
            json!({"schema": "effinterp/session-coverage/v1",
                   "cases_sha256": format!("{:x}", Sha256::digest(text.as_bytes()))})
            .to_string(),
        )
        .unwrap();
    };
    let row = json!({"id":"one", "source":"sessions", "weight":7,
                     "subject":{"kind":"shell", "source":"echo hello"}});
    write(std::slice::from_ref(&row));
    let original = sessions::session_corpus_digest(dir.path()).unwrap();
    assert_eq!(
        sessions::load_session_rows(dir.path(), None).unwrap()[0].weight,
        7
    );
    fs::write(dir.path().join("cases.jsonl"), "{}\n").unwrap();
    assert!(
        sessions::load_session_rows(dir.path(), None)
            .unwrap_err()
            .contains("checksum")
    );

    let mut changed = row.clone();
    changed["weight"] = json!(8);
    write(&[changed]);
    assert_ne!(
        original,
        sessions::session_corpus_digest(dir.path()).unwrap()
    );
    write(&[row.clone(), row.clone()]);
    assert!(
        sessions::load_session_rows(dir.path(), None)
            .unwrap_err()
            .contains("duplicate")
    );
    let mut hosted = row;
    hosted["subject"]["cwd"] = json!(dir.path());
    write(&[hosted]);
    assert!(
        sessions::load_session_rows(dir.path(), None)
            .unwrap_err()
            .contains("host context")
    );
}
