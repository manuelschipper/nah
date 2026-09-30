#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! `nah test`: a human-readable dry run that reports the decision, always exits
//! successfully, and never appends an audit record.

use crate::support;

use support::{nah, repo};

#[test]
fn test_command_is_a_human_dry_run_and_does_not_write_an_audit_record() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "echo hello"], None);

    assert!(output.status.success(), "{output:?}");
    // The decision reports the host-resolved path, including macOS symlinks
    // and Windows short names, so redact either form nah may print.
    let printed = [support::test_temp_path(&project), project]
        .map(|path| serde_json::to_string(path.to_str().unwrap()).unwrap());
    let stdout = printed
        .iter()
        .fold(String::from_utf8(output.stdout).unwrap(), |stdout, path| {
            stdout.replace(path.trim_matches('"'), "<project>")
        })
        // The producer identity is derived from the engine's sources, which
        // move with every engine change.
        .lines()
        .map(|line| {
            if line.starts_with("producer: effinterp/blake3:") {
                "producer: effinterp/blake3:<identity>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .map(|line| line + "\n")
        .collect::<String>();
    assert_eq!(stdout, include_str!("../golden/test-echo.txt"));
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}

#[test]
fn test_command_returns_success_after_a_blocked_dry_run() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let output = nah(temp.path(), &project, &["test", "rm -rf /"], None);

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("verdict: block\n")
    );
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}
