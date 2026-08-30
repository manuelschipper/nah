//! The hidden effinterp shadow switch: `~/.nah/effinterp.json`, the one-call
//! `--effinterp` flag, and the shadow stream recorded on each decision.
#![cfg(feature = "effinterp")]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use nah_proto::decision::{DecisionOutput, Verdict};
use serde_json::{Value, json};

/// A corpus case both streams agree on: a recursive delete of a system tree.
const AGREED_BLOCK: &str = "rm -rf /etc";
/// A case the old lowering and effectinterp describe differently.
const DISAGREED_BLOCK: &str = "git push --force";

fn nah(home: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(arguments)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap()
}

fn decide(home: &Path, cwd: &Path, command: &str, arguments: &[&str]) -> DecisionOutput {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("decide")
        .args(arguments)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({
                "v": 1,
                "tool": "Bash",
                "input": {"command": command},
                "cwd": cwd,
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

fn audit_records(home: &Path, arguments: &[&str]) -> Vec<Value> {
    let output = nah(home, arguments);
    assert!(output.status.success(), "nah log failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn latest_record(home: &Path) -> Value {
    audit_records(home, &["log", "--json", "-n", "1"])
        .pop()
        .expect("a decision was recorded")
}

fn temp_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let path = support::test_temp_path(directory.path());
    (directory, path)
}

#[test]
fn the_shadow_stream_is_absent_until_the_state_file_enables_it() {
    let (_home_temp, home) = temp_home();
    let (_cwd_temp, cwd) = temp_home();

    let before = decide(&home, &cwd, AGREED_BLOCK, &[]);
    assert_eq!(before.verdict(), Verdict::Block);
    assert!(latest_record(&home).get("effinterp").is_none());

    let enabled = nah(&home, &["effinterp", "on"]);
    assert!(enabled.status.success());
    let state = home.join(".nah/effinterp.json");
    assert_eq!(
        serde_json::from_str::<Value>(&std::fs::read_to_string(&state).unwrap()).unwrap(),
        json!({"v": 1, "enabled": true})
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let after = decide(&home, &cwd, AGREED_BLOCK, &[]);
    assert_eq!(
        after.verdict(),
        before.verdict(),
        "shadow changes no verdict"
    );
    let stream = latest_record(&home);
    let stream = stream.get("effinterp").expect("shadow stream is recorded");
    assert!(stream["engine_time_us"].as_u64().is_some());
    assert_eq!(
        stream["effects"].as_array().unwrap().len(),
        stream["annotations"].as_array().unwrap().len(),
        "one annotation per interpreted effect"
    );

    assert!(nah(&home, &["effinterp", "off"]).status.success());
    let disabled = decide(&home, &cwd, AGREED_BLOCK, &[]);
    assert_eq!(disabled.verdict(), before.verdict());
    assert!(latest_record(&home).get("effinterp").is_none());
}

#[test]
fn the_hidden_flag_forces_the_shadow_stream_for_one_call() {
    let (_home_temp, home) = temp_home();
    let (_cwd_temp, cwd) = temp_home();

    let forced = decide(&home, &cwd, AGREED_BLOCK, &["--effinterp"]);
    assert_eq!(forced.verdict(), Verdict::Block);
    assert!(!home.join(".nah/effinterp.json").exists());
    assert!(latest_record(&home).get("effinterp").is_some());

    decide(&home, &cwd, AGREED_BLOCK, &[]);
    assert!(latest_record(&home).get("effinterp").is_none());
}

#[test]
fn the_gap_listing_holds_exactly_the_decisions_whose_streams_disagree() {
    let (_home_temp, home) = temp_home();
    let (_cwd_temp, cwd) = temp_home();
    assert!(nah(&home, &["effinterp", "on"]).status.success());

    decide(&home, &cwd, AGREED_BLOCK, &[]);
    assert!(
        audit_records(&home, &["log", "--json", "--effinterp-gap", "-n", "10"]).is_empty(),
        "agreeing streams record no gap"
    );

    decide(&home, &cwd, DISAGREED_BLOCK, &[]);
    let expected = audit_records(&home, &["log", "--json", "-n", "10"])
        .into_iter()
        .filter(|record| record["effinterp"]["gap"] == json!(true))
        .map(|record| record["envelope"]["id"].clone())
        .collect::<Vec<_>>();
    assert!(
        !expected.is_empty(),
        "the two streams describe {DISAGREED_BLOCK} differently"
    );
    let listed = audit_records(&home, &["log", "--json", "--effinterp-gap", "-n", "10"])
        .into_iter()
        .map(|record| record["envelope"]["id"].clone())
        .collect::<Vec<_>>();
    assert_eq!(listed, expected);
}

#[test]
fn the_explanation_renders_both_streams() {
    let (_home_temp, home) = temp_home();
    let (_cwd_temp, cwd) = temp_home();
    assert!(nah(&home, &["effinterp", "on"]).status.success());

    let decision = decide(&home, &cwd, AGREED_BLOCK, &[]);
    let record = latest_record(&home);
    let explanation = nah(&home, &["why", decision.id()]);
    assert!(explanation.status.success());
    let explanation = String::from_utf8(explanation.stdout).unwrap();

    for effect in record["effects"].as_array().unwrap() {
        assert!(explanation.contains(effect["id"].as_str().unwrap()));
    }
    for effect in record["effinterp"]["effects"].as_array().unwrap() {
        assert!(
            explanation.contains(effect["operation"].as_str().unwrap()),
            "{explanation}"
        );
    }
    assert!(explanation.contains(&record["effinterp"]["engine_time_us"].to_string()));
}

#[test]
fn enabling_the_shadow_from_inside_a_session_is_self_protected() {
    let (_home_temp, home) = temp_home();
    let (_cwd_temp, cwd) = temp_home();

    let decision = decide(&home, &cwd, "nah effinterp on", &[]);
    assert_eq!(decision.verdict(), Verdict::Block);
}
