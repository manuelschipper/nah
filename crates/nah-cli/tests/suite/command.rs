#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::io::Write;
use std::process::{Command, Stdio};

use nah_proto::decision::{DecisionOutput, Verdict};
use serde_json::json;
use support::repo;

#[test]
fn decide_command_emits_machine_json_and_verdict_exit_codes() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    for (path, expected_code, expected_verdict) in [
        ("src/lib.rs", 2, Verdict::Delegate),
        (".env", 1, Verdict::Block),
    ] {
        let input = json!({
            "v": 1,
            "tool": "Read",
            "input": {"file_path": path},
            "cwd": repo,
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
            .arg("decide")
            .env("HOME", &root)
            .env("USERPROFILE", &root)
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
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(expected_code));
        let output: DecisionOutput = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(output.verdict(), expected_verdict);

        // `nah test --tool` dry-runs the same call to the same decision.
        let tested = Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(["test", "--json", "--tool", "Read", "--args-json"])
            .arg(json!({"file_path": path}).to_string())
            .current_dir(&repo)
            .env("HOME", &root)
            .env("USERPROFILE", &root)
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        assert_eq!(tested.status.code(), Some(0), "{tested:?}");
        let tested: serde_json::Value = serde_json::from_slice(&tested.stdout).unwrap();
        let decided: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        for field in ["verdict", "coverage", "reason", "policy_attributions"] {
            assert_eq!(tested["decision"][field], decided[field], "{path}: {field}");
        }
    }
}

#[test]
fn commands_past_a_parser_bound_delegate_instead_of_ending_the_process() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let oversized = format!("echo {}", "a".repeat(1024 * 1024));
    let too_complex = (0..20_000).map(|_| ":").collect::<Vec<_>>().join(" && ");
    for (command, expected_reason) in [
        (&oversized, "input-byte-limit"),
        (&too_complex, "analysis is incomplete"),
    ] {
        let input = json!({
            "v": 1,
            "tool": "Bash",
            "input": {"command": command},
            "cwd": repo,
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
            .arg("decide")
            .env("HOME", &root)
            .env("USERPROFILE", &root)
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
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        // `code()` is None when a signal ended the process, so this also
        // asserts that nah still exits with a documented verdict code.
        assert_eq!(result.status.code(), Some(2), "{expected_reason}");
        let output: DecisionOutput = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(output.verdict(), Verdict::Delegate);
        let warning = String::from_utf8(result.stderr).unwrap();
        assert!(
            warning.contains(expected_reason),
            "{expected_reason}: {warning}"
        );
    }

    // 8000 nested groups is 40 KB and used to overflow the parser's stack,
    // which ended `nah` on a signal with no verdict at all. The engine now
    // parses the whole input and blocks the trailing root deletion, so this
    // asserts both that nah exits with a documented verdict code (never None)
    // and that the proven `rm -rf /` still reaches a guard.
    let nested = format!("{}true{}; rm -rf /", "{ ".repeat(8000), "; }".repeat(8000));
    let input = json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": &nested},
        "cwd": repo,
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("decide")
        .env("HOME", &root)
        .env("USERPROFILE", &root)
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
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    let output: DecisionOutput = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(output.verdict(), Verdict::Block);

    let result = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("test")
        .arg(&nested)
        .current_dir(&repo)
        .env("HOME", &root)
        .env("USERPROFILE", &root)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let rendered = String::from_utf8(result.stdout).unwrap();
    assert!(rendered.starts_with("verdict: block\n"), "{rendered}");

    let wrapped = format!("bash -c '{}true{}'", "{ ".repeat(8000), "; }".repeat(8000));
    let result = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("test")
        .arg(wrapped)
        .current_dir(&repo)
        .env("HOME", &root)
        .env("USERPROFILE", &root)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let rendered = String::from_utf8(result.stdout).unwrap();
    assert!(rendered.starts_with("verdict: delegate\n"), "{rendered}");
}
