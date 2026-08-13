#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use nah_proto::decision::{DecisionOutput, Verdict};
use serde_json::json;
use support::repo;

/// Every state file nah reads before policy runs, with the warning it must
/// emit when that file cannot be read.
const CONSERVATIVE_DAMAGED_STATE: [(&str, &str); 2] = [
    (
        "trust.json",
        "invalid-trust-database; no project root is trusted",
    ),
    (
        "built-ins.json",
        "invalid-shipped-state; shipped defaults apply",
    ),
];

/// Unreadable bytes, then a state version from a future release. A downgrade —
/// or a stale hook pointing at an older binary — produces the second one.
const DAMAGE: [&str; 2] = ["GARBAGE{not json", r#"{"v":999}"#];

fn nah(home: &Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("USER", "tester")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn decide(
    home: &Path,
    cwd: &Path,
    tool: &str,
    input: serde_json::Value,
) -> (DecisionOutput, String, Option<i32>) {
    let payload = json!({"v": 1, "tool": tool, "input": input, "cwd": cwd}).to_string();
    let output = nah(home, &["decide"], Some(&payload));
    (
        serde_json::from_slice(&output.stdout).expect("decide always answers with a decision"),
        String::from_utf8(output.stderr).unwrap(),
        output.status.code(),
    )
}

fn damage(home: &Path, file: &str, contents: &str) {
    std::fs::create_dir_all(home.join(".nah")).unwrap();
    std::fs::write(home.join(".nah").join(file), contents).unwrap();
}

#[test]
fn damaged_state_keeps_the_guards_enforcing_and_says_so() {
    for (file, warning) in CONSERVATIVE_DAMAGED_STATE {
        for contents in DAMAGE {
            let temp = tempfile::tempdir().unwrap();
            // macOS temp directories sit under a symlinked /var, and nah resolves
            // paths before matching them
            let root = std::fs::canonicalize(temp.path()).unwrap();
            let project = repo(&root);
            damage(&root, file, contents);

            let (decision, stderr, code) =
                decide(&root, &project, "Bash", json!({"command":"rm -rf /"}));
            let warning = if file == "built-ins.json" && contents == DAMAGE[1] {
                "unsupported-shipped-state-version; shipped defaults apply"
            } else {
                warning
            };

            assert_eq!(decision.verdict(), Verdict::Block, "{file}: {contents}");
            assert_eq!(code, Some(1), "{file}: {contents}");
            assert!(stderr.contains(warning), "{file}: {contents}: {stderr}");
        }
    }
}

#[test]
fn damaged_state_decides_exactly_like_a_fresh_install() {
    let probes = [
        ("Bash", json!({"command":"rm -rf /"})),
        ("Bash", json!({"command":"git push --force"})),
        ("Read", json!({"file_path":"src/lib.rs"})),
        ("Read", json!({"file_path":".env"})),
    ];
    let answers = |home: &Path, project: &Path| {
        probes
            .iter()
            .map(|(tool, input)| {
                let (decision, _, code) = decide(home, project, tool, input.clone());
                (decision.verdict(), decision.reason().to_owned(), code)
            })
            .collect::<Vec<_>>()
    };

    let fresh = tempfile::tempdir().unwrap();
    let fresh_project = repo(fresh.path());
    assert!(!fresh.path().join(".nah").exists());
    let expected = answers(fresh.path(), &fresh_project);

    for (file, _) in CONSERVATIVE_DAMAGED_STATE {
        for contents in DAMAGE {
            let temp = tempfile::tempdir().unwrap();
            // macOS temp directories sit under a symlinked /var, and nah resolves
            // paths before matching them
            let root = std::fs::canonicalize(temp.path()).unwrap();
            let project = repo(&root);
            damage(&root, file, contents);

            assert_eq!(answers(&root, &project), expected, "{file}: {contents}");
        }
    }
}

#[test]
fn damaged_activation_state_delegates_with_a_failure() {
    for contents in DAMAGE {
        let temp = tempfile::tempdir().unwrap();
        // macOS temp directories sit under a symlinked /var, and nah resolves
        // paths before matching them
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let project = repo(&root);
        damage(&root, "activations.json", contents);
        let payload = json!({
            "v": 1,
            "tool": "Bash",
            "input": {"command":"unknown-tool"},
            "cwd": project,
        })
        .to_string();

        let output = nah(&root, &["decide"], Some(&payload));

        assert_eq!(output.status.code(), Some(2), "{contents}: {output:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["verdict"],
            "delegate"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("invalid-activation-database; extension guard state unavailable"),
            "{contents}: {stderr}"
        );
        assert!(
            stderr.contains("extension guard state unavailable"),
            "{contents}: {stderr}"
        );
    }
}

#[test]
fn damaged_shipped_state_falls_back_to_the_shipped_defaults() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let project = repo(&root);
    assert!(
        nah(&root, &["guard", "disable", "fs-system-tree"], None)
            .status
            .success()
    );
    let (disabled, _, _) = decide(
        &root,
        &project,
        "Bash",
        json!({"command":"rm -rf /usr/bin"}),
    );
    assert_eq!(disabled.verdict(), Verdict::Delegate);

    damage(&root, "built-ins.json", DAMAGE[0]);

    let (blocked, _, _) = decide(
        &root,
        &project,
        "Bash",
        json!({"command":"rm -rf /usr/bin"}),
    );
    assert_eq!(blocked.verdict(), Verdict::Block);
    let (safe, _, _) = decide(&root, &project, "Read", json!({"file_path":"src/lib.rs"}));
    assert_eq!(safe.verdict(), Verdict::Delegate);
}

#[cfg(unix)]
#[test]
fn a_malformed_bundle_does_not_disarm_a_healthy_sibling() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    assert!(nah(&root, &["guard", "new", "tool"], None).status.success());
    assert!(
        nah(&root, &["guard", "enable", "tool"], None)
            .status
            .success()
    );
    let broken = &root.join(".nah/guards/broken");
    std::fs::create_dir_all(broken).unwrap();
    std::fs::write(broken.join("policy.toml"), "this is not toml").unwrap();

    let (decision, stderr, _) = decide(
        &root,
        &root,
        "Bash",
        json!({"command":"tool destroy --all"}),
    );

    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(
        stderr.contains("inactive extension bundle `broken`: invalid-policy-manifest"),
        "{stderr}"
    );
}
