#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use nah_proto::decision::{DecisionOutput, Verdict};
use serde_json::json;
use sha2::Sha256;
use support::{bash_path, repo};

fn write_unsigned_nap(home: &Path, mode: &str, started_at: u64, expires_at: u64) {
    std::fs::create_dir_all(home.join(".nah")).unwrap();
    std::fs::write(
        home.join(".nah/nap.json"),
        json!({
            "v": 1,
            "mode": mode,
            "started_at": started_at,
            "expires_at": expires_at,
        })
        .to_string(),
    )
    .unwrap();
}

fn write_authenticated_nap(home: &Path, mode: &str, started_at: u64, expires_at: u64) {
    const KEY: [u8; 32] = [0x5a; 32];

    let directory = home.join(".nah");
    std::fs::create_dir_all(&directory).unwrap();
    let key_path = directory.join("nap.key");
    std::fs::write(&key_path, KEY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(b"nah nap state v1\0");
    mac.update(&1_u32.to_be_bytes());
    mac.update(&[if mode == "self-protection" { 0 } else { 1 }]);
    mac.update(&started_at.to_be_bytes());
    mac.update(&expires_at.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0; 32];
    tag.copy_from_slice(&bytes);
    std::fs::write(
        directory.join("nap.json"),
        json!({
            "v": 1,
            "mode": mode,
            "started_at": started_at,
            "expires_at": expires_at,
            "mac": tag,
        })
        .to_string(),
    )
    .unwrap();
}

fn decide(home: &Path, cwd: &Path, command: &str) -> (DecisionOutput, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("decide")
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
    let decision = serde_json::from_slice(&output.stdout).unwrap();
    (decision, String::from_utf8(output.stderr).unwrap())
}

fn strict_claude(home: &Path, cwd: &Path, command: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "claude", "run", "--fail-closed"])
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
                "hook_event_name":"PreToolUse",
                "tool_name":"Bash",
                "tool_input":{"command":command},
                "cwd":cwd,
                "session_id":"session-1"
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    child.wait_with_output().unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn unsigned_nap_state_fails_awake_without_minting_a_key() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let timestamp = now();
    write_unsigned_nap(home, "all", timestamp, timestamp + 600);

    let (decision, stderr) = decide(home, &project, "rm -rf /");
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(stderr.contains("invalid-nap-state"), "{stderr}");
    assert!(!home.join(".nah/nap.key").exists());
}

#[test]
fn tampered_authenticated_state_fails_awake() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let timestamp = now();
    write_authenticated_nap(home, "self-protection", timestamp, timestamp + 600);
    let path = home.join(".nah/nap.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state["mode"] = json!("all");
    std::fs::write(path, state.to_string()).unwrap();

    let (decision, stderr) = decide(home, &project, "rm -rf /");
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(stderr.contains("invalid-nap-state"), "{stderr}");
}

#[test]
fn nap_requires_an_operator_terminal_and_agents_cannot_start_it() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);

    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("nap")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("interactive terminal")
    );

    let timestamp = now();
    write_authenticated_nap(home, "all", timestamp, timestamp + 600);
    for command in ["nah nap", "script -qec 'nah nap' /dev/null"] {
        let (decision, _) = decide(home, &project, command);
        assert_eq!(decision.verdict(), Verdict::Block, "{command}");
        assert!(decision.reason().contains("operator"), "{command}");
    }
}

#[test]
fn self_nap_pauses_self_protection_but_keeps_guards_awake_globally() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let first = repo(home);
    let second_parent = home.join("second");
    std::fs::create_dir(&second_parent).unwrap();
    let second = repo(&second_parent);
    let timestamp = now();
    write_authenticated_nap(home, "self-protection", timestamp, timestamp + 600);

    for project in [&first, &second] {
        let (configuration, _) = decide(home, project, "nah trust .");
        assert_ne!(configuration.verdict(), Verdict::Block);

        let (danger, _) = decide(home, project, "rm -rf /");
        assert_eq!(danger.verdict(), Verdict::Block);
    }
}

#[test]
fn all_nap_delegates_every_non_permanent_call_and_wake_restores_enforcement() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let timestamp = now();
    write_authenticated_nap(home, "all", timestamp, timestamp + 600);

    for command in [
        r#"python3 -c "import subprocess; subprocess.run(['bash','-c','nah nap'])""#,
        r#"python3 -c "import subprocess; subprocess.run(['bash','-c','script -qec \"nah nap\" /dev/null'])""#,
        r#"node -e "const {spawn}=require('child_process'); spawn('nah', ['nap'])""#,
        r#"pwsh -Command "Start-Process nah -ArgumentList nap""#,
    ] {
        let (permanent, _) = decide(home, &project, command);
        assert_eq!(permanent.verdict(), Verdict::Block, "{command}");
        assert!(permanent.reason().contains("operator"), "{command}");
    }

    let (critical, _) = decide(
        home,
        &project,
        r#"python3 -c "import os; os.system('nah trust .')""#,
    );
    assert_eq!(critical.verdict(), Verdict::Delegate);

    let (paused, stderr) = decide(home, &project, "rm -rf /");
    assert_eq!(paused.verdict(), Verdict::Delegate);
    assert!(stderr.contains("all enforcement nap active globally"));

    let refusal = strict_claude(home, &project, &format!("echo {}", "a".repeat(1024 * 1024)));
    assert!(refusal.status.success(), "{refusal:?}");
    assert!(refusal.stdout.is_empty(), "{refusal:?}");

    for protected in ["nap.json", "nap.key"] {
        let command = format!(
            "printf forged > {}",
            bash_path(&home.join(".nah").join(protected))
        );
        let (decision, _) = decide(home, &project, &command);
        assert_eq!(decision.verdict(), Verdict::Block, "{protected}");
        assert!(
            decision
                .reason()
                .contains("must be started by the operator"),
            "{protected}: {}",
            decision.reason()
        );
    }

    let wake = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("wake")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(wake.status.success());
    assert!(!home.join(".nah/nap.json").exists());
    assert!(home.join(".nah/nap.key").exists());

    let (awake, _) = decide(home, &project, "rm -rf /");
    assert_eq!(awake.verdict(), Verdict::Block);
}

#[test]
fn all_nap_intentionally_ignores_unavailable_extension_state() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let timestamp = now();
    write_authenticated_nap(home, "all", timestamp, timestamp + 600);
    std::fs::write(home.join(".nah/activations.json"), "not-json").unwrap();

    let (decision, stderr) = decide(home, &project, "unknown-tool");

    assert_eq!(decision.verdict(), Verdict::Delegate);
    assert!(
        stderr.contains("invalid-activation-database; extension guard state unavailable"),
        "{stderr}"
    );
    assert!(
        stderr.contains("all enforcement nap active globally"),
        "{stderr}"
    );
    assert!(
        !stderr
            .lines()
            .any(|line| line == "nah: extension guard state unavailable"),
        "{stderr}"
    );
}

#[test]
fn expired_or_invalid_state_fails_awake() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    let timestamp = now();
    write_authenticated_nap(home, "all", timestamp.saturating_sub(600), timestamp);
    let (expired, _) = decide(home, &project, "rm -rf /");
    assert_eq!(expired.verdict(), Verdict::Block);

    std::fs::write(home.join(".nah/nap.json"), "{}").unwrap();
    let (invalid, stderr) = decide(home, &project, "rm -rf /");
    assert_eq!(invalid.verdict(), Verdict::Block);
    assert!(stderr.contains("invalid-nap-state"));
    assert!(stderr.contains("self-protection remains awake"));
}
