#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn nah(home: &std::path::Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("USERPROFILE", home)
        .env("HOME", home)
        .env("USER", "tester")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
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

#[test]
fn windows_template_activates_reloads_and_removes_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home with spaces");
    fs::create_dir(&home).unwrap();

    let created = nah(&home, &["guard", "new", "tool"], None);
    assert!(created.status.success(), "{created:?}");
    let guard = home.join(".nah/guards/tool");
    assert!(guard.join("run.cmd").is_file());
    assert!(guard.join("run.py").is_file());

    let enabled = nah(&home, &["guard", "enable", "tool"], None);
    assert!(enabled.status.success(), "{enabled:?}");
    let input = serde_json::json!({
        "v": 1,
        "tool": "Bash",
        "input": {"command": "tool destroy --all"},
        "cwd": home,
        "session": "test"
    })
    .to_string();
    let decided = nah(&home, &["decide"], Some(&input));
    assert_eq!(decided.status.code(), Some(1), "{decided:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decided.stdout).unwrap()["verdict"],
        "block"
    );

    let reloaded = nah(&home, &["guards"], None);
    assert!(reloaded.status.success(), "{reloaded:?}");
    assert!(String::from_utf8_lossy(&reloaded.stdout).contains("tool\tuser\tactive\ttool"));
    let disabled = nah(&home, &["guard", "disable", "tool"], None);
    assert!(disabled.status.success(), "{disabled:?}");
    fs::remove_dir_all(&guard).unwrap();
    assert!(
        nah_extensions::ActivationDatabase::load(&home.join(".nah/activations.json"))
            .unwrap()
            .records()
            .is_empty()
    );
}
