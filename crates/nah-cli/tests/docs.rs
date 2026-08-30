#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::Command;

#[test]
fn docs_command_works_without_state() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(args)
            .env("HOME", &root)
            .env("USERPROFILE", &root)
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap()
    };

    let topic = run(&["docs", "start"]);
    assert!(topic.status.success(), "{topic:?}");
    assert!(!topic.stdout.is_empty());
    assert!(topic.stderr.is_empty(), "{topic:?}");

    let index = run(&["docs"]);
    assert!(index.status.success(), "{index:?}");
    assert!(
        String::from_utf8(index.stdout)
            .unwrap()
            .lines()
            .any(|line| line.starts_with("guards "))
    );

    for name in ["missing-topic", "../start"] {
        let missing = run(&["docs", name]);
        assert_eq!(missing.status.code(), Some(2), "{missing:?}");
        assert!(missing.stdout.is_empty(), "{missing:?}");
    }
}
