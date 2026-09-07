#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::process::Command;

fn nah(home: &std::path::Path, runtime: &str, action: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", runtime, action])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HERMES_HOME")
        .output()
        .unwrap()
}

#[test]
fn unsupported_windows_lifecycle_fails_before_writing() {
    for runtime in ["amp", "droid", "hermes", "opencode"] {
        let home = tempfile::tempdir().unwrap();
        let before = std::fs::read_dir(home.path()).unwrap().count();

        let status = nah(home.path(), runtime, "status");
        assert!(status.status.success(), "{runtime}: {status:?}");

        for action in ["install", "uninstall"] {
            let output = nah(home.path(), runtime, action);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{runtime} {action}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("runtime-platform-unsupported"),
                "{runtime} {action}: {output:?}"
            );
            assert_eq!(
                std::fs::read_dir(home.path()).unwrap().count(),
                before,
                "{runtime} {action}"
            );
        }
    }
}
