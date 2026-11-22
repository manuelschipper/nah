#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::support;

fn snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else {
            files.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    files
}

#[test]
fn weakening_requires_both_operator_streams_before_any_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(temp.path());
    for args in [
        vec!["guard", "set", "infrastructure", "strict"],
        vec!["rule", "enable", "machine/system-halt"],
    ] {
        let output = support::nah(&home, &home, &args, None);
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
    let before = snapshot(&home);
    // Each lowers a level some rule runs at.
    let mut commands = vec![
        vec!["rule", "disable", "machine/outside-workspace-delete"],
        vec!["guard", "set", "infrastructure", "core"],
        vec!["guard", "reset", "infrastructure"],
        vec!["guard", "set", "work", "off"],
        vec!["rule", "reset", "machine/system-halt"],
    ];
    for runtime in nah_proto::runtime::HOOK_RUNTIME_NAMES {
        commands.push(vec!["hook", runtime, "install", "--fail-open"]);
        commands.push(vec!["hook", runtime, "uninstall"]);
    }
    for args in commands {
        for (terminal_input, terminal_output) in [(false, false), (true, false), (false, true)] {
            let (_master, slave) = support::operator_terminal();
            let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
            command
                .args(&args)
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env_remove("XDG_CONFIG_HOME")
                .stdin(if terminal_input {
                    Stdio::from(slave.try_clone().unwrap())
                } else {
                    Stdio::null()
                })
                .stdout(if terminal_output {
                    Stdio::from(slave)
                } else {
                    Stdio::piped()
                });
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(4), "{args:?}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("interactive terminal"),
                "{args:?}: {output:?}"
            );
            assert_eq!(snapshot(&home), before, "{args:?}");
        }
        let mut help = args.clone();
        help.push("--help");
        let output = support::nah(&home, &home, &help, None);
        assert!(output.status.success(), "{help:?}: {output:?}");
        assert_eq!(snapshot(&home), before, "{help:?}");
    }

    // A reset that restores protection, or a change that only raises it,
    // needs no terminal.
    for (weaken, restore) in [
        (
            vec!["rule", "disable", "machine/outside-workspace-delete"],
            vec!["rule", "reset", "machine/outside-workspace-delete"],
        ),
        (
            vec!["guard", "set", "work", "off"],
            vec!["guard", "reset", "work"],
        ),
        (
            vec!["guard", "set", "secrets", "off"],
            vec!["guard", "set", "secrets", "strict"],
        ),
    ] {
        let output = support::nah(&home, &home, &weaken, None);
        assert!(output.status.success(), "{weaken:?}: {output:?}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
        let output = command
            .args(&restore)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        assert!(output.status.success(), "{restore:?}: {output:?}");
    }
}
