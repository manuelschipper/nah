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
    let project = home.join("repo");
    std::fs::create_dir(&project).unwrap();
    let project = project.to_str().unwrap();
    for args in [
        vec!["guard", "enable", "db-destroy"],
        vec!["guard", "new", "user-policy"],
        vec!["guard", "enable", "user-policy"],
        vec!["guard", "enable", "user-policy", "--user"],
        vec!["guard", "new", "project-policy", "--project", project],
        vec!["trust", project],
        vec!["guard", "enable", "project-policy", "--project", project],
    ] {
        let output = support::nah(&home, &home, &args, None);
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
    // Changed active bytes can remove a failure that a fail-closed hook blocks.
    for bundle in [
        home.join(".nah/guards/user-policy"),
        Path::new(project).join(".nah/guards/project-policy"),
    ] {
        let manifest = bundle.join("policy.toml");
        let mut bytes = std::fs::read(&manifest).unwrap();
        bytes.extend_from_slice(b"\n# revised proposal\n");
        std::fs::write(manifest, bytes).unwrap();
    }
    let before = snapshot(&home);
    let mut commands = vec![
        vec!["guard", "disable", "fs-home"],
        vec!["guard", "reset", "db-destroy"],
        vec!["guard", "disable", "user-policy"],
        vec!["guard", "disable", "user-policy", "--user"],
        vec!["guard", "disable", "project-policy", "--project", project],
        vec!["guard", "enable", "user-policy"],
        vec!["guard", "enable", "user-policy", "--user"],
        vec!["guard", "enable", "project-policy", "--project", project],
        vec!["untrust", project],
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

    for args in [
        vec!["guard", "enable", "user-policy", "--user"],
        vec!["guard", "enable", "project-policy", "--project", project],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
        command
            .args(&args)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME");
        let output = support::operator_output(&mut command);
        assert!(output.status.success(), "{args:?}: {output:?}");
        // Once the operator approved the bytes, enabling again needs no terminal.
        let output = support::nah(&home, &home, &args, None);
        assert!(output.status.success(), "{args:?}: {output:?}");
    }

    // Resetting a factory-on guard restores protection without a terminal.
    let output = support::nah(&home, &home, &["guard", "disable", "fs-home"], None);
    assert!(output.status.success(), "{output:?}");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    let output = command
        .args(["guard", "reset", "fs-home"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}
