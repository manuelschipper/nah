#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::{Command, Stdio};

use support::{absolute, host_platform};

#[test]
fn trust_command_persists_an_idempotent_canonical_root() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&root).unwrap();

    for args in [vec!["trust", root.to_str().unwrap()], vec!["trust"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(args)
            .current_dir(&root)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("trusted ")
        );
    }
    assert!(home.join(".nah/trust.json").is_file());
    assert!(!home.join(".config/nah").exists());

    let home = absolute(&support::test_temp_path(&home));
    let database = nah_extensions::TrustDatabase::load(
        &nah_extensions::trust_database_path(&home, host_platform()),
        host_platform(),
    )
    .unwrap();
    let roots = database.projection().unwrap();
    assert_eq!(roots.trusted_roots().len(), 1);
    assert_eq!(
        roots.trusted_roots()[0].path().as_str(),
        support::test_temp_path(&root).to_str().unwrap()
    );
}

#[test]
fn trust_rejects_the_home_root_that_owns_user_guards() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["trust", home.to_str().unwrap()])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("home directory cannot be trusted as a project root")
    );
}

#[test]
fn trust_errors_name_the_requested_project_root() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let missing = temp.path().join("missing");

    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["trust", missing.to_str().unwrap()])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains(&format!("{:?}", missing.to_str().unwrap())),
        "{error}"
    );
    assert!(error.contains("choose an existing directory"), "{error}");

    let escaped = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["trust", "missing\nroot"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(escaped.status.code(), Some(2));
    let error = String::from_utf8(escaped.stderr).unwrap();
    assert!(!error.contains("missing\nroot"), "{error:?}");
    assert!(error.contains(r"missing\nroot"), "{error:?}");
}

#[cfg(unix)]
#[test]
fn untrust_revokes_the_root_and_its_project_policy_attributions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("repo");
    let guard = root.join(".nah/guards/project-guard");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&guard).unwrap();
    std::fs::write(
        guard.join("policy.toml"),
        "name = \"project-guard\"\nmatch = [\"project-guard\"]\nprotocol = \"exec/v1\"\nprovenance = \"agent\"\n",
    )
    .unwrap();
    let run = guard.join("run");
    std::fs::write(
        &run,
        "#!/bin/sh\nprintf '%s\\n' '{\"block\":true,\"reason\":\"project guard\"}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();

    for args in [
        vec!["trust", root.to_str().unwrap()],
        vec!["guard", "enable", "project-guard"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(args)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["untrust", root.to_str().unwrap()])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("revoked 1 enabled project guard")
    );

    let home = absolute(&support::test_temp_path(&home));
    let trust = nah_extensions::TrustDatabase::load(
        &nah_extensions::trust_database_path(&home, host_platform()),
        host_platform(),
    )
    .unwrap();
    assert!(trust.projection().unwrap().trusted_roots().is_empty());
    let activations = nah_extensions::ActivationDatabase::load(
        &nah_extensions::activation_database_path(&home, host_platform()),
    )
    .unwrap();
    assert!(activations.records().is_empty());

    let missing = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["untrust", root.to_str().unwrap()])
        .env("HOME", home.as_str())
        .env("USERPROFILE", home.as_str())
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("trusted-root-not-found"));

    let retrust = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["trust", root.to_str().unwrap()])
        .env("HOME", home.as_str())
        .env("USERPROFILE", home.as_str())
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(retrust.status.success(), "{retrust:?}");
    let activations = nah_extensions::ActivationDatabase::load(
        &nah_extensions::activation_database_path(&home, host_platform()),
    )
    .unwrap();
    assert!(activations.records().is_empty());
}

#[test]
fn concurrent_trust_commands_preserve_every_root() {
    const ROOTS: usize = 12;

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut children = Vec::new();
    for index in 0..ROOTS {
        let root = temp.path().join(format!("repo-{index}"));
        std::fs::create_dir(&root).unwrap();
        children.push(
            Command::new(env!("CARGO_BIN_EXE_nah"))
                .args(["trust", root.to_str().unwrap()])
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env_remove("XDG_CONFIG_HOME")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    let home = absolute(&std::fs::canonicalize(home).unwrap());
    let database = nah_extensions::TrustDatabase::load(
        &nah_extensions::trust_database_path(&home, host_platform()),
        host_platform(),
    )
    .unwrap();
    assert_eq!(database.projection().unwrap().trusted_roots().len(), ROOTS);
}
