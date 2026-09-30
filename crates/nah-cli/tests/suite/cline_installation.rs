#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::process::{Command, Stdio};

fn nah(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("PATH", "")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[test]
fn install_status_repair_and_uninstall_are_owned_and_idempotent() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let file = if cfg!(windows) {
        "PreToolUse.ps1"
    } else {
        "PreToolUse"
    };
    let ide_path = home.join("Documents/Cline/Hooks").join(file);
    let cli_path = home.join(".cline/hooks").join(file);

    let installed = nah(home, &["hook", "cline", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let first = std::fs::read(&ide_path).unwrap();
    let script = String::from_utf8(first.clone()).unwrap();
    if cfg!(windows) {
        assert!(script.starts_with("# Managed by nah: Cline PreToolUse\n"));
        assert!(script.contains("[Console]::In.ReadToEnd()"));
        assert!(
            script
                .to_ascii_lowercase()
                .contains("nah.exe' hook cline run")
        );
    } else {
        assert!(script.starts_with("#!/bin/sh\n# Managed by nah: Cline PreToolUse\n"));
    }
    assert!(script.contains(" hook cline run\n"));
    // The CLI also runs the Documents hook, so a second one would make it
    // decide every call twice
    assert!(!cli_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            std::fs::metadata(&ide_path).unwrap().permissions().mode() & 0o111,
            0
        );
    }

    let status = nah(home, &["hook", "cline", "status"]);
    assert!(status.status.success(), "{status:?}");
    let output = String::from_utf8_lossy(&status.stdout);
    for expected in [
        "Cline",
        "wiring current",
        "fail-open",
        "nah docs runtime-cline",
    ] {
        assert!(output.contains(expected), "missing {expected:?}:\n{output}");
    }
    assert!(nah(home, &["hook", "cline", "install"]).status.success());
    assert_eq!(std::fs::read(&ide_path).unwrap(), first);

    // Earlier installs also wrote the CLI root; reinstalling retires it
    std::fs::create_dir_all(cli_path.parent().unwrap()).unwrap();
    std::fs::write(&cli_path, &first).unwrap();
    let status = nah(home, &["hook", "cline", "status"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("reinstall required"),
        "{status:?}"
    );
    assert!(nah(home, &["hook", "cline", "install"]).status.success());
    assert!(!cli_path.exists());

    // When that copy is the only registration left, its fail-closed policy
    // survives the reinstall that retires it
    assert!(
        nah(home, &["hook", "cline", "install", "--fail-closed"])
            .status
            .success()
    );
    std::fs::rename(&ide_path, &cli_path).unwrap();
    let status = nah(home, &["hook", "cline", "status"]);
    let output = String::from_utf8_lossy(&status.stdout);
    assert!(
        output.contains("reinstall required") && output.contains("fail-closed"),
        "{output}"
    );
    assert!(nah(home, &["hook", "cline", "install"]).status.success());
    assert!(!cli_path.exists());
    let strict = std::fs::read_to_string(&ide_path).unwrap();
    assert!(strict.contains(" hook cline run --fail-closed"), "{strict}");
    assert!(
        nah(home, &["hook", "cline", "install", "--fail-open"])
            .status
            .success()
    );
    assert_eq!(std::fs::read(&ide_path).unwrap(), first);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ide_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let status = nah(home, &["hook", "cline", "status"]);
        let output = String::from_utf8_lossy(&status.stdout);
        for expected in [
            "Cline",
            "reinstall required",
            "fail-open",
            "nah hook cline install",
            "nah docs runtime-cline",
        ] {
            assert!(output.contains(expected), "missing {expected:?}:\n{output}");
        }
        assert!(nah(home, &["hook", "cline", "install"]).status.success());
    }

    let removed = nah(home, &["hook", "cline", "uninstall"]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(!ide_path.exists());
    assert!(!cli_path.exists());
    assert!(nah(home, &["hook", "cline", "uninstall"]).status.success());
}

#[test]
fn install_refuses_unowned_or_symlinked_hook_paths() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let file = if cfg!(windows) {
        "PreToolUse.ps1"
    } else {
        "PreToolUse"
    };
    let path = home.join("Documents/Cline/Hooks").join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    let conflict = nah(home, &["hook", "cline", "install"]);
    assert_eq!(conflict.status.code(), Some(2), "{conflict:?}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );

    // nah does not need the CLI root here, so a user's script there stays,
    // including an edited copy that still carries nah's marker
    for script in [
        "#!/bin/sh\nexit 0\n",
        "#!/bin/sh\n# Managed by nah: Cline PreToolUse\nexec '/usr/bin/env' MY_POLICY=custom '/opt/nah' hook cline run\n",
    ] {
        let cli_user = tempfile::tempdir().unwrap();
        let cli_path = cli_user.path().join(".cline/hooks").join(file);
        std::fs::create_dir_all(cli_path.parent().unwrap()).unwrap();
        std::fs::write(&cli_path, script).unwrap();
        for action in ["install", "uninstall"] {
            let output = nah(cli_user.path(), &["hook", "cline", action]);
            assert!(output.status.success(), "{output:?}");
            assert_eq!(std::fs::read_to_string(&cli_path).unwrap(), script);
        }
    }

    // A symlink there is never followed to classify it as nah's copy
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked = tempfile::tempdir().unwrap();
        let generated = linked.path().join("Documents/Cline/Hooks/PreToolUse");
        assert!(
            nah(linked.path(), &["hook", "cline", "install"])
                .status
                .success()
        );
        let target = linked.path().join("generated");
        std::fs::rename(&generated, &target).unwrap();
        let cli_path = linked.path().join(".cline/hooks/PreToolUse");
        std::fs::create_dir_all(cli_path.parent().unwrap()).unwrap();
        symlink(&target, &cli_path).unwrap();
        assert!(
            nah(linked.path(), &["hook", "cline", "install"])
                .status
                .success()
        );
        assert!(std::fs::symlink_metadata(&cli_path).unwrap().is_symlink());
        assert!(target.exists());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let redirected = tempfile::tempdir().unwrap();
        let target = redirected.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir_all(redirected.path().join("Documents")).unwrap();
        symlink(&target, redirected.path().join("Documents/Cline")).unwrap();
        let output = nah(redirected.path(), &["hook", "cline", "install"]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(!target.join("Hooks/PreToolUse").exists());
    }
}

// macOS keeps its documents directory at a fixed place and never asks
// xdg-user-dir, so only the platforms that consult it exercise this
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn install_uses_clines_xdg_documents_directory() {
    use std::os::unix::fs::PermissionsExt;

    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let bin = home.join("bin");
    let documents = home.join("My Documents");
    std::fs::create_dir(&bin).unwrap();
    let xdg = bin.join("xdg-user-dir");
    std::fs::write(
        &xdg,
        format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", documents.display()),
    )
    .unwrap();
    std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).unwrap();

    let installed = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "cline", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");
    assert!(documents.join("Cline/Hooks/PreToolUse").exists());
    assert!(home.join(".cline/hooks/PreToolUse").exists());
    assert!(!home.join("Documents/Cline/Hooks/PreToolUse").exists());
}
