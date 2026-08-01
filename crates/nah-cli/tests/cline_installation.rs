#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

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
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let ide_path = home.join("Documents/Cline/Hooks/PreToolUse");
    let cli_path = home.join(".cline/hooks/PreToolUse");

    let installed = nah(home, &["hook", "cline", "install"]);
    assert!(installed.status.success(), "{installed:?}");
    let first = std::fs::read(&ide_path).unwrap();
    let script = String::from_utf8(first.clone()).unwrap();
    assert!(script.starts_with("#!/bin/sh\n# Managed by nah: Cline PreToolUse\n"));
    assert!(script.contains(" hook cline run\n"));
    assert_eq!(std::fs::read(&cli_path).unwrap(), first);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            std::fs::metadata(&ide_path).unwrap().permissions().mode() & 0o111,
            0
        );
        assert_ne!(
            std::fs::metadata(&cli_path).unwrap().permissions().mode() & 0o111,
            0
        );
    }

    let status = nah(home, &["hook", "cline", "status"]);
    assert!(status.status.success(), "{status:?}");
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "Cline: wiring current\nverify: nah docs runtime-cline\n"
    );
    assert!(nah(home, &["hook", "cline", "install"]).status.success());
    assert_eq!(std::fs::read(&ide_path).unwrap(), first);
    assert_eq!(std::fs::read(&cli_path).unwrap(), first);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cli_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let status = nah(home, &["hook", "cline", "status"]);
        assert_eq!(
            String::from_utf8_lossy(&status.stdout),
            "Cline: reinstall required\nnext: nah hook cline install\ndocs: nah docs runtime-cline\n"
        );
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
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let path = home.join("Documents/Cline/Hooks/PreToolUse");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    let conflict = nah(home, &["hook", "cline", "install"]);
    assert_eq!(conflict.status.code(), Some(2), "{conflict:?}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );

    let cli_conflict = tempfile::tempdir().unwrap();
    let cli_path = cli_conflict.path().join(".cline/hooks/PreToolUse");
    std::fs::create_dir_all(cli_path.parent().unwrap()).unwrap();
    std::fs::write(&cli_path, "#!/bin/sh\nexit 0\n").unwrap();
    let conflict = nah(cli_conflict.path(), &["hook", "cline", "install"]);
    assert_eq!(conflict.status.code(), Some(2), "{conflict:?}");
    assert_eq!(
        std::fs::read_to_string(&cli_path).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
    assert!(
        !cli_conflict
            .path()
            .join("Documents/Cline/Hooks/PreToolUse")
            .exists()
    );

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
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
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
