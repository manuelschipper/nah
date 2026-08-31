//! Identity labels copied into the effectinterp annotation layer keep the
//! classifications the Bash lowering already shipped.
#![cfg(feature = "effinterp")]

use nah_effinterp::labels::host_integrity::host_integrity_class;
use nah_effinterp::labels::runtime_cli::{self, RuntimeCli};
use nah_effinterp::labels::sensitivity::sensitivity;
use nah_effinterp::labels::tier;
use nah_proto::action::{FilesystemOperation, HostIntegrityClass, NahProtectionTier, Sensitivity};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::{Root, RootKind};

fn argv(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn secret_categories_are_narrow_and_cross_platform() {
    let linux_home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for path in [
        "/home/test/.ssh",
        "/home/test/.ssh/id_rsa",
        "/home/test/.ssh/id_ed25519.backup",
        "/home/test/.ssh/identity",
        "/home/test/.gnupg",
        "/home/test/.gnupg/private-keys-v1.d/key",
        "/home/test/.npmrc",
        "/home/test/.cargo/credentials.toml",
        "/home/test/.config/pypoetry/auth.toml",
        "/home/test/.gem/credentials",
        "/home/test/.config/glab-cli/config.yml",
        "/home/test/.config/containers/auth.json",
        "/run/user/1000/containers/auth.json",
        "/home/test/.aws/credentials",
        "/home/test/.aws/sso/cache/session.json",
        "/home/test/.aws/cli/cache/session.json",
        "/home/test/.config/gcloud/credentials.db",
        "/home/test/.config/gcloud/access_tokens.db",
        "/home/test/.config/gcloud/application_default_credentials.json",
        "/home/test/.config/gh/hosts.yml",
        "/home/test/.docker/config.json",
        "/home/test/.kube/config",
        "/private/etc/shadow",
        "/etc/kubernetes/admin.conf",
        "/etc/rancher/k3s/k3s.yaml",
        "/home/alice/.aws/credentials",
        "/var/lib/service/.aws/credentials",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &linux_home, Platform::Linux, false),
            Sensitivity::CredentialSecret,
            "{path}"
        );
    }
    let aws = AbsolutePath::new(Platform::Linux, "/home/test/.aws/config").unwrap();
    assert_eq!(
        sensitivity(aws.as_str(), &aws, &linux_home, Platform::Linux, false),
        Sensitivity::OtherSensitive
    );
    let gnupg = AbsolutePath::new(Platform::Linux, "/home/test/.gnupg/gpg.conf").unwrap();
    assert_eq!(
        sensitivity(gnupg.as_str(), &gnupg, &linux_home, Platform::Linux, false),
        Sensitivity::OtherSensitive
    );
    for path in [
        "/home/test/.ssh/README.md",
        "/home/test/.ssh/notes.txt",
        "/home/test/.ssh/config.backup",
        "/home/test/.ssh/config",
        "/home/test/.ssh/known_hosts",
        "/home/test/.ssh/authorized_keys",
        "/home/test/.ssh/id_ed25519.pub",
        "/home/test/.ssh/id_ed25519-cert.pub",
        "/home/test/.ssh/config.d/work",
        "/home/test/.ssh/authorized_keys.d/work",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &linux_home, Platform::Linux, false),
            Sensitivity::None,
            "{path}"
        );
    }
    for (path, expected) in [
        ("/home/*/.ssh/id_rsa", Sensitivity::CredentialSecret),
        ("/home/*/.aws/config", Sensitivity::OtherSensitive),
        // Credential basenames apply anywhere; the home glob is still
        // anchored beneath the home parent.
        ("/tmp/*/.ssh/id_rsa", Sensitivity::CredentialSecret),
        ("/tmp/*/.aws/config", Sensitivity::None),
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &linux_home, Platform::Linux, false),
            expected,
            "{path}"
        );
    }

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    for (path, expected) in [
        (r"C:\Users\Test\.SSH\id_rsa", Sensitivity::CredentialSecret),
        (
            r"C:\Users\Test\.AWS\credentials",
            Sensitivity::CredentialSecret,
        ),
        (r"C:\repo\.NPMRC", Sensitivity::OtherSensitive),
    ] {
        let target = AbsolutePath::new(Platform::Windows, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &windows_home, Platform::Windows, false),
            expected,
            "{path}"
        );
    }
}

#[test]
fn project_local_key_material_is_never_insensitive() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    // A blocking classification is reserved for names that identify the
    // secret itself.
    for path in [
        "/workspace/project/id_rsa",
        "/workspace/project/keys/id_ed25519",
        "/workspace/project/.netrc",
        "/workspace/project/.git-credentials",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &home, Platform::Linux, false),
            Sensitivity::CredentialSecret,
            "{path}"
        );
    }
    // Names that are also ordinary development files stay visible to the
    // guards without making a plain local read block.
    for path in [
        "/workspace/project/certs/server.key",
        "/workspace/project/test/fixtures/server.key",
        "/workspace/project/certs/server.pem",
        "/workspace/project/keystore.p12",
        "/workspace/project/keystore.pfx",
        "/workspace/project/credentials",
        "/workspace/project/kubeconfig",
        "/workspace/project/terraform.tfstate",
        "/workspace/project/.docker/config.json",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &home, Platform::Linux, false),
            Sensitivity::OtherSensitive,
            "{path}"
        );
    }
    // A name that merely mentions credentials is not credential material.
    for path in [
        "/workspace/project/package.json",
        "/workspace/project/src/main.rs",
        "/workspace/project/src/credentials.rs",
        "/workspace/project/credentials.json",
        "/workspace/project/docs/credentials.md",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &home, Platform::Linux, false),
            Sensitivity::None,
            "{path}"
        );
    }
}

#[test]
fn keychains_are_credential_storage_on_each_root() {
    let home = AbsolutePath::new(Platform::Macos, "/Users/test").unwrap();
    for path in [
        "/Users/test/Library/Keychains/login.keychain-db",
        "/Library/Keychains/System.keychain",
    ] {
        let target = AbsolutePath::new(Platform::Macos, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &home, Platform::Macos, false),
            Sensitivity::CredentialSecret,
            "{path}"
        );
    }
}

#[test]
fn host_integrity_catalog_is_operation_and_family_specific() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (path, expected) in [
        ("/home/test/.bashrc", HostIntegrityClass::ShellProfile),
        (
            "/home/test/.config/systemd/user/backup.service",
            HostIntegrityClass::StartupPersistence,
        ),
        ("/etc/crontab", HostIntegrityClass::StartupPersistence),
        (
            "/usr/lib/systemd/system-generators/example",
            HostIntegrityClass::StartupPersistence,
        ),
        (
            "/home/test/.ssh/authorized_keys",
            HostIntegrityClass::AuthIdentity,
        ),
        ("/etc/passwd", HostIntegrityClass::AuthIdentity),
        ("/etc/sudoers.d/team", HostIntegrityClass::AuthIdentity),
        ("/etc/ssh/sshd_config", HostIntegrityClass::AuthIdentity),
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Write,
                path,
                &target,
                &home,
                Platform::Linux,
                false,
                false,
            ),
            Some(expected),
            "{path}"
        );
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Read,
                path,
                &target,
                &home,
                Platform::Linux,
                false,
                false,
            ),
            None,
            "read {path}"
        );
    }
    for path in [
        "/home/test/.vimrc",
        "/home/test/notes",
        "/repo/.env",
        "/etc/hosts",
        "/etc/systemd/network/10-ethernet.network",
        "/tmp/file",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Write,
                path,
                &target,
                &home,
                Platform::Linux,
                false,
                false,
            ),
            None,
            "{path}"
        );
    }
}

#[test]
fn host_integrity_catalog_preserves_the_exact_profile_partition() {
    let linux_home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    let classify = |path: &str, home: &AbsolutePath, platform: Platform| {
        let target = AbsolutePath::new(platform, path).unwrap();
        host_integrity_class(
            FilesystemOperation::Write,
            path,
            &target,
            home,
            platform,
            false,
            false,
        )
    };

    for path in [
        "/home/test/.bashrc",
        "/home/test/.bash_profile",
        "/home/test/.bash_login",
        "/home/test/.bash_aliases",
        "/home/test/.bash_logout",
        "/home/test/.profile",
        "/home/test/.zshrc",
        "/home/test/.zshenv",
        "/home/test/.zprofile",
        "/home/test/.zlogin",
        "/home/test/.zlogout",
        "/home/test/.config/fish/config.fish",
        "/home/test/.config/fish/conf.d/aliases.fish",
    ] {
        assert_eq!(
            classify(path, &linux_home, Platform::Linux),
            Some(HostIntegrityClass::ShellProfile),
            "{path}"
        );
    }

    for path in [
        "/home/test/.ssh/rc",
        "/home/test/.config/autostart/example.desktop",
        "/home/test/.config/systemd/user/example.service",
        "/etc/profile",
        "/etc/profile.d/example.sh",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/zshenv",
        "/etc/zprofile",
        "/etc/zshrc",
        "/etc/zlogin",
        "/etc/zlogout",
        "/etc/zsh/zshenv",
        "/etc/zsh/zprofile",
        "/etc/zsh/zshrc",
        "/etc/zsh/zlogin",
        "/etc/zsh/zlogout",
        "/etc/crontab",
        "/etc/cron.d/example",
        "/etc/cron.hourly/example",
        "/etc/cron.daily/example",
        "/etc/cron.weekly/example",
        "/etc/cron.monthly/example",
        "/var/spool/cron/example",
        "/etc/systemd/system/example.service",
        "/run/systemd/system/example.service",
        "/usr/local/lib/systemd/system/example.service",
        "/usr/lib/systemd/system/example.service",
        "/lib/systemd/system/example.service",
        "/etc/systemd/user/example.service",
        "/usr/local/lib/systemd/user/example.service",
        "/usr/lib/systemd/user/example.service",
        "/lib/systemd/user/example.service",
        "/etc/systemd/system-generators/example",
        "/etc/systemd/user-generators/example",
        "/etc/systemd/system-environment-generators/example",
        "/etc/systemd/user-environment-generators/example",
        "/usr/local/lib/systemd/system-generators/example",
        "/usr/local/lib/systemd/user-generators/example",
        "/usr/local/lib/systemd/system-environment-generators/example",
        "/usr/local/lib/systemd/user-environment-generators/example",
        "/usr/lib/systemd/system-generators/example",
        "/usr/lib/systemd/user-generators/example",
        "/usr/lib/systemd/system-environment-generators/example",
        "/usr/lib/systemd/user-environment-generators/example",
        "/lib/systemd/system-generators/example",
        "/lib/systemd/user-generators/example",
        "/lib/systemd/system-environment-generators/example",
        "/lib/systemd/user-environment-generators/example",
        "/etc/init.d/example",
        "/etc/rc.local",
        "/etc/xdg/autostart/example.desktop",
        "/etc/ssh/sshrc",
        "/etc/ld.so.preload",
    ] {
        assert_eq!(
            classify(path, &linux_home, Platform::Linux),
            Some(HostIntegrityClass::StartupPersistence),
            "{path}"
        );
    }

    let mac_home = AbsolutePath::new(Platform::Macos, "/Users/test").unwrap();
    for path in [
        "/Users/test/Library/LaunchAgents/example.plist",
        "/Library/LaunchAgents/example.plist",
        "/Library/LaunchDaemons/example.plist",
    ] {
        assert_eq!(
            classify(path, &mac_home, Platform::Macos),
            Some(HostIntegrityClass::StartupPersistence),
            "{path}"
        );
    }

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    for path in [
        r"C:\Users\Test\Documents\PowerShell\profile.ps1",
        r"C:\Users\Test\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
        r"C:\Users\Test\Documents\WindowsPowerShell\profile.ps1",
        r"C:\Users\Test\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    ] {
        assert_eq!(
            classify(path, &windows_home, Platform::Windows),
            Some(HostIntegrityClass::ShellProfile),
            "{path}"
        );
    }
    for path in [
        r"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\example.cmd",
        r"D:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\example.cmd",
    ] {
        assert_eq!(
            classify(path, &windows_home, Platform::Windows),
            Some(HostIntegrityClass::StartupPersistence),
            "{path}"
        );
    }

    for (path, home, platform) in [
        ("/home/test/.bashrc.d/example", &linux_home, Platform::Linux),
        ("/home/test/.zshrc.d/example", &linux_home, Platform::Linux),
        ("/home/test/.ssh/config", &linux_home, Platform::Linux),
        (
            "/run/systemd/user/example.service",
            &linux_home,
            Platform::Linux,
        ),
        ("/private/etc/profile", &mac_home, Platform::Macos),
        (
            r"C:\Users\Test\Documents\PowerShell\Microsoft.VSCode_profile.ps1",
            &windows_home,
            Platform::Windows,
        ),
    ] {
        assert_eq!(classify(path, home, platform), None, "{path}");
    }
}

#[test]
fn host_integrity_uses_the_strongest_requested_or_effective_identity() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (target, expected) in [
        (
            "/home/test/.config/systemd/user/example.service",
            HostIntegrityClass::StartupPersistence,
        ),
        (
            "/home/test/.ssh/authorized_keys",
            HostIntegrityClass::AuthIdentity,
        ),
    ] {
        let target = AbsolutePath::new(Platform::Linux, target).unwrap();
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Write,
                "/home/test/.bashrc",
                &target,
                &home,
                Platform::Linux,
                false,
                false,
            ),
            Some(expected)
        );
    }
}

#[test]
fn host_integrity_patterns_and_recursive_deletes_cover_catalog_reach() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (path, pattern, recursive, expected) in [
        (
            "/home/test/.ssh/*",
            true,
            true,
            Some(HostIntegrityClass::AuthIdentity),
        ),
        (
            "/home/test/.ssh",
            false,
            true,
            Some(HostIntegrityClass::AuthIdentity),
        ),
        (
            "/home/test/.config",
            false,
            true,
            Some(HostIntegrityClass::StartupPersistence),
        ),
        (
            "/etc/ssh",
            false,
            true,
            Some(HostIntegrityClass::AuthIdentity),
        ),
        ("/home/test/*", true, true, None),
        (
            "/home/test/.*",
            true,
            true,
            Some(HostIntegrityClass::AuthIdentity),
        ),
        ("/home/test/.config", false, false, None),
        ("/etc/ssh", false, false, None),
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Delete,
                path,
                &target,
                &home,
                Platform::Linux,
                pattern,
                recursive,
            ),
            expected,
            "{path}"
        );
    }
}

#[test]
fn host_integrity_catalog_handles_macos_aliases_and_windows_drives() {
    let mac_home = AbsolutePath::new(Platform::Macos, "/Users/test").unwrap();
    for (path, expected) in [
        (
            "/Users/test/Library/LaunchAgents/dev.example.plist",
            HostIntegrityClass::StartupPersistence,
        ),
        (
            "/private/etc/sudoers.d/team",
            HostIntegrityClass::AuthIdentity,
        ),
    ] {
        let target = AbsolutePath::new(Platform::Macos, path).unwrap();
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Write,
                path,
                &target,
                &mac_home,
                Platform::Macos,
                false,
                false,
            ),
            Some(expected),
            "{path}"
        );
    }

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    for (path, expected) in [
        (
            r"C:\Users\Test\Documents\PowerShell\PROFILE.PS1",
            HostIntegrityClass::ShellProfile,
        ),
        (
            r"D:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\agent.cmd",
            HostIntegrityClass::StartupPersistence,
        ),
        (
            r"D:\Windows\System32\config\SAM",
            HostIntegrityClass::AuthIdentity,
        ),
    ] {
        let target = AbsolutePath::new(Platform::Windows, path).unwrap();
        assert_eq!(
            host_integrity_class(
                FilesystemOperation::Write,
                path,
                &target,
                &windows_home,
                Platform::Windows,
                false,
                false,
            ),
            Some(expected),
            "{path}"
        );
    }
}

#[test]
fn nah_protection_tiers_are_narrow_and_cross_platform() {
    let linux_home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    let linux_root = Root::new(
        RootKind::Project,
        AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
    );
    for (path, expected) in [
        (
            "/home/test/.nah/trust.json",
            Some(NahProtectionTier::Critical),
        ),
        (
            "/home/test/.nah/nap.json",
            Some(NahProtectionTier::Permanent),
        ),
        (
            "/home/test/.nah/nap.key",
            Some(NahProtectionTier::Permanent),
        ),
        (
            "/home/test/.nah/guards/corp/run",
            Some(NahProtectionTier::Proposal),
        ),
        (
            "/repo/.nah/guards/deploy/run",
            Some(NahProtectionTier::Proposal),
        ),
        ("/home/test/.claude/hooks/nah", None),
        ("/home/test/Documents/Cline/Hooks/PreToolUse", None),
        ("/home/test/Cline/Hooks/PreToolUse", None),
        ("/home/test/.cline/hooks/PreToolUse", None),
        ("/repo/.clinerules/hooks/PreToolUse", None),
        ("/repo/.cline/plugins/unsafe.js", None),
        ("/repo/.codex/config.toml", None),
        ("/home/test/.codex/hooks.json", None),
        ("/home/test/.cursor/hooks.json", None),
        ("/home/test/.factory/hooks.json", None),
        ("/home/test/.gemini/config/hooks.json", None),
        ("/home/test/.gemini", None),
        (
            "/home/test/.gemini/antigravity-cli/plugins/unsafe/hooks.json",
            None,
        ),
        ("/home/test/.gemini/config/plugins/unsafe/hooks.json", None),
        ("/home/test/.config/devin/config.json", None),
        ("/home/test/.config/devin", None),
        ("/home/test/.hermes/config.yaml", None),
        ("/home/test/.hermes/plugins/nah/__init__.py", None),
        ("/home/test/.openclaw/extensions/nah/index.js", None),
        ("/home/test/.openclaw/openclaw.json", None),
        ("/repo/.openclaw/extensions/mutate.js", None),
        ("/repo/.hermes/plugins/mutate.py", None),
        ("/repo/.cursor/hooks/override.sh", None),
        ("/repo/.agents/hooks.json", None),
        ("/repo/.factory/hooks.json", None),
        ("/repo/.agents/plugins/unsafe/hooks.json", None),
        ("/home/test/.pi/agent/extensions/nah/index.js", None),
        ("/home/test/.pi/agent/settings.json", None),
        ("/home/test/.config/opencode/plugins/nah.js", None),
        ("/home/test/.config/amp/plugins/nah.ts", None),
        ("/repo/.amp/plugins/mutate-args.ts", None),
        ("/repo/.amp", None),
        ("/repo/.opencode/plugins/mutate-args.js", None),
        ("/repo/.opencode", None),
        ("/repo/opencode.json", None),
        ("/home/test/.config/opencode", None),
        ("/home/test/.pi", None),
        ("/home/test", None),
        ("/", None),
        ("/outside/.claude/hooks/nah", None),
        ("/opt/tools/bin/nah", Some(NahProtectionTier::Critical)),
        ("/repo/src/nah.rs", None),
        ("/repo/bin/nah", None),
    ] {
        let path = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            tier::classify(
                FilesystemOperation::Write,
                &path,
                &path,
                std::slice::from_ref(&linux_root),
                &[],
                &linux_home,
                &[],
                Platform::Linux,
                false,
            ),
            expected,
            "{path:?}"
        );
    }

    let trusted = AbsolutePath::new(Platform::Linux, "/trusted").unwrap();
    let trusted_guard =
        AbsolutePath::new(Platform::Linux, "/trusted/.nah/guards/deploy/run").unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Write,
            &trusted_guard,
            &trusted_guard,
            &[],
            &[trusted],
            &linux_home,
            &[],
            Platform::Linux,
            false,
        ),
        Some(NahProtectionTier::Proposal)
    );

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    let windows_target =
        AbsolutePath::new(Platform::Windows, r"c:\users\test\.NAH\trust.json").unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Delete,
            &windows_target,
            &windows_target,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        Some(NahProtectionTier::Critical)
    );
    assert_eq!(
        tier::classify(
            FilesystemOperation::Read,
            &windows_target,
            &windows_target,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        None
    );
    let windows_nap_key =
        AbsolutePath::new(Platform::Windows, r"c:\users\test\.NAH\nap.key").unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Write,
            &windows_nap_key,
            &windows_nap_key,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        Some(NahProtectionTier::Permanent)
    );
    let windows_release_binary = AbsolutePath::new(
        Platform::Windows,
        r"c:\users\test\AppData\Local\Programs\nah\nah.exe",
    )
    .unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Write,
            &windows_release_binary,
            &windows_release_binary,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        Some(NahProtectionTier::Critical)
    );
    let windows_release_directory = AbsolutePath::new(
        Platform::Windows,
        r"c:\users\test\AppData\Local\Programs\nah",
    )
    .unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Delete,
            &windows_release_directory,
            &windows_release_directory,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        Some(NahProtectionTier::Critical)
    );
    let windows_devin = AbsolutePath::new(
        Platform::Windows,
        r"c:\users\test\AppData\Roaming\devin\config.json",
    )
    .unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Write,
            &windows_devin,
            &windows_devin,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        None
    );
    let windows_devin_directory =
        AbsolutePath::new(Platform::Windows, r"c:\users\test\AppData\Roaming\devin").unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Delete,
            &windows_devin_directory,
            &windows_devin_directory,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        None
    );
}

#[test]
fn critical_aliases_cannot_be_downgraded_by_proposal_paths() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    let root = Root::new(
        RootKind::Project,
        AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
    );
    for (resolved, target) in [
        (
            "/home/test/.nah/guards/../trust.json",
            "/home/test/.nah/trust.json",
        ),
        (
            "/home/test/.nah/guards/demo/link",
            "/home/test/.nah/trust.json",
        ),
    ] {
        assert_eq!(
            tier::classify(
                FilesystemOperation::Write,
                &AbsolutePath::new(Platform::Linux, resolved).unwrap(),
                &AbsolutePath::new(Platform::Linux, target).unwrap(),
                std::slice::from_ref(&root),
                &[],
                &home,
                &[],
                Platform::Linux,
                false,
            ),
            Some(NahProtectionTier::Critical),
            "{resolved} -> {target}"
        );
    }

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    assert_eq!(
        tier::classify(
            FilesystemOperation::Write,
            &AbsolutePath::new(
                Platform::Windows,
                r"C:\Users\Test\.nah\guards\..\trust.json",
            )
            .unwrap(),
            &AbsolutePath::new(Platform::Windows, r"C:\Users\Test\.nah\trust.json",).unwrap(),
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
        ),
        Some(NahProtectionTier::Critical)
    );
}

#[test]
fn only_known_nah_state_mutations_are_recognized() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for arguments in [
        &["nap"][..],
        &["tui"][..],
        &["trust", "/repo"][..],
        &["untrust", "/repo"][..],
        &["guard", "enable", "fs-system-tree"][..],
        &["effinterp", "on"][..],
        &["hook", "claude", "install"][..],
        &["hook", "codex", "uninstall"][..],
    ] {
        assert_eq!(
            runtime_cli::classify("nah", &argv(arguments), &home, Platform::Linux),
            Some(RuntimeCli::Nah),
            "{arguments:?}"
        );
    }
    for arguments in [
        &["docs", "guards"][..],
        &["log", "--json"][..],
        &["why", "decision-id"][..],
        &["hook", "claude", "status"][..],
        &["hook", "unknown", "install"][..],
        &["test", "git status"][..],
    ] {
        assert_eq!(
            runtime_cli::classify("nah", &argv(arguments), &home, Platform::Linux),
            None,
            "{arguments:?}"
        );
    }
}

#[test]
fn runtime_plugin_mutations_are_recognized() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (program, arguments, expected) in [
        ("amp", &["plugins", "remove", "nah.ts"][..], RuntimeCli::Amp),
        (
            "amp",
            &["plugins", "rm", "nah.ts", "--target", "system"][..],
            RuntimeCli::Amp,
        ),
        (
            "agy",
            &["plugin", "disable", "nah"][..],
            RuntimeCli::Antigravity,
        ),
        (
            "droid",
            &["plugin", "uninstall", "nah"][..],
            RuntimeCli::Droid,
        ),
        (
            "copilot",
            &["plugin", "disable", "nah"][..],
            RuntimeCli::Copilot,
        ),
        (
            "hermes",
            &["hooks", "revoke", "nah hook hermes run"][..],
            RuntimeCli::Hermes,
        ),
        (
            "hermes",
            &["config", "unset", "hooks.pre_tool_call.0"][..],
            RuntimeCli::Hermes,
        ),
        (
            "hermes",
            &["config", "set", "hooks.pre_tool_call.x"][..],
            RuntimeCli::Hermes,
        ),
        (
            "openclaw",
            &["plugins", "uninstall", "nah", "--force"][..],
            RuntimeCli::Openclaw,
        ),
        (
            "openclaw",
            &["plugins", "uninstall", "--force", "nah"][..],
            RuntimeCli::Openclaw,
        ),
        (
            "openclaw",
            &["config", "set", "plugins.enabled", "false"][..],
            RuntimeCli::Openclaw,
        ),
        (
            "openclaw",
            &["config", "unset", "plugins.entries.nah"][..],
            RuntimeCli::Openclaw,
        ),
    ] {
        assert_eq!(
            runtime_cli::classify(program, &argv(arguments), &home, Platform::Linux),
            Some(expected),
            "{program} {arguments:?}"
        );
    }
    for (program, arguments) in [
        ("amp", &["plugins", "add", "@owner/example"][..]),
        ("agy", &["plugin", "disable", "unsafe"][..]),
        ("agy", &["plugin", "remove", "nah"][..]),
        ("antigravity", &["plugin", "disable", "nah"][..]),
        ("droid", &["plugin", "disable", "nah"][..]),
        ("droid", &["plugin", "list"][..]),
        ("hermes", &["hooks", "revoke", "other-hook"][..]),
        ("copilot", &["plugin", "install", "unsafe@example"][..]),
        ("openclaw", &["plugins", "update", "nah"][..]),
    ] {
        assert_eq!(
            runtime_cli::classify(program, &argv(arguments), &home, Platform::Linux),
            None,
            "{program} {arguments:?}"
        );
    }
}

#[test]
fn runtime_launch_bypasses_are_recognized() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (program, arguments, expected) in [
        ("claude", &["--safe-mode"][..], RuntimeCli::Claude),
        ("claude", &["--bare"][..], RuntimeCli::Claude),
        ("cline", &["--config", "/tmp/other"][..], RuntimeCli::Cline),
        ("codex", &["--disable", "hooks"][..], RuntimeCli::Codex),
        (
            "devin",
            &["--config", "/tmp/unsafe.json"][..],
            RuntimeCli::Devin,
        ),
        (
            "droid",
            &["--settings=/tmp/unsafe.json"][..],
            RuntimeCli::Droid,
        ),
        ("hermes", &["--safe-mode"][..], RuntimeCli::Hermes),
        (
            "openclaw",
            &["--profile", "other"][..],
            RuntimeCli::Openclaw,
        ),
        ("openclaw", &["--dev"][..], RuntimeCli::Openclaw),
        ("opencode", &["--pure"][..], RuntimeCli::Opencode),
        ("pi", &["--no-extensions"][..], RuntimeCli::Pi),
        (
            "prime-agent",
            &["--no-extensions"][..],
            RuntimeCli::PrimeAgent,
        ),
    ] {
        assert_eq!(
            runtime_cli::classify(program, &argv(arguments), &home, Platform::Linux),
            Some(expected),
            "{program} {arguments:?}"
        );
    }
    for (program, arguments) in [
        ("cline", &["--config", ""][..]),
        ("cline", &["--config="][..]),
        ("cline", &["--config", "/home/test/.cline"][..]),
        ("devin", &["--config", ""][..]),
        (
            "devin",
            &["--config", "/home/test/.config/devin/config.json"][..],
        ),
        ("droid", &["--settings", ""][..]),
        (
            "droid",
            &["--settings", "/home/test/.factory/settings.json"][..],
        ),
        ("openclaw", &["--profile", "default"][..]),
        (
            "droid",
            &["exec", "--skip-permissions-unsafe", "echo ok"][..],
        ),
        ("cargo", &["uninstall", "nah-cli"][..]),
    ] {
        assert_eq!(
            runtime_cli::classify(program, &argv(arguments), &home, Platform::Linux),
            None,
            "{program} {arguments:?}"
        );
    }
}

#[test]
fn help_and_version_argv_never_recognize_a_runtime() {
    let home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    for (program, arguments) in [
        ("nah", &["trust", ".", "--help"][..]),
        ("nah", &["hook", "codex", "install", "--help"][..]),
        ("claude", &["--safe-mode", "--help"][..]),
        ("hermes", &["--safe-mode", "--version"][..]),
        ("opencode", &["--pure", "--version"][..]),
    ] {
        assert_eq!(
            runtime_cli::classify(program, &argv(arguments), &home, Platform::Linux),
            None,
            "{program} {arguments:?}"
        );
    }
    // The executable is a program path, not a bare name.
    assert_eq!(
        runtime_cli::classify(
            "/home/test/.local/bin/nah",
            &argv(&["trust", "/repo"]),
            &home,
            Platform::Linux,
        ),
        Some(RuntimeCli::Nah)
    );
    assert_eq!(
        runtime_cli::classify(
            r"C:\Program Files\nah\NAH.EXE",
            &argv(&["nap"]),
            &home,
            Platform::Linux,
        ),
        Some(RuntimeCli::Nah)
    );
}
