//! One owner classifies the pure path labels. The effectinterp annotation
//! layer consumes these functions, so this corpus pins the labels it emits.

use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::labels::hidden_characters::has_hidden_characters;
use nah_proto::labels::host_integrity::host_integrity_class;
use nah_proto::labels::host_script::mixes_scripts;
use nah_proto::labels::scope::path_scope;
use nah_proto::labels::sensitivity::sensitivity;
use nah_proto::labels::tier;
use nah_proto::labels::{HostIntegrityClass, NahProtectionTier, PathScope, Sensitivity};
use nah_proto::observation::{Root, RootKind};

#[test]
fn secret_categories_are_narrow_and_cross_platform() {
    let linux_home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    // Private keys and recovery material nothing can reissue.
    for path in [
        "/home/test/.ssh",
        "/home/test/.ssh/id_rsa",
        "/home/test/.ssh/id_ed25519.backup",
        "/home/test/.ssh/identity",
        "/home/test/.gnupg",
        "/home/test/.gnupg/private-keys-v1.d/key",
        "/home/test/.gnupg/openpgp-revocs.d/revocation.rev",
        "/home/test/.gnupg/secring.gpg",
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &linux_home, Platform::Linux, false),
            Sensitivity::KeyMaterial,
            "{path}"
        );
    }
    // Login, token and configuration credentials their service can reissue.
    for path in [
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
        ("/home/*/.ssh/id_rsa", Sensitivity::KeyMaterial),
        ("/home/*/.aws/config", Sensitivity::OtherSensitive),
        // Credential basenames apply anywhere; the home glob is still
        // anchored beneath the home parent.
        ("/tmp/*/.ssh/id_rsa", Sensitivity::KeyMaterial),
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
        (r"C:\Users\Test\.SSH\id_rsa", Sensitivity::KeyMaterial),
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
    for (path, expected) in [
        ("/workspace/project/id_rsa", Sensitivity::KeyMaterial),
        (
            "/workspace/project/keys/id_ed25519",
            Sensitivity::KeyMaterial,
        ),
        ("/workspace/project/.netrc", Sensitivity::CredentialSecret),
        (
            "/workspace/project/.git-credentials",
            Sensitivity::CredentialSecret,
        ),
    ] {
        let target = AbsolutePath::new(Platform::Linux, path).unwrap();
        assert_eq!(
            sensitivity(path, &target, &home, Platform::Linux, false),
            expected,
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
            Sensitivity::KeyMaterial,
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
            tier::nah_protection_tier(
                FilesystemOperation::Write,
                &path,
                &path,
                std::slice::from_ref(&linux_root),
                &[],
                &linux_home,
                &[],
                Platform::Linux,
                false,
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
        tier::nah_protection_tier(
            FilesystemOperation::Write,
            &trusted_guard,
            &trusted_guard,
            &[],
            &[trusted],
            &linux_home,
            &[],
            Platform::Linux,
            false,
            false,
        ),
        Some(NahProtectionTier::Proposal)
    );

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    let windows_target =
        AbsolutePath::new(Platform::Windows, r"c:\users\test\.NAH\trust.json").unwrap();
    assert_eq!(
        tier::nah_protection_tier(
            FilesystemOperation::Delete,
            &windows_target,
            &windows_target,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
            false,
        ),
        Some(NahProtectionTier::Critical)
    );
    assert_eq!(
        tier::nah_protection_tier(
            FilesystemOperation::Read,
            &windows_target,
            &windows_target,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
            false,
        ),
        None
    );
    let windows_nap_key =
        AbsolutePath::new(Platform::Windows, r"c:\users\test\.NAH\nap.key").unwrap();
    assert_eq!(
        tier::nah_protection_tier(
            FilesystemOperation::Write,
            &windows_nap_key,
            &windows_nap_key,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
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
        tier::nah_protection_tier(
            FilesystemOperation::Write,
            &windows_release_binary,
            &windows_release_binary,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
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
        tier::nah_protection_tier(
            FilesystemOperation::Delete,
            &windows_release_directory,
            &windows_release_directory,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
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
        tier::nah_protection_tier(
            FilesystemOperation::Write,
            &windows_devin,
            &windows_devin,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
            false,
        ),
        None
    );
    let windows_devin_directory =
        AbsolutePath::new(Platform::Windows, r"c:\users\test\AppData\Roaming\devin").unwrap();
    assert_eq!(
        tier::nah_protection_tier(
            FilesystemOperation::Delete,
            &windows_devin_directory,
            &windows_devin_directory,
            &[],
            &[],
            &windows_home,
            &[],
            Platform::Windows,
            false,
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
            tier::nah_protection_tier(
                FilesystemOperation::Write,
                &AbsolutePath::new(Platform::Linux, resolved).unwrap(),
                &AbsolutePath::new(Platform::Linux, target).unwrap(),
                std::slice::from_ref(&root),
                &[],
                &home,
                &[],
                Platform::Linux,
                false,
                false,
            ),
            Some(NahProtectionTier::Critical),
            "{resolved} -> {target}"
        );
    }

    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\Test").unwrap();
    assert_eq!(
        tier::nah_protection_tier(
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
            false,
        ),
        Some(NahProtectionTier::Critical)
    );
}
#[test]
fn nap_container_requires_whole_container_mutation_evidence() {
    use nah_proto::action::FilesystemOperation;
    use nah_proto::ctx::{AbsolutePath, Platform};
    use nah_proto::labels::NahProtectionTier;
    for (platform, home, container) in [
        (Platform::Linux, "/home/test", "/home/test/.nah"),
        (Platform::Windows, r"C:\Users\Test", r"c:\users\test\.NAH"),
    ] {
        let home = AbsolutePath::new(platform, home).unwrap();
        let target = AbsolutePath::new(platform, container).unwrap();
        for operation in [FilesystemOperation::Write, FilesystemOperation::Delete] {
            assert_eq!(
                tier::nah_protection_tier(
                    operation,
                    &target,
                    &target,
                    &[],
                    &[],
                    &home,
                    &[],
                    platform,
                    false,
                    true
                ),
                Some(NahProtectionTier::Permanent)
            );
            assert_eq!(
                tier::nah_protection_tier(
                    operation,
                    &target,
                    &target,
                    &[],
                    &[],
                    &home,
                    &[],
                    platform,
                    false,
                    false
                ),
                Some(NahProtectionTier::Critical)
            );
        }
    }
}

#[test]
fn path_scope_ranks_project_roots_over_home_and_system_trees() {
    for (platform, home, outer, inner, cases) in [
        (
            Platform::Linux,
            "/home/test",
            "/home/test/work",
            "/home/test/work/repo",
            &[
                ("/home/test/work/repo/src/main.rs", "inner"),
                ("/home/test/work/notes.md", "outer"),
                ("/home/test/.bashrc", "home"),
                ("/home/test", "home"),
                ("/etc/systemd/system/nah.service", "system"),
                ("/var/log/syslog", "system"),
                ("/opt/tools/bin/nah", "outside"),
            ][..],
        ),
        (
            Platform::Macos,
            "/Users/test",
            "/Users/test/work",
            "/Users/test/work/repo",
            &[
                ("/Users/test/work/repo/.nah/guards/deploy/run", "inner"),
                ("/Users/test/work/repo", "inner"),
                ("/Users/test/Library/LaunchAgents/agent.plist", "home"),
                ("/private/etc/sudoers", "outside"),
                ("/etc/sudoers", "system"),
                ("/Applications/Xcode.app", "outside"),
            ][..],
        ),
        (
            Platform::Windows,
            r"C:\Users\Test",
            r"C:\Users\Test\work",
            r"C:\Users\Test\work\repo",
            &[
                (r"c:\users\test\WORK\Repo\src\main.rs", "inner"),
                (r"C:\Users\Test\work\notes.md", "outer"),
                (r"C:\Users\Test\.nah\trust.json", "home"),
                (r"C:\Windows\System32\config\SAM", "outside"),
            ][..],
        ),
    ] {
        let home = AbsolutePath::new(platform, home).unwrap();
        let outer = AbsolutePath::new(platform, outer).unwrap();
        let inner = AbsolutePath::new(platform, inner).unwrap();
        // Ordered outermost first so the innermost root has to win on length.
        let roots = [
            Root::new(RootKind::Project, outer.clone()),
            Root::new(RootKind::Project, inner.clone()),
        ];
        for (target, expected) in cases {
            let expected = match *expected {
                "inner" => PathScope::Project {
                    root: inner.clone(),
                },
                "outer" => PathScope::Project {
                    root: outer.clone(),
                },
                "home" => PathScope::Home,
                "system" => PathScope::System,
                _ => PathScope::OutsideProject,
            };
            let target = AbsolutePath::new(platform, *target).unwrap();
            assert_eq!(
                path_scope(&target, &roots, &home, platform),
                expected,
                "{target:?}"
            );
        }
    }
}

#[test]
fn installed_nah_identity_and_cargo_destinations_share_one_lexical_path() {
    use nah_proto::labels::protected_path_ancestor;
    let windows_home = AbsolutePath::new(Platform::Windows, r"C:\Users\X").unwrap();
    let linux_home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
    let installed = |path: &str, home: &AbsolutePath, platform: Platform| {
        tier::is_installed_nah(path, &[], home, platform)
    };
    // Windows paths are case-insensitive, and `..` stops at the drive.
    for path in [
        r"C:\Users\X\.cargo\bin\NAH.exe",
        "c:/users/x/.CARGO/bin/../bin/nah.exe",
        r"C:\..\Users\X\.cargo\bin\nah.exe",
    ] {
        assert!(installed(path, &windows_home, Platform::Windows), "{path}");
    }
    assert!(protected_path_ancestor(
        r"C:\Users\X\.Cargo\BIN",
        windows_home.as_str(),
        &[],
        Platform::Windows,
    ));
    assert!(installed(
        "/usr/local/lib/../bin/nah",
        &linux_home,
        Platform::Linux
    ));
    // Outside Windows a backslash is part of a name, so it spells another file.
    assert!(!installed(
        r"/home/test/.cargo\bin/nah",
        &linux_home,
        Platform::Linux
    ));
    assert!(!installed(
        "/home/test/.cargo/bin/rg",
        &linux_home,
        Platform::Linux
    ));
    assert!(!protected_path_ancestor(
        "/tmp/tools/bin",
        linux_home.as_str(),
        &[],
        Platform::Linux,
    ));
}

#[test]
fn lookalike_hosts_mix_scripts_within_one_label() {
    for host in [
        // Latin with a Cyrillic U+0456, in the first label or a later one.
        "g\u{456}thub.com",
        "api.g\u{456}thub.com",
        // The same label in punycode, with an uppercase prefix.
        "xn--gthub-n2e.com",
        "XN--gthub-n2e.com",
        // Digits and a hyphen do not make a mixed label single-script.
        "g\u{456}thub-2.com",
        // URL clients decode escapes, partial or complete, before resolving.
        "g%D1%96thub.com",
        "%67%d1%96%74%68%75%62.com",
        // UTS #46 maps mathematical letters to the Latin ones they draw.
        "\u{1d558}\u{456}\u{1d565}\u{1d559}\u{1d566}\u{1d553}.com",
        // An ideographic full stop separates labels like a dot.
        "g\u{456}thub\u{3002}com",
    ] {
        assert!(mixes_scripts(host), "{host}");
    }
    for host in [
        "github.com",
        "my-site123.example.com",
        // Single-script internationalized labels, Latin and Cyrillic.
        "m\u{fc}nchen.de",
        "xn--mnchen-3ya.de",
        "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}-1.\u{440}\u{444}",
        // A combining mark is Inherited, so it joins the Latin it follows.
        "cafe\u{301}.fr",
        // Han beside Latin is one writing system under UTS #39 revision 34.
        "\u{6f22}\u{5b57}api.example",
        // Han beside Katakana and Hiragana is one writing system, Japanese.
        "\u{65e5}\u{672c}\u{30c9}\u{30e1}\u{30a4}\u{30f3}\u{306e}.jp",
        // Scripts may differ between labels.
        "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.com",
        // Punycode that does not decode is judged as written, all ASCII.
        "xn--gthub-n2e!.com",
    ] {
        assert!(!mixes_scripts(host), "{host}");
    }
}

#[test]
fn hidden_characters_are_the_display_changing_classes_at_their_boundaries() {
    // Tag letters spelling `code`, the specification of a subdivision flag.
    let tags = |code: &str| {
        code.chars()
            .map(|letter| char::from_u32(0xE0000 + letter as u32).unwrap())
            .collect::<String>()
    };
    let flag = |code: &str| format!("\u{1F3F4}{}\u{E007F}", tags(code));
    for character in concat!(
        // C0 controls other than tab, line feed and carriage return; DEL; C1.
        "\u{0}\u{8}\u{B}\u{C}\u{E}\u{1B}\u{1F}\u{7F}\u{80}\u{9B}\u{9F}",
        // Bidi embeddings, overrides and isolates.
        "\u{202A}\u{202E}\u{2066}\u{2069}",
        // Invisible format characters.
        "\u{200B}\u{2060}\u{FEFF}\u{180E}",
        // Tag characters outside a subdivision flag.
        "\u{E0000}\u{E0001}\u{E0041}\u{E007F}",
    )
    .chars()
    {
        let text = format!("echo a{character}b");
        assert!(has_hidden_characters(&text), "{:X}", character as u32);
    }
    for character in concat!(
        "\t\n\r ~\u{A0}\u{2029}\u{202F}\u{2065}\u{206A}\u{2061}\u{180F}",
        // Joiners, directional marks and variation selectors.
        "\u{200C}\u{200D}\u{200E}\u{200F}\u{61C}\u{FE0F}\u{E0100}",
    )
    .chars()
    {
        let text = format!("echo a{character}b");
        assert!(!has_hidden_characters(&text), "{:X}", character as u32);
    }
    // Escapes spelled as text are the characters `\`, `e` and `x`.
    assert!(!has_hidden_characters(
        r"printf '\e[31m\x1b[0m\033[1m'; echo $'\e'"
    ));
    // Subdivision flags, and emoji with joiners and skin tones.
    for text in [
        flag("gbsct"),
        format!("{}{}", flag("gbeng"), flag("gbwls")),
        format!(
            "{} \u{1F469}\u{200D}\u{1F4BB} \u{1F44D}\u{1F3FD}",
            flag("usca")
        ),
    ] {
        assert!(!has_hidden_characters(&text), "{text:?}");
    }
    // Tag runs that only look like a flag hide text.
    for text in [
        flag("gb"),
        flag("gbabcdef"),
        flag("GBSCT"),
        flag("rm -rf"),
        format!("\u{1F3F4}{}", tags("gbsct")),
        format!("{}\u{E007F}", tags("gbsct")),
        format!("{}{}", flag("gbsct"), tags("x")),
    ] {
        assert!(has_hidden_characters(&text), "{text:?}");
    }
}
