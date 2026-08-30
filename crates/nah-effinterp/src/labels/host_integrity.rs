// UNDOCUMENTED-EFFINTERP: copied host-integrity catalogs for plan annotations.

use nah_proto::action::{FilesystemOperation, HostIntegrityClass, pattern_bound};
use nah_proto::ctx::{AbsolutePath, Platform};

use super::{contains, join};

/// Classifies the host-integrity surface a write or delete reaches; reads and
/// paths outside the catalog return `None`.
pub fn host_integrity_class(
    operation: FilesystemOperation,
    requested: &str,
    target: &AbsolutePath,
    home: &AbsolutePath,
    platform: Platform,
    pattern: bool,
    recursive: bool,
) -> Option<HostIntegrityClass> {
    if !matches!(
        operation,
        FilesystemOperation::Write | FilesystemOperation::Delete
    ) {
        return None;
    }
    let mut paths = vec![target.as_str().to_owned()];
    if let Some(requested) = requested_identity(requested, home, platform)
        && !paths
            .iter()
            .any(|path| equivalent(path, &requested, platform))
    {
        paths.push(requested);
    }
    let recursive_delete = operation == FilesystemOperation::Delete && recursive;
    if paths
        .iter()
        .any(|path| auth_identity_path(path, home, platform, pattern, recursive_delete))
    {
        Some(HostIntegrityClass::AuthIdentity)
    } else if paths
        .iter()
        .any(|path| startup_persistence_path(path, home, platform, pattern, recursive_delete))
    {
        Some(HostIntegrityClass::StartupPersistence)
    } else if paths
        .iter()
        .any(|path| shell_profile_path(path, home, platform, pattern, recursive_delete))
    {
        Some(HostIntegrityClass::ShellProfile)
    } else {
        None
    }
}

fn requested_identity(requested: &str, home: &AbsolutePath, platform: Platform) -> Option<String> {
    if requested == "~" {
        Some(home.as_str().to_owned())
    } else if let Some(relative) = requested
        .strip_prefix("~/")
        .or_else(|| requested.strip_prefix("~\\"))
    {
        Some(join(home.as_str(), relative, platform))
    } else if AbsolutePath::new(platform, requested).is_ok() {
        Some(requested.to_owned())
    } else {
        None
    }
}

fn auth_identity_path(
    path: &str,
    home: &AbsolutePath,
    platform: Platform,
    pattern: bool,
    recursive_delete: bool,
) -> bool {
    if catalog_entry_matches(
        path,
        &join(home.as_str(), ".ssh/authorized_keys", platform),
        false,
        platform,
        pattern,
        recursive_delete,
    ) || catalog_entry_matches(
        path,
        &join(home.as_str(), ".ssh/authorized_keys.d", platform),
        true,
        platform,
        pattern,
        recursive_delete,
    ) {
        return true;
    }
    match platform {
        Platform::Linux | Platform::Macos => {
            let mut files = vec![
                "/etc/passwd",
                "/etc/group",
                "/etc/shadow",
                "/etc/gshadow",
                "/etc/sudoers",
                "/etc/pam.conf",
                "/etc/ssh/sshd_config",
            ];
            let mut directories = vec!["/etc/sudoers.d", "/etc/pam.d", "/etc/ssh/sshd_config.d"];
            if platform == Platform::Macos {
                files.extend([
                    "/private/etc/passwd",
                    "/private/etc/group",
                    "/private/etc/shadow",
                    "/private/etc/gshadow",
                    "/private/etc/sudoers",
                    "/private/etc/pam.conf",
                    "/private/etc/ssh/sshd_config",
                ]);
                directories.extend([
                    "/private/etc/sudoers.d",
                    "/private/etc/pam.d",
                    "/private/etc/ssh/sshd_config.d",
                ]);
            }
            files.into_iter().any(|entry| {
                catalog_entry_matches(path, entry, false, platform, pattern, recursive_delete)
            }) || directories.into_iter().any(|entry| {
                catalog_entry_matches(path, entry, true, platform, pattern, recursive_delete)
            })
        }
        Platform::Windows => windows_suffix_matches(
            path,
            &[
                "/windows/system32/config/sam",
                "/windows/system32/config/security",
                "/windows/system32/config/system",
            ],
            false,
            pattern,
            recursive_delete,
        ),
    }
}

fn shell_profile_path(
    path: &str,
    home: &AbsolutePath,
    platform: Platform,
    pattern: bool,
    recursive_delete: bool,
) -> bool {
    let home_files = [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_aliases",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
        ".config/fish/config.fish",
    ];
    let mut platform_home_files = Vec::new();
    if platform == Platform::Windows {
        platform_home_files.extend([
            "Documents/PowerShell/profile.ps1",
            "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
            "Documents/WindowsPowerShell/profile.ps1",
            "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
        ]);
    }
    home_files
        .into_iter()
        .chain(platform_home_files)
        .any(|entry| {
            catalog_entry_matches(
                path,
                &join(home.as_str(), entry, platform),
                false,
                platform,
                pattern,
                recursive_delete,
            )
        })
        || catalog_entry_matches(
            path,
            &join(home.as_str(), ".config/fish/conf.d", platform),
            true,
            platform,
            pattern,
            recursive_delete,
        )
}

fn startup_persistence_path(
    path: &str,
    home: &AbsolutePath,
    platform: Platform,
    pattern: bool,
    recursive_delete: bool,
) -> bool {
    let mut home_directories = vec![".config/autostart", ".config/systemd/user"];
    if platform == Platform::Macos {
        home_directories.push("Library/LaunchAgents");
    } else if platform == Platform::Windows {
        home_directories.push("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    }
    if catalog_entry_matches(
        path,
        &join(home.as_str(), ".ssh/rc", platform),
        false,
        platform,
        pattern,
        recursive_delete,
    ) || home_directories.into_iter().any(|entry| {
        catalog_entry_matches(
            path,
            &join(home.as_str(), entry, platform),
            true,
            platform,
            pattern,
            recursive_delete,
        )
    }) {
        return true;
    }
    match platform {
        Platform::Linux | Platform::Macos => {
            let files = [
                "/etc/profile",
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
                "/etc/rc.local",
                "/etc/ssh/sshrc",
                "/etc/ld.so.preload",
            ];
            let mut directories = vec![
                "/etc/profile.d",
                "/etc/xdg/autostart",
                "/etc/cron.d",
                "/etc/cron.hourly",
                "/etc/cron.daily",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
                "/var/spool/cron",
                "/etc/systemd/system",
                "/run/systemd/system",
                "/usr/local/lib/systemd/system",
                "/usr/lib/systemd/system",
                "/lib/systemd/system",
                "/etc/systemd/user",
                "/usr/local/lib/systemd/user",
                "/usr/lib/systemd/user",
                "/lib/systemd/user",
                "/etc/systemd/system-generators",
                "/etc/systemd/user-generators",
                "/etc/systemd/system-environment-generators",
                "/etc/systemd/user-environment-generators",
                "/usr/local/lib/systemd/system-generators",
                "/usr/local/lib/systemd/user-generators",
                "/usr/local/lib/systemd/system-environment-generators",
                "/usr/local/lib/systemd/user-environment-generators",
                "/usr/lib/systemd/system-generators",
                "/usr/lib/systemd/user-generators",
                "/usr/lib/systemd/system-environment-generators",
                "/usr/lib/systemd/user-environment-generators",
                "/lib/systemd/system-generators",
                "/lib/systemd/user-generators",
                "/lib/systemd/system-environment-generators",
                "/lib/systemd/user-environment-generators",
                "/etc/init.d",
            ];
            if platform == Platform::Macos {
                directories.extend(["/Library/LaunchAgents", "/Library/LaunchDaemons"]);
            }
            files.into_iter().any(|entry| {
                catalog_entry_matches(path, entry, false, platform, pattern, recursive_delete)
            }) || directories.into_iter().any(|entry| {
                catalog_entry_matches(path, entry, true, platform, pattern, recursive_delete)
            })
        }
        Platform::Windows => windows_suffix_matches(
            path,
            &["/programdata/microsoft/windows/start menu/programs/startup"],
            true,
            pattern,
            recursive_delete,
        ),
    }
}

fn windows_suffix_matches(
    path: &str,
    entries: &[&str],
    directory: bool,
    pattern: bool,
    recursive_delete: bool,
) -> bool {
    let path = normalize_path(path, Platform::Windows);
    let Some(relative) = path
        .as_bytes()
        .get(1)
        .filter(|byte| **byte == b':')
        .map(|_| &path[2..])
    else {
        return false;
    };
    entries.iter().any(|entry| {
        catalog_entry_matches(
            relative,
            entry,
            directory,
            Platform::Windows,
            pattern,
            recursive_delete,
        )
    })
}

fn catalog_entry_matches(
    path: &str,
    entry: &str,
    directory: bool,
    platform: Platform,
    pattern: bool,
    recursive_delete: bool,
) -> bool {
    let path = normalize_path(path, platform);
    let entry = normalize_path(entry, platform);
    if if directory {
        contains(&entry, &path, platform)
    } else {
        equivalent(&entry, &path, platform)
    } {
        return true;
    }
    if recursive_delete && !equivalent(&path, &entry, platform) && contains(&path, &entry, platform)
    {
        return true;
    }
    if !pattern {
        return false;
    }
    let raw_pattern_bound = pattern_bound(&path);
    let wildcard_starts_component = raw_pattern_bound.ends_with(['/', '\\']);
    let pattern_bound = normalize_path(raw_pattern_bound, platform);
    let bound = pattern_bound.trim_end_matches('/').to_owned();
    if bound.is_empty() {
        return false;
    }
    let reaches_entry = entry.starts_with(&bound)
        && !entry.strip_prefix(&bound).is_some_and(|suffix| {
            wildcard_starts_component && suffix.trim_start_matches('/').starts_with('.')
        });
    reaches_entry || directory && contains(&entry, &bound, platform)
}

fn equivalent(left: &str, right: &str, platform: Platform) -> bool {
    normalize_path(left, platform) == normalize_path(right, platform)
}

fn normalize_path(value: &str, platform: Platform) -> String {
    let value = if platform == Platform::Windows {
        value.replace('\\', "/").to_ascii_lowercase()
    } else {
        value.to_owned()
    };
    if value == "/" {
        value
    } else {
        value.trim_end_matches('/').to_owned()
    }
}
