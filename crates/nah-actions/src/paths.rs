//! Classifies lexical path scope and sensitivity; it does not canonicalize host paths.

use nah_proto::action::{
    FilesystemOperation, HostIntegrityClass, PathScope, Sensitivity, pattern_bound,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::Root;

pub(crate) fn path_scope(
    target: &AbsolutePath,
    roots: &[Root],
    home: &AbsolutePath,
    platform: Platform,
) -> PathScope {
    if let Some(root) = roots
        .iter()
        .filter(|root| contains(root.path().as_str(), target.as_str(), platform))
        .max_by_key(|root| root.path().as_str().len())
    {
        return PathScope::Project {
            root: root.path().clone(),
        };
    }
    if contains(home.as_str(), target.as_str(), platform) {
        return PathScope::Home;
    }
    if ["/dev", "/etc", "/lib", "/run", "/var"]
        .iter()
        .any(|root| contains(root, target.as_str(), platform))
    {
        PathScope::System
    } else {
        PathScope::OutsideProject
    }
}

pub(crate) fn sensitivity(
    requested: &str,
    target: &AbsolutePath,
    home: &AbsolutePath,
    platform: Platform,
    pattern: bool,
) -> Sensitivity {
    if has_component(requested, ".git", platform)
        || has_component(target.as_str(), ".git", platform)
    {
        return Sensitivity::OtherSensitive;
    }
    const KEY_HOME_PATHS: &[&str] = &[
        ".gnupg/private-keys-v1.d",
        ".gnupg/openpgp-revocs.d",
        ".gnupg/secring.gpg",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".cargo/credentials",
        ".cargo/credentials.toml",
        ".config/pypoetry/auth.toml",
        ".gem/credentials",
        ".aws/credentials",
        ".aws/cli/cache",
        ".aws/sso/cache",
        ".azure/accessTokens.json",
        ".azure/msal_token_cache.bin",
        ".azure/msal_token_cache.json",
        ".config/gcloud/access_tokens.db",
        ".config/gcloud/application_default_credentials.json",
        ".config/gcloud/credentials.db",
        ".config/gcloud/legacy_credentials",
        ".config/gh/hosts.yml",
        ".config/glab-cli/config.yml",
        ".config/containers/auth.json",
        ".docker/config.json",
        ".kube/config",
        "Library/Keychains",
        ".terraform.d/credentials.tfrc.json",
        "AppData/Roaming/gcloud/access_tokens.db",
        "AppData/Roaming/gcloud/application_default_credentials.json",
        "AppData/Roaming/gcloud/credentials.db",
        "AppData/Roaming/gcloud/legacy_credentials",
        "AppData/Roaming/GitHub CLI/hosts.yml",
        "AppData/Local/glab-cli/config.yml",
        "AppData/Roaming/glab-cli/config.yml",
        "AppData/Roaming/pypoetry/auth.toml",
    ];
    const OTHER_HOME_PATHS: &[&str] = &[
        ".gnupg",
        ".cargo",
        ".gem",
        ".aws",
        ".azure",
        ".config/gcloud",
        ".config/gh",
        ".config/glab-cli",
        ".config/containers",
        ".docker",
        ".kube",
        ".config/az",
        ".config/heroku",
        ".terraform.d/credentials.tfrc.json",
        ".terraformrc",
        "AppData/Roaming/gcloud",
        "AppData/Roaming/GitHub CLI",
        ".nah",
        ".config/systemd/user",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".pi/agent/settings.json",
        ".bashrc",
        ".bash_profile",
        ".bash_aliases",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
        ".bashrc.d",
        ".zshrc.d",
    ];
    const OTHER_SYSTEM_PATHS: &[&str] = &[
        "/etc/docker",
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/etc/systemd",
        "/lib/systemd",
    ];

    if ssh_credential_path(requested, home, platform)
        || ssh_credential_path(target.as_str(), home, platform)
        || gnupg_credential_path(requested, home, platform)
        || gnupg_credential_path(target.as_str(), home, platform)
        || matches_home_path(requested, home, KEY_HOME_PATHS, platform, pattern)
        || matches_home_path(target.as_str(), home, KEY_HOME_PATHS, platform, pattern)
        || container_runtime_auth(requested, platform)
        || container_runtime_auth(target.as_str(), platform)
        || credential_basename(requested, platform, pattern)
        || credential_basename(target.as_str(), platform, pattern)
        || [requested, target.as_str()].iter().any(|path| {
            [
                "/etc/shadow",
                "/private/etc/shadow",
                "/etc/kubernetes/admin.conf",
                "/etc/rancher/k3s/k3s.yaml",
                "/Library/Keychains",
            ]
            .iter()
            .any(|entry| selects(entry, path, platform, pattern))
        })
    {
        return Sensitivity::CredentialSecret;
    }
    if environment_basename(requested, platform, pattern)
        || environment_basename(target.as_str(), platform, pattern)
    {
        return Sensitivity::EnvironmentSecret;
    }
    if configuration_basename(requested, platform, pattern)
        || configuration_basename(target.as_str(), platform, pattern)
        || credential_material_basename(requested, platform, pattern)
        || credential_material_basename(target.as_str(), platform, pattern)
        || matches_home_path(requested, home, OTHER_HOME_PATHS, platform, pattern)
        || matches_home_path(target.as_str(), home, OTHER_HOME_PATHS, platform, pattern)
        || OTHER_SYSTEM_PATHS.iter().any(|entry| {
            selects(entry, requested, platform, pattern)
                || selects(entry, target.as_str(), platform, pattern)
        })
    {
        return Sensitivity::OtherSensitive;
    }
    Sensitivity::None
}

pub(crate) fn host_integrity_class(
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
    for entry in [".ssh/authorized_keys"] {
        if catalog_entry_matches(
            path,
            &join(home.as_str(), entry, platform),
            false,
            platform,
            pattern,
            recursive_delete,
        ) {
            return true;
        }
    }
    for entry in [".ssh/authorized_keys.d"] {
        if catalog_entry_matches(
            path,
            &join(home.as_str(), entry, platform),
            true,
            platform,
            pattern,
            recursive_delete,
        ) {
            return true;
        }
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
    let home_directories = [".config/fish/conf.d"];
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
        || home_directories.into_iter().any(|entry| {
            catalog_entry_matches(
                path,
                &join(home.as_str(), entry, platform),
                true,
                platform,
                pattern,
                recursive_delete,
            )
        })
}

fn startup_persistence_path(
    path: &str,
    home: &AbsolutePath,
    platform: Platform,
    pattern: bool,
    recursive_delete: bool,
) -> bool {
    let home_files = [".ssh/rc"];
    let mut home_directories = vec![".config/autostart", ".config/systemd/user"];
    if platform == Platform::Macos {
        home_directories.push("Library/LaunchAgents");
    } else if platform == Platform::Windows {
        home_directories.push("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    }
    if home_files.into_iter().any(|entry| {
        catalog_entry_matches(
            path,
            &join(home.as_str(), entry, platform),
            false,
            platform,
            pattern,
            recursive_delete,
        )
    }) || home_directories.into_iter().any(|entry| {
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

/// Names that carry a private key or a credential wherever the file lives, the
/// way `.env` already does. A key committed into a project is the common
/// accident, so anchoring these to `$HOME` would leave it unclassified.
///
/// Only names that identify the secret itself belong here, because a match is a
/// block. A container extension such as `.pem` names an encoding, not a secret —
/// `cert.pem` and `key.pem` look identical — so those go to
/// `credential_material_basename`, which keeps them out of `Sensitivity::None`
/// without blocking a plain read.
fn credential_basename(path: &str, platform: Platform, pattern: bool) -> bool {
    let basename = basename(path, platform);
    [
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".netrc",
        ".git-credentials",
    ]
    .iter()
    .any(|entry| selects(entry, &basename, platform, pattern))
}

/// Names that usually hold key or credential material but are common enough in
/// ordinary repositories that a block would be noisy. Classifying them as
/// sensitive lets `secrets-exfil` see the read, while a plain local read still
/// delegates.
///
/// The suffix list stays literal: a pattern bound truncates before the
/// extension it would need to match, so widening it there would invent a
/// narrowing that does not exist.
fn credential_material_basename(path: &str, platform: Platform, pattern: bool) -> bool {
    let basename = basename(path, platform);
    ["credentials", "kubeconfig", "terraform.tfstate"]
        .iter()
        .any(|entry| selects(entry, &basename, platform, pattern))
        || [".key", ".pem", ".p12", ".pfx"]
            .iter()
            .any(|suffix| basename.ends_with(suffix))
        || basename == "config.json" && has_component(path, ".docker", platform)
}

fn basename(path: &str, platform: Platform) -> String {
    if platform == Platform::Windows {
        path.rsplit(['/', '\\'])
            .next()
            .unwrap_or(path)
            .to_ascii_lowercase()
    } else {
        path.rsplit('/').next().unwrap_or(path).to_owned()
    }
}

fn configuration_basename(path: &str, platform: Platform, pattern: bool) -> bool {
    let basename = if platform == Platform::Windows {
        path.rsplit(['/', '\\'])
            .next()
            .unwrap_or(path)
            .to_ascii_lowercase()
    } else {
        path.rsplit('/').next().unwrap_or(path).to_owned()
    };
    [".npmrc", "terraform.tfvars"]
        .iter()
        .any(|entry| selects(entry, &basename, platform, pattern))
}

fn matches_home_path(
    path: &str,
    home: &AbsolutePath,
    entries: &[&str],
    platform: Platform,
    pattern: bool,
) -> bool {
    let home_relative = relative_home_path(path, home.as_str(), platform);
    entries.iter().any(|entry| {
        home_relative
            .as_deref()
            .is_some_and(|relative| selects(entry, relative, platform, pattern))
            || matches_home_glob(path, home.as_str(), entry, platform)
    })
}

fn ssh_credential_path(path: &str, home: &AbsolutePath, platform: Platform) -> bool {
    let Some(relative) = relative_home_path(path, home.as_str(), platform) else {
        return false;
    };
    let relative = relative.replace('\\', "/");
    let relative = if platform == Platform::Windows {
        relative.to_ascii_lowercase()
    } else {
        relative
    };
    if relative.trim_end_matches('/') == ".ssh" {
        return true;
    }
    let Some(ssh_path) = relative.strip_prefix(".ssh/") else {
        return false;
    };
    let name = ssh_path.rsplit('/').next().unwrap_or(ssh_path);
    if name.ends_with(".pub") || name.contains(".pub.") {
        return false;
    }
    ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"]
        .iter()
        .any(|private| name == *private || name.starts_with(&format!("{private}.")))
}

fn gnupg_credential_path(path: &str, home: &AbsolutePath, platform: Platform) -> bool {
    let Some(relative) = relative_home_path(path, home.as_str(), platform) else {
        return false;
    };
    let relative = relative.replace('\\', "/");
    let relative = if platform == Platform::Windows {
        relative.to_ascii_lowercase()
    } else {
        relative
    };
    relative == ".gnupg"
}

fn container_runtime_auth(path: &str, platform: Platform) -> bool {
    if platform == Platform::Windows {
        return false;
    }
    path.strip_prefix("/run/user/")
        .and_then(|path| path.split_once('/'))
        .is_some_and(|(user, relative)| !user.is_empty() && relative == "containers/auth.json")
}

fn relative_home_path(path: &str, home: &str, platform: Platform) -> Option<String> {
    let normalize = |value: &str| {
        let value = value.replace('\\', "/");
        if platform == Platform::Windows {
            value.to_ascii_lowercase()
        } else {
            value
        }
    };
    let path = normalize(path);
    let home = normalize(home).trim_end_matches('/').to_owned();
    if let Some(relative) = path.strip_prefix("~/") {
        return Some(relative.to_owned());
    }
    if let Some(relative) = path
        .strip_prefix(&home)
        .and_then(|relative| relative.strip_prefix('/'))
    {
        return Some(relative.to_owned());
    }
    if let Some(relative) = path.strip_prefix("/root/") {
        return Some(relative.to_owned());
    }
    for prefix in ["/home/", "/var/lib/", "/Users/", "/users/"] {
        if let Some(path) = path.strip_prefix(prefix)
            && let Some((user, relative)) = path.split_once('/')
            && !user.is_empty()
            && !relative.is_empty()
        {
            return Some(relative.to_owned());
        }
    }
    if platform == Platform::Windows
        && let Some((_, users)) = path.split_once(":/users/")
        && let Some((user, relative)) = users.split_once('/')
        && !user.is_empty()
        && !relative.is_empty()
    {
        return Some(relative.to_owned());
    }
    None
}

fn environment_basename(path: &str, platform: Platform, pattern: bool) -> bool {
    let basename = if platform == Platform::Windows {
        path.rsplit(['/', '\\']).next().unwrap_or(path)
    } else {
        path.rsplit('/').next().unwrap_or(path)
    };
    let basename = if platform == Platform::Windows {
        basename.to_ascii_lowercase()
    } else {
        basename.to_owned()
    };
    let dotted_environment = basename.starts_with(".env.")
        && ![".example", ".sample", ".template", ".dist"]
            .iter()
            .any(|suffix| basename.ends_with(suffix));
    dotted_environment
        || [".env", ".pypirc", ".pgpass", ".boto"]
            .iter()
            .any(|entry| selects(entry, &basename, platform, pattern))
}

fn has_component(path: &str, expected: &str, platform: Platform) -> bool {
    if platform == Platform::Windows {
        path.split(['/', '\\'])
            .any(|component| component.eq_ignore_ascii_case(expected))
    } else {
        path.split('/').any(|component| component == expected)
    }
}

pub(crate) fn literal_relative_path(pattern: &str, platform: Platform) -> bool {
    !pattern.is_empty()
        && !pattern.contains('\\')
        && AbsolutePath::new(platform, pattern).is_err()
        && pattern.split('/').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' ')
                })
        })
}

pub(crate) fn join(base: &str, relative: &str, platform: Platform) -> String {
    let (base, relative, separator) = if platform == Platform::Windows {
        (
            base.trim_end_matches(['/', '\\']),
            relative.replace('/', "\\"),
            '\\',
        )
    } else {
        (base.trim_end_matches('/'), relative.to_owned(), '/')
    };
    format!("{base}{separator}{relative}")
}

pub(crate) fn resolve_from_cwd(
    cwd: Option<&str>,
    pwd: Option<&str>,
    target: &str,
    home: &str,
    platform: Platform,
    expand_tilde: bool,
) -> Option<String> {
    if expand_tilde && target == "~+" {
        return pwd.map(str::to_owned);
    }
    if expand_tilde
        && let Some(relative) = target
            .strip_prefix("~+/")
            .or_else(|| target.strip_prefix("~+\\"))
    {
        return pwd.map(|pwd| join(pwd, relative, platform));
    }
    if expand_tilde && target == "~" {
        return Some(home.to_owned());
    }
    if expand_tilde
        && let Some(relative) = target
            .strip_prefix("~/")
            .or_else(|| target.strip_prefix("~\\"))
    {
        return Some(join(home, relative, platform));
    }
    if expand_tilde && target.starts_with('~') {
        return same_user_home(target, home, platform);
    }
    if target == "." {
        return cwd.map(str::to_owned);
    }
    if target == "./~" {
        return cwd.map(|cwd| join(cwd, "~", platform));
    }
    if let Some(relative) = target
        .strip_prefix("./~/")
        .or_else(|| target.strip_prefix("./~\\"))
    {
        return cwd.map(|cwd| join(cwd, &format!("~/{relative}"), platform));
    }
    if let Some(relative) = target.strip_prefix("./").or_else(|| {
        (platform == Platform::Windows)
            .then(|| target.strip_prefix(".\\"))
            .flatten()
    }) {
        return cwd.map(|cwd| join(cwd, relative, platform));
    }
    if AbsolutePath::new(platform, target).is_ok() {
        Some(target.to_owned())
    } else {
        cwd.map(|cwd| join(cwd, target, platform))
    }
}

pub(crate) fn cwd_relative(path: &str, platform: Platform) -> bool {
    !path.starts_with('~') && AbsolutePath::new(platform, path).is_err()
}

fn same_user_home(target: &str, home: &str, platform: Platform) -> Option<String> {
    if platform == Platform::Windows {
        return None;
    }
    let target = target.strip_prefix('~')?;
    let (user, relative) = target
        .split_once('/')
        .map_or((target, None), |(user, relative)| (user, Some(relative)));
    let current_user = match home {
        "/root" | "/var/root" => "root",
        home => home
            .strip_prefix("/home/")
            .or_else(|| home.strip_prefix("/Users/"))
            .filter(|user| !user.is_empty() && !user.contains('/'))?,
    };
    if user.is_empty() || user != current_user {
        return None;
    }
    Some(relative.map_or_else(
        || home.to_owned(),
        |relative| join(home, relative, platform),
    ))
}

pub(crate) fn contains(base: &str, path: &str, platform: Platform) -> bool {
    let normalize = |value: &str| {
        if platform == Platform::Windows {
            value
                .trim_end_matches(['/', '\\'])
                .replace('\\', "/")
                .to_ascii_lowercase()
        } else {
            value.trim_end_matches('/').to_owned()
        }
    };
    let base = normalize(base);
    let path = normalize(path);
    path == base
        || path
            .strip_prefix(&base)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// An expanded pattern selects an unknown path bounded by its literal prefix, so
/// a known path that starts with the bound is still in reach.
///
/// `<directory>/*` and `<directory>/.*` narrow no name: they select every entry
/// of a directory, which the whole-directory rules such as `fs-home` already
/// answer, and reading them as a bound would flag every ordinary glob.
pub(crate) fn selects(known: &str, path: &str, platform: Platform, pattern: bool) -> bool {
    if contains(known, path, platform) {
        return true;
    }
    let normalize = |value: &str| {
        if platform == Platform::Windows {
            value.replace('\\', "/").to_ascii_lowercase()
        } else {
            value.to_owned()
        }
    };
    let bound = normalize(pattern_bound(path));
    let name = bound
        .rsplit_once('/')
        .map_or(bound.as_str(), |(_, name)| name);
    pattern && !matches!(name, "" | ".") && normalize(known).starts_with(&bound)
}

fn matches_home_glob(path: &str, home: &str, suffix: &str, platform: Platform) -> bool {
    let normalize = |value: &str| {
        let value = value.replace('\\', "/");
        if platform == Platform::Windows {
            value.to_ascii_lowercase()
        } else {
            value
        }
    };
    let path = normalize(path);
    let home = normalize(home);
    let suffix = normalize(suffix);
    let Some((home_parent, _)) = home.rsplit_once('/') else {
        return false;
    };
    let Some((prefix, tail)) = path.split_once('*') else {
        return false;
    };
    let expected_prefix = format!("{home_parent}/");
    if prefix != expected_prefix {
        return false;
    }
    let tail = tail.trim_start_matches('/');
    contains(&suffix, tail, platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_sensitive_basenames_are_case_insensitive() {
        let path = r"C:\repo\.ENV";
        assert!(
            environment_basename(path, Platform::Windows, false),
            "{path}"
        );
        for path in [
            r"C:\repo\.ENV.EXAMPLE",
            r"C:\repo\.ENV.SAMPLE",
            r"C:\repo\.ENVRC",
            r"C:\repo\.ENVIRONMENT",
            r"C:\repo\.NPMRC",
            r"C:\repo\Terraform.Tfvars",
        ] {
            assert!(
                !environment_basename(path, Platform::Windows, false),
                "{path}"
            );
        }
    }

    #[test]
    fn expanded_patterns_reach_sensitive_basenames_they_bound() {
        for (path, pattern, expected) in [
            (".env?", true, true),
            (".env?", false, false),
            (".npmr?", true, true),
            // A pattern that starts a fresh component narrows no name.
            ("src/*.rs", true, false),
            ("*.log", true, false),
            (".*", true, false),
        ] {
            assert_eq!(
                environment_basename(path, Platform::Linux, pattern)
                    || configuration_basename(path, Platform::Linux, pattern),
                expected,
                "{path}"
            );
        }
    }

    #[test]
    fn git_metadata_is_sensitive_on_each_platform() {
        assert!(has_component("/repo/.git/config", ".git", Platform::Linux));
        assert!(has_component(
            r"C:\repo\.GIT\config",
            ".git",
            Platform::Windows
        ));
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
}
