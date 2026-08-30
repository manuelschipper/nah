// UNDOCUMENTED-EFFINTERP: copied sensitive-path catalogs for plan annotations.

use nah_proto::action::Sensitivity;
use nah_proto::ctx::{AbsolutePath, Platform};

use super::{contains, selects};

/// Classifies how sensitive a target path is, reading both the requested word
/// (a concrete path or a glob pattern) and the resolved target.
pub fn sensitivity(
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
    let basename = basename(path, platform);
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
    relative_home_path(path, home.as_str(), platform)
        .map(|relative| relative.replace('\\', "/"))
        .map(|relative| {
            if platform == Platform::Windows {
                relative.to_ascii_lowercase()
            } else {
                relative
            }
        })
        .is_some_and(|relative| relative == ".gnupg")
}

fn container_runtime_auth(path: &str, platform: Platform) -> bool {
    platform != Platform::Windows
        && path
            .strip_prefix("/run/user/")
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
    let basename = basename(path, platform);
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
    if prefix != format!("{home_parent}/") {
        return false;
    }
    contains(&suffix, tail.trim_start_matches('/'), platform)
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
}
