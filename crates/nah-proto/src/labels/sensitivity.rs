//! Classifies how sensitive a path is; it does not canonicalize host paths.

use super::lexical_path::fold_path_spelling;
use super::{Sensitivity, lexically_contains, selects_known_path};
use crate::ctx::{AbsolutePath, Platform};

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
    const KEY_MATERIAL_HOME_PATHS: &[&str] = &[
        ".gnupg/private-keys-v1.d",
        ".gnupg/openpgp-revocs.d",
        ".gnupg/secring.gpg",
        "Library/Keychains",
    ];
    const KEY_HOME_PATHS: &[&str] = &[
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
        || matches_home_path(requested, home, KEY_MATERIAL_HOME_PATHS, platform, pattern)
        || matches_home_path(
            target.as_str(),
            home,
            KEY_MATERIAL_HOME_PATHS,
            platform,
            pattern,
        )
        || private_key_basename(requested, platform, pattern)
        || private_key_basename(target.as_str(), platform, pattern)
        || [requested, target.as_str()]
            .iter()
            .any(|path| selects_known_path("/Library/Keychains", path, platform, pattern))
    {
        return Sensitivity::KeyMaterial;
    }
    if matches_home_path(requested, home, KEY_HOME_PATHS, platform, pattern)
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
            ]
            .iter()
            .any(|entry| selects_known_path(entry, path, platform, pattern))
        })
    {
        return Sensitivity::CredentialSecret;
    }
    if environment_basename(requested, platform, pattern)
        || environment_basename(target.as_str(), platform, pattern)
    {
        return Sensitivity::EnvironmentSecret;
    }
    // A bounded pattern covers the descendants it names literally. An extglob
    // or brace group (`certs/@(server.key)`, `~/{id_rsa,config}`) enumerates
    // exactly those names, so a credential among its alternatives makes the
    // read cover a credential even though the directory that bounds it is not
    // itself sensitive. Only the enumerated literals widen this; an open `*`
    // names no descendant here and is left to the observed entries.
    if pattern {
        for expansion in pattern_alternatives(requested) {
            if let Ok(selected) = AbsolutePath::new(platform, &expansion) {
                let widened = sensitivity(&expansion, &selected, home, platform, false);
                if widened != Sensitivity::None {
                    return widened;
                }
            }
        }
    }
    if configuration_basename(requested, platform, pattern)
        || configuration_basename(target.as_str(), platform, pattern)
        || credential_material_basename(requested, platform, pattern)
        || credential_material_basename(target.as_str(), platform, pattern)
        || matches_home_path(requested, home, OTHER_HOME_PATHS, platform, pattern)
        || matches_home_path(target.as_str(), home, OTHER_HOME_PATHS, platform, pattern)
        || OTHER_SYSTEM_PATHS.iter().any(|entry| {
            selects_known_path(entry, requested, platform, pattern)
                || selects_known_path(entry, target.as_str(), platform, pattern)
        })
    {
        return Sensitivity::OtherSensitive;
    }
    Sensitivity::None
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
    [".netrc", ".git-credentials"]
        .iter()
        .any(|entry| selects_known_path(entry, &basename, platform, pattern))
}

/// The default SSH private-key names, wherever the file lives. Like
/// `credential_basename`, only names that identify the secret itself.
fn private_key_basename(path: &str, platform: Platform, pattern: bool) -> bool {
    let basename = basename(path, platform);
    ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
        .iter()
        .any(|entry| selects_known_path(entry, &basename, platform, pattern))
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
        .any(|entry| selects_known_path(entry, &basename, platform, pattern))
        || [".key", ".pem", ".p12", ".pfx"]
            .iter()
            .any(|suffix| basename.ends_with(suffix))
        || basename == "config.json" && has_component(path, ".docker", platform)
}

fn basename(path: &str, platform: Platform) -> String {
    let path = fold_path_spelling(path, platform);
    path.rsplit('/').next().unwrap_or(&path).to_owned()
}

fn configuration_basename(path: &str, platform: Platform, pattern: bool) -> bool {
    let basename = basename(path, platform);
    [".npmrc", "terraform.tfvars"]
        .iter()
        .any(|entry| selects_known_path(entry, &basename, platform, pattern))
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
            .is_some_and(|relative| selects_known_path(entry, relative, platform, pattern))
            || matches_home_glob(path, home.as_str(), entry, platform)
    })
}

fn ssh_credential_path(path: &str, home: &AbsolutePath, platform: Platform) -> bool {
    let Some(relative) = relative_home_path(path, home.as_str(), platform) else {
        return false;
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

/// Like `lexical_path::fold_path_spelling`, but turns `\` into `/` on every platform, so a
/// POSIX spelling such as `/home/me/.ssh\id_rsa` still reaches the home
/// credential rules. `fold` keeps that backslash as part of a name there, and
/// the credential guards would stop matching it.
fn fold_home_spelling(path: &str, platform: Platform) -> String {
    let path = path.replace('\\', "/");
    if platform == Platform::Windows {
        path.to_ascii_lowercase()
    } else {
        path
    }
}

/// The part of `path` under a home directory, in `fold_home_spelling` form.
fn relative_home_path(path: &str, home: &str, platform: Platform) -> Option<String> {
    let path = fold_home_spelling(path, platform);
    let home = fold_home_spelling(home, platform)
        .trim_end_matches('/')
        .to_owned();
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
            .any(|entry| selects_known_path(entry, &basename, platform, pattern))
}

/// Expands the enumerated alternatives of a bounded pattern's final component.
/// An extglob group (`@(a|b)`, `+(a)`, `?(a)`, `*(a)`) and a brace list
/// (`{a,b}`) name exactly their alternatives, so each yields a concrete path to
/// classify. A negation group (`!(...)`) names the complement and is skipped, as
/// is a component with an open wildcard, which enumerates no literal descendant.
fn pattern_alternatives(requested: &str) -> Vec<String> {
    let (parent, last) = requested
        .rsplit_once(['/', '\\'])
        .map_or(("", requested), |(parent, last)| (parent, last));
    let separator = if requested.contains('\\') && !requested.contains('/') {
        '\\'
    } else {
        '/'
    };
    let alternatives = if let Some(rest) = last
        .strip_prefix("@(")
        .or_else(|| last.strip_prefix("+("))
        .or_else(|| last.strip_prefix("?("))
        .or_else(|| last.strip_prefix("*("))
        && let Some(inner) = rest.strip_suffix(')')
    {
        inner.split('|').collect::<Vec<_>>()
    } else if let Some(inner) = last
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    {
        inner.split(',').collect::<Vec<_>>()
    } else {
        return Vec::new();
    };
    alternatives
        .into_iter()
        .filter(|alternative| {
            !alternative.is_empty()
                && !alternative
                    .bytes()
                    .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b'(' | b'{'))
        })
        .map(|alternative| {
            if parent.is_empty() {
                alternative.to_owned()
            } else {
                format!("{parent}{separator}{alternative}")
            }
        })
        .collect()
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
    if !path.contains('*') {
        return false;
    }
    let path = fold_home_spelling(path, platform);
    let home = fold_home_spelling(home, platform);
    let suffix = fold_home_spelling(suffix, platform);
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
    lexically_contains(&suffix, tail, platform)
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
