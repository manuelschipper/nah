//! Classifies how sensitive a path is; it does not canonicalize host paths.

use super::git_config::is_git_config_path;
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
    // A repository's own configuration is a secret only for the credentials
    // it holds, which its path cannot say: the bridge labels it from its
    // observed content. Reached under another name it stays Git metadata.
    let git_config = !pattern
        && is_git_config_path(requested, platform)
        && (requested == target.as_str() || is_git_config_path(target.as_str(), platform));
    if !git_config
        && (has_component(requested, ".git", platform)
            || has_component(target.as_str(), ".git", platform))
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

    // Whether `check` holds for the requested spelling or the target, each
    // split into its parts once. Most callers name one path both ways, which
    // is checked once.
    let spellings = [
        Some(requested),
        (requested != target.as_str()).then(|| target.as_str()),
    ]
    .into_iter()
    .flatten()
    .map(|path| Spelling {
        path,
        home_relative: relative_home_path(path, home.as_str(), platform),
        basename: basename(path, platform),
    })
    .collect::<Vec<_>>();
    let either = |check: &dyn Fn(&Spelling<'_>) -> bool| spellings.iter().any(check);
    if either(&|spelling| {
        let Spelling {
            path,
            home_relative,
            basename,
        } = spelling;
        let home_relative = home_relative.as_deref();
        ssh_credential_path(home_relative)
            || gnupg_credential_path(home_relative)
            || matches_home_path(
                path,
                home_relative,
                home,
                KEY_MATERIAL_HOME_PATHS,
                platform,
                pattern,
            )
            || private_key_basename(basename, platform, pattern)
            || selects_known_path("/Library/Keychains", path, platform, pattern)
    }) {
        return Sensitivity::KeyMaterial;
    }
    if either(&|spelling| {
        let Spelling {
            path,
            home_relative,
            basename,
        } = spelling;
        matches_home_path(
            path,
            home_relative.as_deref(),
            home,
            KEY_HOME_PATHS,
            platform,
            pattern,
        ) || container_runtime_auth(path, platform)
            || credential_basename(basename, platform, pattern)
            || [
                "/etc/shadow",
                "/private/etc/shadow",
                "/etc/kubernetes/admin.conf",
                "/etc/rancher/k3s/k3s.yaml",
            ]
            .iter()
            .any(|entry| selects_known_path(entry, path, platform, pattern))
    }) {
        return Sensitivity::CredentialSecret;
    }
    if either(&|spelling| environment_basename(&spelling.basename, platform, pattern)) {
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
    if either(&|spelling| {
        let Spelling {
            path,
            home_relative,
            basename,
        } = spelling;
        configuration_basename(basename, platform, pattern)
            || credential_material_basename(path, basename, platform, pattern)
            || matches_home_path(
                path,
                home_relative.as_deref(),
                home,
                OTHER_HOME_PATHS,
                platform,
                pattern,
            )
            || OTHER_SYSTEM_PATHS
                .iter()
                .any(|entry| selects_known_path(entry, path, platform, pattern))
    }) {
        return Sensitivity::OtherSensitive;
    }
    Sensitivity::None
}

/// One spelling `sensitivity` classifies, with the parts its rules read.
struct Spelling<'a> {
    path: &'a str,
    home_relative: Option<String>,
    basename: String,
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
fn credential_basename(basename: &str, platform: Platform, pattern: bool) -> bool {
    [".netrc", ".git-credentials"]
        .iter()
        .any(|entry| selects_known_path(entry, basename, platform, pattern))
}

/// The default SSH private-key names, wherever the file lives. Like
/// `credential_basename`, only names that identify the secret itself.
fn private_key_basename(basename: &str, platform: Platform, pattern: bool) -> bool {
    ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
        .iter()
        .any(|entry| selects_known_path(entry, basename, platform, pattern))
}

/// Names that usually hold key or credential material but are common enough in
/// ordinary repositories that a block would be noisy. Classifying them as
/// sensitive lets `secrets-exfil` see the read, while a plain local read still
/// delegates.
///
/// The suffix list stays literal: a pattern bound truncates before the
/// extension it would need to match, so widening it there would invent a
/// narrowing that does not exist.
fn credential_material_basename(
    path: &str,
    basename: &str,
    platform: Platform,
    pattern: bool,
) -> bool {
    ["credentials", "kubeconfig", "terraform.tfstate"]
        .iter()
        .any(|entry| selects_known_path(entry, basename, platform, pattern))
        || [".key", ".pem", ".p12", ".pfx"]
            .iter()
            .any(|suffix| basename.ends_with(suffix))
        || basename == "config.json" && has_component(path, ".docker", platform)
}

fn basename(path: &str, platform: Platform) -> String {
    let path = fold_path_spelling(path, platform);
    path.rsplit('/').next().unwrap_or(&path).to_owned()
}

fn configuration_basename(basename: &str, platform: Platform, pattern: bool) -> bool {
    [".npmrc", "terraform.tfvars"]
        .iter()
        .any(|entry| selects_known_path(entry, basename, platform, pattern))
}

/// Whether `path`, which lies at `home_relative` under a home directory,
/// selects one of the home `entries`.
fn matches_home_path(
    path: &str,
    home_relative: Option<&str>,
    home: &AbsolutePath,
    entries: &[&str],
    platform: Platform,
    pattern: bool,
) -> bool {
    let glob = path.contains('*');
    entries.iter().any(|entry| {
        home_relative.is_some_and(|relative| selects_known_path(entry, relative, platform, pattern))
            || glob && matches_home_glob(path, home.as_str(), entry, platform)
    })
}

/// Whether a path at `home_relative` under a home directory is an SSH private
/// key or the directory holding them.
fn ssh_credential_path(home_relative: Option<&str>) -> bool {
    let Some(relative) = home_relative else {
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
    // A default key name alone, or with a suffix naming a backup, account or
    // host (`id_ed25519.old`, `id_ed25519_github`, `id_rsa-work`).
    ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"]
        .iter()
        .any(|private| {
            name.strip_prefix(private).is_some_and(|rest| {
                rest.is_empty() || rest.len() > 1 && rest.starts_with(['.', '_', '-'])
            })
        })
}

fn gnupg_credential_path(home_relative: Option<&str>) -> bool {
    home_relative == Some(".gnupg")
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

/// Whether a concrete file name carries environment credentials.
pub fn environment_file(path: &str, platform: Platform) -> bool {
    environment_basename(&basename(path, platform), platform, false)
}

fn environment_basename(basename: &str, platform: Platform, pattern: bool) -> bool {
    let dotted_environment = basename.starts_with(".env.")
        && ![".example", ".sample", ".template", ".dist"]
            .iter()
            .any(|suffix| basename.ends_with(suffix));
    dotted_environment
        || [".env", ".pypirc", ".pgpass", ".boto"]
            .iter()
            .any(|entry| selects_known_path(entry, basename, platform, pattern))
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
            environment_basename(&basename(path, Platform::Windows), Platform::Windows, false),
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
                !environment_basename(&basename(path, Platform::Windows), Platform::Windows, false),
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
                environment_basename(&basename(path, Platform::Linux), Platform::Linux, pattern)
                    || configuration_basename(
                        &basename(path, Platform::Linux),
                        Platform::Linux,
                        pattern
                    ),
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
