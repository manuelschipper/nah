//! Classifies lexical path scope and sensitivity; it does not canonicalize host paths.

use nah_proto::action::{PathScope, Sensitivity, pattern_bound};
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
/// sensitive lets `exfil-pipe` see the read, while a plain local read still
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
}
