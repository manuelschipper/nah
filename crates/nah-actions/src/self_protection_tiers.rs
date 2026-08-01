//! Classifies nah state protection tiers; it does not emit policy verdicts.

use nah_proto::action::{FilesystemOperation, NahProtectionTier};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::Root;

use crate::paths::{contains, join, selects};

#[allow(clippy::too_many_arguments)]
pub(crate) fn classify(
    operation: FilesystemOperation,
    resolved: &AbsolutePath,
    target: &AbsolutePath,
    roots: &[Root],
    trusted_roots: &[AbsolutePath],
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    pattern: bool,
) -> Option<NahProtectionTier> {
    if operation == FilesystemOperation::Read {
        return None;
    }

    let resolved = lexically_normalized(resolved.as_str(), platform);
    let target = lexically_normalized(target.as_str(), platform);
    let paths = [resolved.as_str(), target.as_str()];
    if paths.iter().any(|path| {
        [".nah/nap.json", ".nah/nap.key", ".nah/nap.lock"]
            .iter()
            .any(|entry| same_path(&join(home.as_str(), entry, platform), path, platform))
    }) {
        return Some(NahProtectionTier::Permanent);
    }
    let owned_home_paths = [".nah"];
    let home_policy_paths = [".nah/guards"];
    let mut tier = None;
    for path in paths {
        if operation == FilesystemOperation::Delete && same_path(home.as_str(), path, platform) {
            continue;
        }
        // A pattern's bound only ever adds reachable paths, so it may raise the
        // tier but never lower it: the proposal downgrade still needs the target
        // itself to sit inside a guard directory.
        let proposal = home_policy_paths
            .iter()
            .any(|entry| contains(&join(home.as_str(), entry, platform), path, platform))
            || roots.iter().any(|root| {
                contains(
                    &join(root.path().as_str(), ".nah", platform),
                    path,
                    platform,
                )
            })
            || trusted_roots
                .iter()
                .any(|root| contains(&join(root.as_str(), ".nah", platform), path, platform));
        if proposal {
            tier = Some(NahProtectionTier::Proposal);
            continue;
        }

        let critical = owned_home_paths.iter().any(|entry| {
            protects_owned_path(
                &join(home.as_str(), entry, platform),
                path,
                platform,
                operation,
                pattern,
            )
        }) || installed_binary_paths(home, platform)
            .iter()
            .any(|entry| protects_owned_path(entry, path, platform, operation, pattern))
            || critical_paths.iter().any(|entry| {
                protects_owned_path(entry.as_str(), path, platform, operation, pattern)
            })
            || (executable_bin_path(path, platform)
                && !roots
                    .iter()
                    .any(|root| contains(root.path().as_str(), path, platform))
                && !trusted_roots
                    .iter()
                    .any(|root| contains(root.as_str(), path, platform)));
        if critical {
            return Some(NahProtectionTier::Critical);
        }
    }
    tier
}

fn lexically_normalized(path: &str, platform: Platform) -> String {
    let windows = platform == Platform::Windows;
    let unc = windows && (path.starts_with(r"\\") || path.starts_with("//"));
    let mut components = Vec::new();
    let floor = if unc {
        2
    } else if windows
        && path
            .split(['/', '\\'])
            .find(|component| !component.is_empty())
            .is_some_and(|component| component.ends_with(':'))
    {
        1
    } else {
        0
    };
    for component in path.split(|character| character == '/' || (windows && character == '\\')) {
        match component {
            "" | "." => {}
            ".." if components.len() > floor => {
                components.pop();
            }
            ".." => {}
            component => components.push(component),
        }
    }
    if windows {
        let path = components.join("\\");
        if unc { format!(r"\\{path}") } else { path }
    } else {
        format!("/{}", components.join("/"))
    }
}

fn executable_bin_path(path: &str, platform: Platform) -> bool {
    let components = normalized_components(path, platform);
    matches!(
        components.as_slice(),
        [.., directory, binary]
            if matches!(directory.as_str(), "bin" | "scripts")
                && matches!(binary.as_str(), "nah" | "nah.exe")
    )
}

fn protects_owned_path(
    owned: &str,
    path: &str,
    platform: Platform,
    operation: FilesystemOperation,
    pattern: bool,
) -> bool {
    selects(owned, path, platform, pattern)
        || operation == FilesystemOperation::Delete
            && !catastrophic_tree(path, platform)
            && contains(path, owned, platform)
}

fn catastrophic_tree(path: &str, platform: Platform) -> bool {
    let components = normalized_components(path, platform);
    components.is_empty()
        || platform == Platform::Windows
            && matches!(components.as_slice(), [drive] if drive.ends_with(':'))
        || platform != Platform::Windows
            && matches!(
                path,
                "/bin"
                    | "/boot"
                    | "/dev"
                    | "/etc"
                    | "/lib"
                    | "/lib32"
                    | "/lib64"
                    | "/root"
                    | "/run"
                    | "/sbin"
                    | "/proc"
                    | "/sys"
                    | "/usr"
                    | "/usr/bin"
                    | "/usr/sbin"
                    | "/var"
                    | "/tmp"
                    | "/Library"
                    | "/System"
                    | "/private/etc"
                    | "/private/tmp"
                    | "/private/var"
            )
}

fn normalized_components(path: &str, platform: Platform) -> Vec<String> {
    path.split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .map(|component| {
            if platform == Platform::Windows {
                component.to_ascii_lowercase()
            } else {
                component.to_owned()
            }
        })
        .collect()
}

fn installed_binary_paths(home: &AbsolutePath, platform: Platform) -> Vec<String> {
    let binary = if platform == Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    let mut paths = [".local/bin", ".cargo/bin"]
        .iter()
        .map(|directory| join(&join(home.as_str(), directory, platform), binary, platform))
        .collect::<Vec<_>>();
    if platform != Platform::Windows {
        paths.extend(
            ["/usr/local/bin/nah", "/usr/bin/nah"]
                .iter()
                .map(ToString::to_string),
        );
    }
    paths
}

fn same_path(left: &str, right: &str, platform: Platform) -> bool {
    contains(left, right, platform) && contains(right, left, platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nah_protection_tiers_are_narrow_and_cross_platform() {
        let linux_home = AbsolutePath::new(Platform::Linux, "/home/test").unwrap();
        let linux_root = Root::new(
            nah_proto::observation::RootKind::Project,
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
                classify(
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
            classify(
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
            classify(
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
            classify(
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
            classify(
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
        let windows_devin = AbsolutePath::new(
            Platform::Windows,
            r"c:\users\test\AppData\Roaming\devin\config.json",
        )
        .unwrap();
        assert_eq!(
            classify(
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
            classify(
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
            nah_proto::observation::RootKind::Project,
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
                classify(
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
            classify(
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
}
