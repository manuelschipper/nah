// UNDOCUMENTED-EFFINTERP: copied nah-state protection tiers for plan annotations.

use nah_proto::action::{FilesystemOperation, NahProtectionTier};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::Root;

use super::{contains, join, selects};

/// Classifies the nah self-protection tier a write or delete reaches, over both
/// the resolved and the effective target path.
#[allow(clippy::too_many_arguments)]
pub fn classify(
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
    let mut tier = None;
    for path in paths {
        if operation == FilesystemOperation::Delete && same_path(home.as_str(), path, platform) {
            continue;
        }
        let proposal = contains(
            &join(home.as_str(), ".nah/guards", platform),
            path,
            platform,
        ) || roots.iter().any(|root| {
            contains(
                &join(root.path().as_str(), ".nah", platform),
                path,
                platform,
            )
        }) || trusted_roots
            .iter()
            .any(|root| contains(&join(root.as_str(), ".nah", platform), path, platform));
        if proposal {
            tier = Some(NahProtectionTier::Proposal);
            continue;
        }
        let critical = protects_owned_path(
            &join(home.as_str(), ".nah", platform),
            path,
            platform,
            operation,
            pattern,
        ) || installed_binary_paths(home, platform)
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

/// Reports whether an executed program path is nah's own installed binary, which
/// the Critical tier owns.
pub fn process_is_critical(path: &str, home: &AbsolutePath, platform: Platform) -> bool {
    let path = lexically_normalized(path, platform);
    installed_binary_paths(home, platform)
        .iter()
        .any(|candidate| same_path(candidate, &path, platform))
        || executable_bin_path(&path, platform)
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
    for component in path.split(|character| character == '/' || windows && character == '\\') {
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
    if platform == Platform::Windows {
        paths.push(join(
            &join(home.as_str(), "AppData/Local/Programs/nah", platform),
            binary,
            platform,
        ));
    } else {
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
