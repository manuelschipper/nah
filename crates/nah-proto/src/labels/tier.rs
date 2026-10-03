//! Classifies nah state protection tiers; it does not emit policy verdicts.

use super::lexical_path::{
    fold_path_spelling, installed_binary_paths, join_lexical_path, lexically_contains,
    lexically_normalized, same_path,
};
use super::system_tree::SYSTEM_TREES;
use super::{NahProtectionTier, selects_known_path};
use crate::action::FilesystemOperation;
use crate::ctx::{AbsolutePath, Platform};
use crate::observation::Root;

/// Classifies the Nah protection tier a filesystem mutation of `resolved` or
/// `target` reaches; reads are never protected. Whole-container evidence means
/// removal/replacement or recursive metadata mutation, not merely a recursive
/// write whose selected contents are unknown.
#[allow(clippy::too_many_arguments)]
pub fn nah_protection_tier(
    operation: FilesystemOperation,
    resolved: &AbsolutePath,
    target: &AbsolutePath,
    roots: &[Root],
    trusted_roots: &[AbsolutePath],
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    pattern: bool,
    whole_container: bool,
) -> Option<NahProtectionTier> {
    if operation == FilesystemOperation::Read {
        return None;
    }

    let resolved = lexically_normalized(resolved.as_str(), platform);
    let target = lexically_normalized(target.as_str(), platform);
    let paths = [resolved.as_str(), target.as_str()];
    // A pattern reaches a nap file when the file is one of its expansions,
    // so `~/.nah/*` takes the nap state while `~/.nah/*/**` does not.
    let expands_to = |selection: &str, file: &str| {
        effinterp_proto::glob_match(
            &fold_path_spelling(selection, platform),
            &fold_path_spelling(file, platform),
        ) == Ok(true)
    };
    if paths.iter().any(|path| {
        (!pattern
            && whole_container
            && same_path(
                &join_lexical_path(home.as_str(), ".nah", platform),
                path,
                platform,
            ))
            || [".nah/nap.json", ".nah/nap.key", ".nah/nap.lock"]
                .iter()
                .map(|entry| join_lexical_path(home.as_str(), entry, platform))
                .any(|file| same_path(&file, path, platform) || pattern && expands_to(path, &file))
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
        let proposal = home_policy_paths.iter().any(|entry| {
            lexically_contains(
                &join_lexical_path(home.as_str(), entry, platform),
                path,
                platform,
            )
        }) || roots.iter().any(|root| {
            lexically_contains(
                &join_lexical_path(root.path().as_str(), ".nah", platform),
                path,
                platform,
            )
        }) || trusted_roots.iter().any(|root| {
            lexically_contains(
                &join_lexical_path(root.as_str(), ".nah", platform),
                path,
                platform,
            )
        });
        if proposal {
            tier = Some(NahProtectionTier::Proposal);
            continue;
        }

        let critical = owned_home_paths.iter().any(|entry| {
            protects_owned_path(
                &join_lexical_path(home.as_str(), entry, platform),
                path,
                platform,
                operation,
                pattern,
            )
        }) || installed_binary_paths(home.as_str(), platform)
            .iter()
            .any(|entry| protects_owned_path(entry, path, platform, operation, pattern))
            || critical_paths.iter().any(|entry| {
                protects_owned_path(entry.as_str(), path, platform, operation, pattern)
            })
            || (executable_bin_path(path, platform)
                && !roots
                    .iter()
                    .any(|root| lexically_contains(root.path().as_str(), path, platform))
                && !trusted_roots
                    .iter()
                    .any(|root| lexically_contains(root.as_str(), path, platform)));
        if critical {
            return Some(NahProtectionTier::Critical);
        }
    }
    tier
}

/// Reports whether an executed program's resolved path is one of nah's
/// installed binaries: the deciding executable's own paths first, then the
/// standard install locations. The path is the process identity, never the
/// spelling that launched it: a `nah` elsewhere is not nah's binary, and a
/// differently named alias resolved to an installed binary is.
pub fn is_installed_nah(
    path: &str,
    installed_executables: &[AbsolutePath],
    home: &AbsolutePath,
    platform: Platform,
) -> bool {
    let path = lexically_normalized(path, platform);
    installed_executables
        .iter()
        .any(|candidate| same_path(candidate.as_str(), &path, platform))
        || installed_binary_paths(home.as_str(), platform)
            .iter()
            .any(|candidate| same_path(candidate, &path, platform))
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
    selects_known_path(owned, path, platform, pattern)
        || operation == FilesystemOperation::Delete
            && !catastrophic_tree(path, platform)
            && lexically_contains(path, owned, platform)
}

fn catastrophic_tree(path: &str, platform: Platform) -> bool {
    let components = normalized_components(path, platform);
    components.is_empty()
        || platform == Platform::Windows
            && matches!(components.as_slice(), [drive] if drive.ends_with(':'))
        || platform != Platform::Windows && SYSTEM_TREES.contains(&path)
}

/// Splits on `\` on every platform, unlike `lexical_path`, so a POSIX name
/// containing a backslash is conservatively read as separate components.
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
