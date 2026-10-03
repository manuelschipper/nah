//! The system-tree catalog: the Unix and macOS trees whose loss breaks the host.

use super::lexical_path::fold_path_spelling;
use super::pattern::selects_every_entry;
use crate::action::pattern_bound;
use crate::ctx::Platform;

/// The system trees: the Unix and macOS roots whose deletion or wholesale
/// overwrite breaks the host. Consumers: `tier::catastrophic_tree`, so a
/// self-protection delete never widens to one, and `selects_root_or_system_tree`
/// and `pattern_selects_system_tree`, which `fs-system-tree` reaches it through.
/// `scope::path_scope` classifies `PathScope::System` with the narrower
/// `SCOPE_SYSTEM_ROOTS` instead.
pub const SYSTEM_TREES: [&str; 23] = [
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/root",
    "/run",
    "/sbin",
    "/proc",
    "/sys",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/var",
    "/tmp",
    "/Library",
    "/System",
    // macOS canonicalizes the public /etc and /var aliases here.
    "/private/etc",
    "/private/tmp",
    "/private/var",
];

/// The scope system roots: the trees whose every path `scope::path_scope`
/// classifies as `PathScope::System`. A narrower list than `SYSTEM_TREES`:
/// paths under `/bin`, `/boot`, `/lib32`, `/lib64`, `/root`, `/sbin`, `/proc`,
/// `/sys`, `/usr`, `/tmp`, `/Library`, `/System` and `/private/{etc,tmp,var}`
/// are `PathScope::OutsideProject`. Replacing it with `SYSTEM_TREES` (less `/`,
/// which encloses every path) changes no `corpus/*.jsonl` decision, but flips
/// the pinned `/private/etc/sudoers` scope in the nah-proto labels suite, and
/// the `system-scope` label then reaches those paths in the credential-search
/// and complete-move flow queries, which no corpus row observes. Unifying them
/// is the owner's decision.
pub(crate) const SCOPE_SYSTEM_ROOTS: [&str; 5] = ["/dev", "/etc", "/lib", "/run", "/var"];

/// An expanded pattern names an unknown path bounded by its literal prefix, so a
/// system tree that starts with the bound is still in reach, as is a pattern
/// that selects every entry of one. Under a temporary tree, whose entries are
/// disposable one by one, a last component that names a literal selects only
/// the entries it matches: `/tmp/*.log` is not `/tmp/*`. Under any other tree
/// a subset can still break the host (`/bin/*sh`), so any pattern of its
/// entries reaches it.
pub fn pattern_selects_system_tree(pattern: &str) -> bool {
    let bound = pattern_bound(pattern);
    let every_entry = || {
        bound
            .rfind('/')
            .map(|separator| {
                (
                    &bound[..separator],
                    pattern[separator + 1..].trim_end_matches('/'),
                )
            })
            .is_none_or(|(tree, name)| {
                !TEMPORARY_TREES.contains(&tree) || name.contains('/') || selects_every_entry(name)
            })
    };
    SYSTEM_TREES.iter().any(|tree| tree.starts_with(bound))
        || selects_root_or_system_tree(&format!("{bound}*")) && every_entry()
}

/// The system trees whose entries a pattern may name selectively.
const TEMPORARY_TREES: [&str; 2] = ["/tmp", "/private/tmp"];

/// Whether `target` selects the filesystem root, a system tree, or a Windows
/// drive root or system tree, or every entry of one.
pub fn selects_root_or_system_tree(target: &str) -> bool {
    SYSTEM_TREES.iter().any(|tree| selects_tree(target, tree))
        || target
            .strip_prefix("/{")
            .and_then(|target| target.strip_suffix('}'))
            .is_some_and(|trees| {
                // `/{etc,usr}` names each single-component system tree it lists.
                trees.split(',').any(|tree| {
                    SYSTEM_TREES
                        .iter()
                        .filter_map(|system| system.strip_prefix('/'))
                        .any(|system| !system.is_empty() && !system.contains('/') && system == tree)
                })
            })
        || selects_windows_root_or_system_tree(target)
}

fn selects_windows_root_or_system_tree(target: &str) -> bool {
    // The Windows trees are read in the Windows spelling on every host.
    let target = fold_path_spelling(target, Platform::Windows);
    let tree = target
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':')
        .then(|| &target[2..]);
    if let Some(tree) = tree {
        if matches!(tree, "/" | "/*" | "/.*" | "/{*,.*}") {
            return true;
        }
        return [
            "/windows",
            "/program files",
            "/program files (x86)",
            "/programdata",
        ]
        .iter()
        .any(|system| selects_tree(tree, system));
    }
    let Some(unc) = target.strip_prefix("//") else {
        return false;
    };
    let components = unc.split('/').collect::<Vec<_>>();
    components.len() == 2
        || (components.len() == 3 && matches!(components[2], "*" | ".*" | "{*,.*}"))
}

fn selects_tree(target: &str, tree: &str) -> bool {
    if target == tree {
        return true;
    }
    let prefix = if tree == "/" {
        "/".to_owned()
    } else {
        format!("{tree}/")
    };
    ["*", ".*", "{*,.*}"]
        .iter()
        .any(|suffix| target == format!("{prefix}{suffix}"))
}
