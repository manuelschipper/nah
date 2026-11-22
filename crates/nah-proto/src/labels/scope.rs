//! Classifies which scope owns a resolved path; it does not canonicalize host paths.

use super::system_tree::{SCOPE_SYSTEM_ROOTS, selects_root_or_system_tree, within_system_tree};
use super::temporary_root::holds_temporary_root;
use super::{PathScope, lexically_contains};
use crate::ctx::{AbsolutePath, Platform};
use crate::observation::Root;

/// Classifies which scope — project root, home, system, or outside — owns the
/// effect's resolved target path. The innermost observed root wins.
pub fn path_scope(
    target: &AbsolutePath,
    roots: &[Root],
    home: &AbsolutePath,
    platform: Platform,
) -> PathScope {
    if let Some(root) = roots
        .iter()
        .filter(|root| lexically_contains(root.path().as_str(), target.as_str(), platform))
        .max_by_key(|root| root.path().as_str().len())
    {
        return PathScope::Project {
            root: root.path().clone(),
        };
    }
    if lexically_contains(home.as_str(), target.as_str(), platform) {
        return PathScope::Home;
    }
    if SCOPE_SYSTEM_ROOTS
        .iter()
        .any(|root| lexically_contains(root, target.as_str(), platform))
    {
        PathScope::System
    } else {
        PathScope::OutsideProject
    }
}

/// Whether `directory`, a folder no Git repository contains, can stand as the
/// project the runtime reports: never home or an ancestor of it, a temporary
/// or cache root or an ancestor of one, or a system tree or a folder in one.
pub fn admits_project_directory(
    directory: &str,
    home: &str,
    observed_roots: &[&str],
    platform: Platform,
) -> bool {
    !lexically_contains(directory, home, platform)
        && !holds_temporary_root(directory, home, observed_roots, platform)
        && !selects_root_or_system_tree(directory)
        && !within_system_tree(directory, platform)
}
