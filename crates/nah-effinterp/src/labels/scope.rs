// UNDOCUMENTED-EFFINTERP: copied path-scope classifier for plan annotations.

use nah_proto::action::PathScope;
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::Root;

use super::contains;

/// Classifies which scope — project root, home, system, or outside — owns the
/// effect's resolved target path.
pub fn path_scope(
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
