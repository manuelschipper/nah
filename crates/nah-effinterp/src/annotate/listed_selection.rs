//! Which entries a glob or root-wide selection reaches, read from a complete
//! listing of the files below the directory that bounds it.

use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::PathObservation;

/// The entries a pattern with a `**` component, or any pattern a deletion
/// that does not recurse takes, reaches from a complete listing of the files
/// below its bound, observed as `target`. `None` for any other pattern, or
/// without such a listing.
///
/// A name selected at any depth (`B/**/name`) reaches the listed entries it
/// matches. A listing holds files, so a matched directory is found as the
/// ancestor of a file; an empty one holds nothing to lose.
///
/// A listing that followed links names each link it went through, and an
/// entry reached through one is the path that link leads to. An `entry`
/// operation (unlink, move) takes a selected link itself, not its target,
/// in the directory its parent's links lead to.
///
/// A pattern ending in `**` reaches every entry below its bound, so its
/// result, marked whole, holds only the paths links lead to.
///
/// A deletion that does not recurse cannot remove a directory that holds
/// files, so with `files_only` any pattern reaches only the listed entries
/// themselves, never the directories above them.
///
/// A write or access-control change through a glob reaches what each
/// matched link points at, so with `writes_links` a pattern without `**` has
/// the same marked-whole result: `keys*` keeps what its spelling reaches and
/// adds the `~/.ssh/authorized_keys` a matched `keys-alias` leads to.
///
/// A `delete` of a pattern with a wildcard directory component selects only
/// through the directories that exist, so it reaches the listed entries it
/// matches when the listing leaves nothing below the bound unlisted (no
/// unfollowed link, empty directory or special file): `~/.config/*/Cache`
/// then reaches `~/.config/autostart` only if a file lies under
/// `autostart/Cache`.
#[allow(clippy::too_many_arguments)]
pub(super) fn listed_selection(
    pattern_suffix: Option<&str>,
    observed: Option<&PathObservation>,
    target: &AbsolutePath,
    platform: Platform,
    entry: bool,
    delete: bool,
    files_only: bool,
    writes_links: bool,
) -> Option<(bool, Vec<AbsolutePath>)> {
    if platform == Platform::Windows {
        return None;
    }
    // Below a root bound (`/` for `/et*`) the suffix carries no separator of
    // its own, and the root's listing is not read for such a selection.
    let suffix = pattern_suffix.filter(|suffix| suffix.starts_with('/'))?;
    let segments: Vec<&str> = suffix.split('/').collect();
    let bounded = segments.contains(&"**") || files_only;
    let wildcard_directory = segments[..segments.len() - 1]
        .iter()
        .any(|segment| segment.contains(['*', '?', '[']));
    // A written glob without `**` keeps the reach its spelling has and adds
    // what the links it matches lead to.
    let adds_link_targets = writes_links && !bounded;
    if !(bounded || delete && wildcard_directory || adds_link_targets) {
        return None;
    }
    let whole = segments.last() == Some(&"**");
    let descendants = observed?
        .descendants()
        .filter(|descendants| descendants.complete())
        .filter(|descendants| bounded || adds_link_targets || !descendants.unlisted_entries())?;
    let root = target.as_str().trim_end_matches('/');
    let below = |path: &str| {
        path.strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
    };
    let links = descendants.links();
    // The path a walked path names: through the innermost link above it.
    let followed =
        |path: &str| followed_through_links(links, path).unwrap_or_else(|| path.to_owned());
    // An entry operation on a link takes the link itself, in the directory
    // its parent's links lead to.
    let identity = |path: &str| match path.rsplit_once('/') {
        Some((parent, name))
            if entry && links.iter().any(|(visible, _)| visible.as_str() == path) =>
        {
            format!("{}/{name}", followed(parent))
        }
        _ => followed(path),
    };
    // Every listed file, and each link the walk went through, which may be
    // matched itself.
    let files = descendants
        .paths()
        .iter()
        .chain(links.iter().map(|(visible, _)| visible))
        .map(AbsolutePath::as_str)
        .filter(|file| below(file));
    let members: std::collections::BTreeSet<String> = if whole {
        files
            .filter_map(|file| {
                let reached = identity(file);
                (reached != file).then_some(reached)
            })
            .collect()
    } else {
        let mut glob = String::new();
        for character in root.chars() {
            if matches!(character, '*' | '?' | '[' | ']' | '\\') {
                glob.push('\\');
            }
            glob.push(character);
        }
        glob.push_str(suffix);
        let mut members = std::collections::BTreeSet::new();
        for file in files {
            let mut entry = file;
            while entry.len() > root.len() {
                if effinterp_proto::glob_match(&glob, entry).ok()? {
                    let reached = identity(entry);
                    if !adds_link_targets || reached != entry {
                        members.insert(reached);
                    }
                }
                if files_only {
                    break;
                }
                entry = &entry[..entry.rfind('/')?];
            }
        }
        members
    };
    members
        .into_iter()
        .map(|member| AbsolutePath::new(platform, member).ok())
        .collect::<Option<_>>()
        .map(|members| (whole || adds_link_targets, members))
}

/// The path a link-following listing's `path` names through the innermost
/// link above or at it, or None when it went through no link. `links` pairs
/// each link the listing went through with the path it leads to.
pub(crate) fn followed_through_links(
    links: &[(AbsolutePath, AbsolutePath)],
    path: &str,
) -> Option<String> {
    let (visible, target) = links
        .iter()
        .filter(|(visible, _)| {
            path.strip_prefix(visible.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .max_by_key(|(visible, _)| visible.as_str().len())?;
    Some(format!(
        "{}{}",
        target.as_str(),
        &path[visible.as_str().len()..]
    ))
}
