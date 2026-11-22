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

/// Whether a link-following listing of `root` went through a link below it
/// to a directory outside every one of `trees`: the root's own spellings
/// and those of each project and checkout. What the listing reached there
/// is a tree the selection never names. Only a link with a `selected` entry
/// below it counts: a read whose filters leave out everything below a link
/// takes nothing through it, and one with nothing listed below it leads to a
/// file or an empty directory, which carries no tree. A root that is itself
/// a link is what the command names. `links` are the listing's, and the
/// observer spells each link's target resolved.
pub(crate) fn leaves_tree_through_link(
    links: &[(AbsolutePath, AbsolutePath)],
    selected: &[AbsolutePath],
    root: &str,
    trees: &[&str],
    platform: Platform,
) -> bool {
    let below = |ancestor: &str, path: &str| {
        path.strip_prefix(ancestor)
            .is_some_and(|rest| rest.starts_with('/'))
    };
    let root = root.trim_end_matches('/');
    links.iter().any(|(visible, target)| {
        below(root, visible.as_str())
            && selected
                .iter()
                .any(|path| below(visible.as_str(), path.as_str()))
            && !trees
                .iter()
                .any(|tree| nah_proto::labels::lexically_contains(tree, target.as_str(), platform))
    })
}

/// A link inside a folder a recursive read takes that leads out of that
/// folder, as session replay's facts export names it.
pub struct LinkOut {
    /// The folder the read takes: the path it names, or for a glob each
    /// directory below its bound the glob matches.
    pub folder: String,
    /// The link, spelled as the listing of the folder names it.
    pub link: String,
    /// Where the link leads, spelled resolved.
    pub leads_to: String,
    /// Whether the read follows links (`zip -r`) or stores each as a link
    /// (`zip -ry`, `tar` without `-h`).
    pub follows_links: bool,
}

/// A folder's spellings in the host's state and each link declared below
/// it with the path it leads to; `None` where the state declares no folder.
pub type FolderLinks<'a> = dyn Fn(&str) -> Option<(Vec<String>, Vec<(String, String)>)> + 'a;

/// The links a recursive filesystem read `effect` of `plan` meets that lead
/// out of the folder it takes, when what it reads is archived, copied or
/// uploaded (`kept_by_write_or_upload`), from the links `listing` declares
/// below the read's bound: the bound's own spellings and each link with
/// where it leads. Every declared link counts, whether the read follows it
/// or not and whatever its filters leave out, since the listing is the
/// host's state, not what the read selects. A folder that is itself a link
/// is what the command names, so a link a glob matches is not one inside
/// its folder.
pub fn links_leading_out(
    plan: &effinterp_proto::Plan,
    effect: &effinterp_proto::Effect,
    listing: &FolderLinks,
    platform: Platform,
) -> Vec<LinkOut> {
    if effect.operation.as_str() != "filesystem.read"
        || !effect.realm.is_host()
        || effect.attributes.get("recursive") != Some(&effinterp_proto::AttrValue::Bool(true))
        || !kept_by_write_or_upload(plan, effect)
    {
        return Vec::new();
    }
    let Some((bound, _)) = crate::observation_request::observation_bound(&effect.resource) else {
        return Vec::new();
    };
    let Some((spellings, links)) = listing(&bound) else {
        return Vec::new();
    };
    let follows_links = crate::observation_request::reads_through_links(effect);
    let bound = bound.trim_end_matches('/');
    let spellings: Vec<&str> = std::iter::once(bound)
        .chain(
            spellings
                .iter()
                .map(|spelling| spelling.trim_end_matches('/')),
        )
        .collect();
    links
        .into_iter()
        .filter_map(|(link, leads_to)| {
            // The rest of the link's path below the spelling it is listed under.
            let rest = spellings.iter().find_map(|base| {
                link.strip_prefix(base)
                    .filter(|rest| rest.len() > 1 && rest.starts_with('/'))
            })?;
            // The folder below the bound: none for a named folder; for a
            // glob, the directory between the bound and the link it matches.
            let within = match &effect.resource {
                effinterp_proto::ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
                } => rest
                    .match_indices('/')
                    .skip(1)
                    .map(|(at, _)| &rest[..at])
                    .find(|within| {
                        effinterp_proto::glob_match(glob, &format!("{bound}{within}")) == Ok(true)
                    })?,
                _ => "",
            };
            let inside = spellings.iter().any(|spelling| {
                nah_proto::labels::lexically_contains(
                    &format!("{spelling}{within}"),
                    &leads_to,
                    platform,
                )
            });
            let folder = format!("{bound}{within}");
            (!inside).then(|| LinkOut {
                folder,
                link: link.clone(),
                leads_to,
                follows_links,
            })
        })
        .collect()
}

/// Whether what `effect` reads reaches a file write or an upload in the
/// plan's causal graph, through the value it feeds or a transfer it is the
/// source of: an archive or copy it writes itself (`zip -r`, `cp -r`), an
/// upload (`scp -r`, `aws s3 sync`), or its output sent on to one
/// (`tar -cf - DIR | curl -T -`, `grep -R ... > FILE`). A search or
/// listing whose output reaches only the terminal keeps nothing.
fn kept_by_write_or_upload(plan: &effinterp_proto::Plan, effect: &effinterp_proto::Effect) -> bool {
    use effinterp_proto::{CausalReason, OccurrenceKind};
    let Some(graph) = &plan.causality.graph else {
        return false;
    };
    let interaction = |node: &effinterp_proto::OccurrenceNode, operations: &[&str]| {
        matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
            if operations.contains(&operation.as_str()))
    };
    let mut pending: Vec<&effinterp_proto::OccurrenceId> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.execution == Some(effect.execution)
                && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction {
                    operation, resource, ..
                } if *operation == effect.operation && *resource == effect.resource)
        })
        .map(|node| &node.id)
        .collect();
    let mut seen: std::collections::BTreeSet<&effinterp_proto::OccurrenceId> =
        pending.iter().copied().collect();
    while let Some(id) = pending.pop() {
        for edge in &graph.edges {
            if &edge.from != id
                || !matches!(
                    edge.reason,
                    CausalReason::ValueDependency | CausalReason::ResourceTransfer
                )
                || !seen.insert(&edge.to)
            {
                continue;
            }
            if graph.nodes.iter().any(|node| {
                node.id == edge.to && interaction(node, &["filesystem.write", "network.upload"])
            }) {
                return true;
            }
            pending.push(&edge.to);
        }
    }
    false
}

/// The pattern a delete through wildcard directories selects, read through
/// the links on its way: for each directory link a link-following `listing`
/// of its bound went through where a leading run of the components of
/// `pattern_suffix` names it, the path that link leads to followed by the
/// components after that run. The shell expands every directory component
/// through the links it meets, so `/tmp/a/*/T`, with `/tmp/a/link` leading
/// to `/tmp/session`, selects `/tmp/session/T`. A link the last component
/// names is taken as the link, unless `final_followed`
/// (`observation_request::follows_final_link`): then `/tmp/a/*/` reads as
/// `/tmp/session` itself. Each reading spells the link's target with
/// glob escapes. Only the links the listing names are read, so a listing
/// that misses one misses its readings too. A listing that leaves nothing
/// below its root unlisted shows which directories exist, so a link below
/// which nothing listed matches the rest of the pattern yields no reading:
/// with `/tmp/a/home` leading to a home without `T`, `/tmp/a/*/T` selects
/// nothing there. Empty on Windows, or for a suffix that does not start a
/// component.
pub(crate) fn readings_through_links(
    pattern_suffix: &str,
    listing: &PathObservation,
    platform: Platform,
    final_followed: bool,
) -> Vec<String> {
    let Some(suffix) = pattern_suffix
        .strip_prefix('/')
        .filter(|_| platform != Platform::Windows)
    else {
        return Vec::new();
    };
    let components: Vec<&str> = suffix.split('/').collect();
    let reading = |target: &AbsolutePath, rest: &[&str]| {
        let mut reading = String::new();
        for character in target.as_str().trim_end_matches('/').chars() {
            if matches!(character, '*' | '?' | '[' | ']' | '\\') {
                reading.push('\\');
            }
            reading.push(character);
        }
        if !rest.is_empty() {
            reading.push('/');
            reading.push_str(&rest.join("/"));
        }
        reading
    };
    let Some(descendants) = listing.descendants() else {
        return Vec::new();
    };
    // Whether a listed entry below the link `visible`, or a folder above
    // one, matches the pattern's `rest` there.
    let listed = |visible: &AbsolutePath, rest: &[&str]| {
        let mut glob = String::new();
        for character in visible.as_str().chars() {
            if matches!(character, '*' | '?' | '[' | ']' | '\\') {
                glob.push('\\');
            }
            glob.push(character);
        }
        glob.push('/');
        glob.push_str(&rest.join("/"));
        let below = format!("{}/", visible.as_str());
        descendants
            .paths()
            .iter()
            .chain(descendants.links().iter().map(|(link, _)| link))
            .map(AbsolutePath::as_str)
            .filter(|path| path.starts_with(&below))
            .any(|path| {
                let mut entry = path;
                while entry.len() > visible.as_str().len() {
                    if effinterp_proto::glob_match(&glob, entry).unwrap_or(true) {
                        return true;
                    }
                    entry = &entry[..entry.rfind('/').unwrap_or(0)];
                }
                false
            })
    };
    let mut readings = std::collections::BTreeSet::new();
    let root = listing.resolved().as_str().trim_end_matches('/');
    for (visible, target) in descendants.links() {
        let names: Vec<&str> = match visible.as_str().strip_prefix(root) {
            Some("") => Vec::new(),
            Some(rest) if rest.starts_with('/') => rest[1..].split('/').collect(),
            _ => continue,
        };
        for end in run_ends(&components, &names) {
            let rest = &components[end..];
            if (end < components.len() || final_followed)
                && (rest.is_empty() || descendants.unlisted_entries() || listed(visible, rest))
            {
                readings.insert(reading(target, rest));
            }
        }
    }
    readings.into_iter().collect()
}

/// The positions in `components` where a leading run of them that names
/// the directories `names`, one by one, ends. A `**` component names any
/// number of directories. A component holding an extglob group or a brace
/// list names any one: their matching is not simulated, since an inexact
/// "no" would drop a link the shell goes through.
fn run_ends(components: &[&str], names: &[&str]) -> std::collections::BTreeSet<usize> {
    let mut ends = std::collections::BTreeSet::from([0]);
    for name in names {
        let mut next = std::collections::BTreeSet::new();
        for mut at in ends {
            while let Some(component) = components.get(at) {
                if *component == "**" {
                    next.insert(at);
                    at += 1;
                    continue;
                }
                if nah_proto::labels::pattern::holds_extglob(component)
                    || component.contains('{')
                    || effinterp_proto::glob_match(component, name).unwrap_or(true)
                {
                    next.insert(at + 1);
                }
                break;
            }
        }
        ends = next;
    }
    ends
}

/// Whether a complete listing below a pattern's bound `bound`, observed as
/// `observed`, shows that no directory link below the bound leads to `folder`
/// or a folder above it, so a pattern that names only entries below `folder`
/// (`labels::home_folders_reached_through_links`) cannot select the folder
/// itself. `folder` is spelled at or below `bound`.
///
/// The listing must name every link below the bound: a walk that leaves a
/// link unfollowed hides where it leads. An empty directory it marks
/// unlisted cannot lead anywhere. A Windows walk counts a reparse point as
/// an entry it could not read, so a complete Windows listing holds no link.
pub(crate) fn no_link_leads_back(
    observed: Option<&PathObservation>,
    bound: &str,
    folder: &str,
    platform: Platform,
) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    let Some(descendants) = observed
        .descendants()
        .filter(|descendants| descendants.complete() && descendants.names_every_link())
    else {
        return false;
    };
    let links = descendants.links();
    if links.is_empty() {
        return true;
    }
    let fold = |path: &str| nah_proto::labels::lexical_path::fold_path_spelling(path, platform);
    let (bound, folder) = (fold(bound), fold(folder));
    let Some(rest) = folder
        .strip_prefix(bound.trim_end_matches('/'))
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
    else {
        return false;
    };
    // The listing spells entries below the bound's own followed path, and
    // the folder is where the links on the way to it lead.
    let root = observed.realpath().unwrap_or_else(|| observed.resolved());
    let visible = format!("{}{rest}", root.as_str().trim_end_matches('/'));
    let followed = followed_through_links(links, &visible).unwrap_or(visible);
    !links.iter().any(|(_, target)| {
        nah_proto::labels::lexically_contains(target.as_str(), &folder, platform)
            || nah_proto::labels::lexically_contains(target.as_str(), &followed, platform)
    })
}
