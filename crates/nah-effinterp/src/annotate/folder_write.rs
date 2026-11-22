//! What a write of a whole folder, or of a glob of its direct children, puts
//! there: the question self-protection asks of a write into the folder that
//! holds Nah's installed program
//! (`nah_proto::labels::tier::installed_nah_in_written_folder`).

use effinterp_proto::{
    CausalReason, Effect, OccurrenceKind, ResourceExpr, ResourcePattern, glob_match,
};
use nah_proto::ctx::Platform;
use nah_proto::labels::lexical_path::{fold_path_spelling, lexically_contains};
use nah_proto::observation::PathKind;

use crate::observation_request::observation_bound;
use crate::plan_view::PlanView;

/// What a write of a whole folder, or of a glob of its direct children,
/// leaves directly in it, as far as the plan and observation show.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FolderEntries {
    /// An entry of the name asked about may be among them.
    Named,
    /// They are known, and none has that name.
    Others,
    /// Nothing shows what they are named: an archive's members, or a source
    /// Nah could not list.
    Unknown,
}

/// What `effect`, a write of a folder, leaves directly in it, asked of the
/// name `name`.
///
/// A copy or move into the folder (the engine's resource transfers into the
/// write) carries the names of its sources: a source's own name, and the
/// entries directly below a source directory, which `rsync -a SRC/` and BSD
/// `cp -R SRC/` copy in place of the directory. A source is known when its
/// observation shows a file, or a directory with a complete listing, and the
/// call writes nothing into it first; a missing source is not known, since
/// the call may create it.
///
/// A write with no source names a set of entries no listing shows: an
/// archive extracted into the folder (`DIR/**`, or the folder written whole)
/// carries members Nah does not read, unless the command names every member
/// and the engine states each as a write of its own (`members_stated`),
/// which is then judged by its own path. A package manager's install names
/// its packages, which `process_protection` judges. A glob of the folder's
/// direct children (`DIR/*`) is matched against the entries already there,
/// so it reaches every name.
pub(super) fn written_entries(view: &PlanView<'_>, effect: &Effect, name: &str) -> FolderEntries {
    if effect.attributes.get("members_stated") == Some(&effinterp_proto::AttrValue::Bool(true))
        || effect.attributes.contains_key("package_manager")
    {
        return FolderEntries::Others;
    }
    if let Some(effinterp_proto::AttrValue::String(archive)) =
        effect.attributes.get("extracts_archive")
    {
        return archive_entries(view, effect, archive, name);
    }
    let sources = transfer_sources(view, effect);
    if sources.is_empty() {
        let children = matches!(&effect.resource, ResourceExpr::Pattern { .. })
            && observation_bound(&effect.resource)
                .is_some_and(|(_, suffix)| !suffix.contains("**"));
        return if children {
            FolderEntries::Named
        } else {
            FolderEntries::Unknown
        };
    }
    let entries = sources
        .iter()
        .map(|source| source_entries(view, effect, source, name))
        .collect::<Vec<_>>();
    [FolderEntries::Named, FolderEntries::Unknown]
        .into_iter()
        .find(|kind| entries.contains(kind))
        .unwrap_or(FolderEntries::Others)
}

/// The host filesystem reads and move deletes whose content the engine
/// transfers into `effect`.
fn transfer_sources<'a>(view: &PlanView<'a>, effect: &Effect) -> Vec<&'a ResourceExpr> {
    view.occurrences_for_execution(effect.execution)
        .filter(|node| {
            node.realm == effect.realm
                && node.condition == effect.condition
                && node.provenance == effect.provenance
                && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    ..
                } if operation == &effect.operation && resource == &effect.resource)
        })
        .flat_map(|node| view.incoming_edges(&node.id))
        .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
        .filter_map(|edge| view.causal_node(&edge.from))
        .filter_map(|source| match &source.occurrence {
            OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                ..
            } if source.realm.is_host()
                && matches!(operation.as_str(), "filesystem.read" | "filesystem.delete") =>
            {
                Some(resource)
            }
            _ => None,
        })
        .collect()
}

/// What copying or moving `source` into a folder leaves directly in it,
/// asked of the name `name`.
fn source_entries(
    view: &PlanView<'_>,
    write: &Effect,
    source: &ResourceExpr,
    name: &str,
) -> FolderEntries {
    let platform = view.authority().platform();
    let Some((bound, suffix)) = observation_bound(source) else {
        return FolderEntries::Unknown;
    };
    let Some(observed) = view.observed_path(&bound).filter(|observed| {
        !written_in_call(view, write, &bound) && observed.kind() != PathKind::Missing
    }) else {
        return FolderEntries::Unknown;
    };
    let named = |entry: &str| same_name(entry, name, platform);
    let found = |holds: bool| {
        if holds {
            FolderEntries::Named
        } else {
            FolderEntries::Others
        }
    };
    let own_name = bound
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("");
    let directory = observed.kind() == PathKind::Directory
        || observed.kind() == PathKind::Symlink
            && observed.target_kind() == Some(PathKind::Directory);
    if !directory {
        return found(named(own_name));
    }
    let Some(listing) = observed
        .descendants()
        .filter(|listing| listing.complete() && !listing.unlisted_entries())
    else {
        return FolderEntries::Unknown;
    };
    let roots = [Some(observed.resolved()), observed.realpath()];
    // A listed entry's components below the source folder.
    let below = |path: &str| {
        roots.iter().flatten().find_map(|root| {
            path.strip_prefix(root.as_str().trim_end_matches(['/', '\\']))
                .and_then(|rest| rest.strip_prefix(['/', '\\']))
                .map(|rest| {
                    rest.split(['/', '\\'])
                        .filter(|component| !component.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
        })
    };
    let mut entries = listing
        .paths()
        .iter()
        .map(|path| path.as_str())
        .chain(listing.links().iter().map(|(link, _)| link.as_str()));
    let glob = match source {
        ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob, .. },
        } if !suffix.is_empty() => glob,
        // The folder itself is copied, or its direct children in its place.
        _ => {
            return found(
                named(own_name)
                    || entries.any(|path| {
                        below(path).is_none_or(|components| {
                            components.first().is_none_or(|child| named(child))
                        })
                    }),
            );
        }
    };
    // A glob copies each entry it matches under that entry's own name, so a
    // listed path, or a folder above it, reaches the folder only where the
    // glob matches it. A glob the matcher cannot read matches every entry.
    let folded = fold_path_spelling(glob, platform);
    let bound = bound.trim_end_matches(['/', '\\']);
    found(entries.any(|path| {
        let Some(components) = below(path) else {
            return true;
        };
        (1..=components.len()).any(|depth| {
            let candidate = format!("{bound}/{}", components[..depth].join("/"));
            match glob_match(&folded, &fold_path_spelling(&candidate, platform)) {
                Ok(true) => named(&components[depth - 1]),
                Ok(false) => false,
                Err(_) => true,
            }
        })
    }))
}

/// What extracting every member of the archive at `archive` leaves directly
/// in the folder: each member at its first component, or at its last with
/// `junk_paths` (`unzip -j`). A member that is absolute or climbs with `..`
/// may land anywhere, so it counts as named; a link member may lead later
/// members elsewhere, and an archive the host did not list or the call
/// writes first holds members no listing shows, so those are unknown.
fn archive_entries(
    view: &PlanView<'_>,
    write: &Effect,
    archive: &str,
    name: &str,
) -> FolderEntries {
    let platform = view.authority().platform();
    if written_in_call(view, write, archive) {
        return FolderEntries::Unknown;
    }
    let Some(members) = view.archive_members(archive) else {
        return FolderEntries::Unknown;
    };
    let junk_paths =
        write.attributes.get("junk_paths") == Some(&effinterp_proto::AttrValue::Bool(true));
    let mut entries = FolderEntries::Others;
    for member in members {
        let components = member
            .name
            .split(['/', '\\'])
            .filter(|component| !component.is_empty() && *component != ".")
            .collect::<Vec<_>>();
        let placed = if junk_paths {
            components.last()
        } else {
            components.first()
        };
        if member.name.starts_with(['/', '\\'])
            || components.contains(&"..")
            || placed
                .is_some_and(|placed| placed.contains(':') || same_name(placed, name, platform))
        {
            return FolderEntries::Named;
        }
        if member.link {
            entries = FolderEntries::Unknown;
        }
    }
    entries
}

/// Whether another write in the call reaches `path` or a folder holding it.
/// An observation describes the host before the call, so what such a write
/// puts there is not in it.
fn written_in_call(view: &PlanView<'_>, write: &Effect, path: &str) -> bool {
    let platform = view.authority().platform();
    view.plan().effects.iter().any(|other| {
        !std::ptr::eq(other, write)
            && other.realm.is_host()
            && matches!(
                other.operation.as_str(),
                "filesystem.write" | "filesystem.create"
            )
            && observation_bound(&other.resource).is_none_or(|(written, _)| {
                lexically_contains(path, &written, platform)
                    || lexically_contains(&written, path, platform)
            })
    })
}

fn same_name(left: &str, right: &str, platform: Platform) -> bool {
    fold_path_spelling(left, platform) == fold_path_spelling(right, platform)
}
