//! PowerShell `Copy-Item`, `Move-Item` and `Rename-Item`: the sources each
//! reads or removes and the destination entries each writes.

use effinterp_proto::{
    Boundary, BoundaryReason, CoverageLevel, ObservationOutcome, PathKind, ProvenanceKind,
    ProvenanceRef, ResourceExpr, ResourceIdentity, ResourcePattern,
};

use crate::builder::PlanBuilder;
use crate::nest::Nest;
use crate::resource_transfer::TransferBinding;

use super::cmdlet_parameters::{COPY_ITEM, MOVE_ITEM, RENAME_ITEM, bind_cmdlet_parameters};
use super::item_landing::{
    LandingShape, MAX_LANDED_ENTRIES, Unestablished, entry_name, filesystem_model_gap,
    landed_entries, observed_directory,
};
use super::path_resolution::{
    drive_rooted, filesystem_effect, filesystem_item, names_location_or_ancestor, resolved_path,
};
use super::powershell_boundary;
use super::ps_words::PsWord;
use super::wildcards::{
    admitted_entries, filters_admit, glob_components_below, wildcard_match, wildcard_root,
};

/// `Move-Item` and `Rename-Item` remove each source entry and create it under
/// the destination name; `Rename-Item`'s new name stays in the source's
/// directory. `Copy-Item` reads each source and leaves it in place.
///
/// An existing destination directory receives each named source under the
/// source's own name, and a move or recursive copy also lands everything
/// beneath that entry. A move onto an existing entry is established only as
/// a file it replaces under -Force. What lands beneath a landing is read from
/// the host's listing of the source (`landed_entries`), and each landed entry
/// is a write of its own; where a wildcard's established selection lands only
/// inside the destination, or nowhere, the destination write states
/// `entries_only`. A listing the host does not give leaves the landing
/// written and an observation boundary. A source that does not
/// resolve still leaves the destination it names established.
pub(super) fn copy_or_move_item(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
    command: &str,
) -> bool {
    use effinterp_proto::{Fact, ObservationQuery, ObservationRefusal};
    // Steps before this one the analysis could not model on the filesystem;
    // the gaps this command records about itself come after.
    let unmodeled_before = builder.budget().unmodeled_steps();
    let rename = command.eq_ignore_ascii_case("Rename-Item");
    let copy = command.eq_ignore_ascii_case("Copy-Item");
    let (cmdlet, model) = if rename {
        (&RENAME_ITEM, "powershell/rename-item@v1")
    } else if copy {
        (&COPY_ITEM, "powershell/copy-item@v1")
    } else {
        (&MOVE_ITEM, "powershell/move-item@v1")
    };
    let bound = match bind_cmdlet_parameters(arguments, cmdlet) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let (sources, wildcards) = match bound.paths("Path") {
        Ok(Some((paths, wildcards))) if !paths.is_empty() && (!rename || paths.len() == 1) => {
            (paths, wildcards)
        }
        Ok(_) => {
            powershell_boundary(
                builder,
                node,
                &format!("PowerShell {command} does not name its source"),
            );
            return false;
        }
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    // A path qualified by another provider (HKLM:\, Env:) names an item of
    // that provider's store, not a file. PowerShell processes each source on
    // its own, so the filesystem sources still land.
    let items = sources
        .iter()
        .map(|source| filesystem_item(source))
        .collect::<Vec<_>>();
    let foreign = items.iter().any(Option::is_none);
    if foreign {
        powershell_boundary(
            builder,
            node,
            &format!("PowerShell {command} source is outside the filesystem provider"),
        );
    }
    if items.iter().all(Option::is_none) {
        return false;
    }
    if bound.switch("WhatIf") {
        return bound.complete(builder, node, command);
    }
    let mut complete = bound.complete(builder, node, command) && !foreign;
    let recursive = copy && bound.switch("Recurse");
    let recursive_attributes = || -> crate::models::common::Attrs {
        if recursive {
            [("recursive".into(), effinterp_proto::AttrValue::Bool(true))].into()
        } else {
            Default::default()
        }
    };
    let destination = match bound.value(cmdlet.positions[1]) {
        Ok(Some(name)) if rename => {
            // The new name is an entry of the source's directory.
            let source = items[0].unwrap_or_default();
            match source.rfind(['\\', '/']) {
                Some(parent) if !name.contains(['\\', '/']) => {
                    Some(format!("{}{name}", &source[..parent + 1]))
                }
                _ => None,
            }
        }
        Ok(destination) => destination.map(|destination| {
            filesystem_item(destination)
                .unwrap_or(destination)
                .to_string()
        }),
        Err(_) => None,
    };
    let destination_unread = destination.is_none();
    // Every host question is asked before any source effect: a wildcard's
    // removal leaves the host's later answers undecided.
    let target = destination.and_then(|destination| {
        let resource = resolved_path(builder, nest, &destination, false, location, node, command)?;
        let directory = observed_directory(builder, &resource, node);
        Some((destination, resource, directory))
    });
    let force = bound.switch("Force");
    // A moved directory brings everything beneath it, as a recursive copy
    // does.
    let tree = recursive || !copy;
    // -Container:$false copies the files beneath a source without the
    // directories that hold them, which is not modeled.
    let flattens = copy && bound.bound("Container") && !bound.switch("Container");
    if flattens {
        complete = false;
        powershell_boundary(
            builder,
            node,
            "PowerShell Copy-Item -Container:$false flattens what it copies, which is not modeled",
        );
    }
    // -Include, -Exclude and -Filter admit items by name before a copy
    // recurses into them. A named item they do not admit is not copied or
    // moved at all; whether they also choose among what a named directory
    // holds is not established (`landed_entries`).
    let filters = [
        bound.values("Include"),
        bound.values("Exclude"),
        bound.values("Filter"),
    ];
    let filtered = filters.iter().any(Option::is_some);
    // `fold` matches without regard to case. Whether PowerShell folds case
    // for these names off Windows is not established, so callers ask both.
    let admits = |name: &str, fold: bool| filters_admit(&filters, name, fold);
    // Whether -Exclude names an entry, whatever -Include and -Filter say.
    let excludes = |name: &str, fold: bool| -> Option<bool> {
        for pattern in filters[1].unwrap_or_default() {
            if wildcard_match(pattern, name, fold)? {
                return Some(true);
            }
        }
        Some(false)
    };
    // The resource each source names, if it resolved and was not left out.
    let mut resolved = Vec::new();
    let mut left_out = vec![false; items.len()];
    for (index, item) in items.iter().enumerate() {
        let Some(source) = item else {
            resolved.push(None);
            continue;
        };
        let Some(resource) =
            resolved_path(builder, nest, source, wildcards, location, node, command)
        else {
            complete = false;
            resolved.push(None);
            continue;
        };
        // PowerShell refuses to move or rename the current location or one
        // of its ancestors (MoveItemInUse, RenameItemInUse), as it refuses to
        // remove them. A copy leaves the source in place.
        if !copy && location.is_some_and(|location| names_location_or_ancestor(&resource, location))
        {
            left_out[index] = true;
            resolved.push(None);
            continue;
        }
        // A filtered wildcard departs as the entries its filters admit, once
        // the host has listed them (`admitted` below).
        if filtered && !matches!(resource, ResourceExpr::Pattern { .. }) {
            // Windows folds case; elsewhere both readings are asked.
            let windows = matches!(
                &resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } if drive_rooted(path)
            );
            let admitted = entry_name(source)
                .and_then(|name| Some((admits(name, true)?, admits(name, windows)?)));
            match admitted {
                Some((true, true)) => {}
                Some((false, false)) => {
                    // -Include and -Filter may pass over a named directory
                    // and choose among what it holds, or not apply to a path
                    // without a wildcard at all. Unless -Exclude names it,
                    // a directory that brings its tree is kept, with what
                    // lands left to `landed_entries`.
                    let excluded = entry_name(source).is_none_or(|name| {
                        excludes(name, true) != Some(false)
                            || excludes(name, windows) != Some(false)
                    });
                    let directory = match &resource {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } => match builder.budget().observe_path(path) {
                            ObservationOutcome::Path(fact) => {
                                let kind = match &fact.followed {
                                    Fact::Known(target) => target.kind.known().copied(),
                                    Fact::Unavailable(_) => Some(fact.kind),
                                };
                                kind.is_none_or(|kind| kind == PathKind::Directory)
                            }
                            _ => true,
                        },
                        _ => true,
                    };
                    if excluded || !tree || !directory {
                        left_out[index] = true;
                        resolved.push(None);
                        continue;
                    }
                    complete = false;
                    builder.boundary(filesystem_model_gap(
                        node,
                        format!(
                            "PowerShell {command} -Include or -Filter does not match a named directory, and whether it still copies what the directory holds is not established"
                        ),
                    ));
                }
                // Admitted under one case rule only: the source is kept.
                Some(_) => {
                    complete = false;
                    builder.boundary(filesystem_model_gap(
                        node,
                        format!(
                            "PowerShell {command} filters admit a named source only under one case rule, which is not modeled"
                        ),
                    ));
                }
                None => {
                    complete = false;
                    powershell_boundary(
                        builder,
                        node,
                        &format!(
                            "PowerShell {command} filters could not be matched against a named source"
                        ),
                    );
                }
            }
        }
        resolved.push(Some(resource));
    }
    // A destination matters only for a source that is moved or copied.
    if destination_unread && resolved.iter().any(Option::is_some) {
        powershell_boundary(
            builder,
            node,
            &format!("PowerShell {command} destination is not one literal path"),
        );
    }
    // What each source is, as the host saw it. The view no longer describes
    // a source this command changed earlier.
    let observations = builder.budget().observations.is_some();
    let roots = resolved
        .iter()
        .map(|left| match left {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path.clone()),
            Some(ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            }) => Some(wildcard_root(glob).to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let facts = roots
        .iter()
        .map(|root| {
            let root = root.as_ref()?;
            observations.then(|| builder.budget().observe_path(root))
        })
        .collect::<Vec<_>>();
    let current = |index: usize| {
        !matches!(
            facts[index],
            Some(ObservationOutcome::Refused(
                ObservationRefusal::Stale | ObservationRefusal::Ambiguous
            ))
        )
    };
    let source_kind = |index: usize| match &facts[index] {
        Some(ObservationOutcome::Path(fact)) => match &fact.followed {
            Fact::Known(target) => target.kind.known().copied(),
            Fact::Unavailable(_) => (fact.kind != PathKind::Symlink).then_some(fact.kind),
        },
        _ => None,
    };
    let wildcard = |index: usize| matches!(resolved[index], Some(ResourceExpr::Pattern { .. }));
    // A wildcard's entries land inside an existing directory, and elsewhere
    // replace or become the destination; what it selects is read from the
    // host's listing of the directory it selects beneath. A source this
    // command changed earlier, or a flattened copy, holds what the host did
    // not see, so the destination stays written instead.
    let mirrors_wildcard = |index: usize| wildcard(index) && current(index) && !flattens;
    // What each directory whose entries land holds, asked before any source
    // effect for the same reason.
    let listings = (0..resolved.len())
        .map(|index| {
            let root = roots[index].as_ref()?;
            let lands = !rename
                && target.is_some()
                && builder.is_host_realm()
                && (mirrors_wildcard(index) || tree && current(index) && !flattens);
            if !lands || source_kind(index) != Some(PathKind::Directory) {
                return None;
            }
            // A copy without -Recurse lands only what the wildcard's own
            // components reach. So does a move as modeled: a moved file holds
            // nothing, and a moved directory is not established anyway.
            let depth = match &resolved[index] {
                Some(ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { glob, .. },
                }) if !recursive => Some(glob_components_below(glob, root)),
                _ => None,
            };
            let outcome = builder
                .budget()
                .observe_listing(root, depth, unmodeled_before);
            builder.node(
                ProvenanceKind::HostObservation {
                    query: ObservationQuery::Listing {
                        path: root.clone(),
                        depth,
                    },
                    outcome: outcome.clone(),
                },
                &[node],
            );
            Some(outcome)
        })
        .collect::<Vec<_>>();
    if !rename && (0..resolved.len()).any(|index| resolved[index].is_some() && !current(index)) {
        complete = false;
        powershell_boundary(
            builder,
            node,
            &format!(
                "PowerShell {command} source changed earlier in the command, so what it holds is not modeled"
            ),
        );
    }
    // The entries a filtered wildcard reads or removes: those the listing
    // shows its pattern matches and its filters admit. Where the listing or a
    // reading of it leaves that open, the departure names every entry the
    // wildcard matches, including those the filters leave in place.
    let mut admitted = vec![None; resolved.len()];
    for index in 0..resolved.len() {
        let Some(ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob, .. },
        }) = &resolved[index]
        else {
            continue;
        };
        if !filtered {
            continue;
        }
        admitted[index] = match &listings[index] {
            Some(ObservationOutcome::Listing(listing)) => {
                admitted_entries(glob, &listing.entries, force, &admits)
            }
            _ => None,
        };
        if admitted[index].is_none() {
            complete = false;
            powershell_boundary(
                builder,
                node,
                &format!(
                    "PowerShell {command} filters are not applied to the source it reads or removes"
                ),
            );
        }
    }
    // Where each named source lands: under its own name in an existing
    // directory, as the destination itself where it is not one, and where
    // the host did not say which, possibly either. A move onto an existing
    // entry fails, replaces it (a file under -Force) or, across volumes,
    // merges into it; only a replaced file is established.
    let mut landings = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let (Some(source), Some((destination, resource, directory))) = (item, &target) else {
            landings.push(None);
            continue;
        };
        if rename || left_out[index] || wildcard(index) {
            landings.push(None);
            continue;
        }
        if *directory == Some(false) {
            landings.push(Some((resource.clone(), true)));
            continue;
        }
        let Some(name) = entry_name(source) else {
            landings.push(None);
            continue;
        };
        let separator = if destination.contains('\\') {
            '\\'
        } else {
            '/'
        };
        let child = format!(
            "{}{separator}{name}",
            destination.trim_end_matches(['\\', '/'])
        );
        let Some(landing) = resolved_path(builder, nest, &child, false, location, node, command)
        else {
            landings.push(None);
            continue;
        };
        // What already occupies the landing: `Some(None)` where nothing
        // does, `None` where the host did not answer. A link is what it
        // names, as PowerShell's File.Exists sees it.
        let occupant = match (&landing, copy || *directory != Some(true)) {
            (
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                },
                false,
            ) if observations && path.starts_with('/') => {
                match builder.budget().observe_path(path) {
                    ObservationOutcome::Path(fact) => match fact.kind {
                        PathKind::Missing => Some(None),
                        PathKind::Symlink => match &fact.followed {
                            Fact::Known(target) => target.kind.known().copied().map(Some),
                            Fact::Unavailable(_) => None,
                        },
                        kind => Some(Some(kind)),
                    },
                    ObservationOutcome::Listing(_) | ObservationOutcome::Refused(_) => None,
                }
            }
            _ => Some(None),
        };
        match occupant {
            Some(None) => landings.push(Some((landing, true))),
            // -Force replaces an existing file with a file, never a
            // directory.
            Some(Some(PathKind::File)) if force && source_kind(index) == Some(PathKind::File) => {
                landings.push(Some((landing, false)));
            }
            _ => {
                complete = false;
                powershell_boundary(
                    builder,
                    node,
                    &format!(
                        "PowerShell {command} destination entry exists or is unobserved, so whether the move fails, replaces or merges is not established"
                    ),
                );
                landings.push(None);
            }
        }
    }
    // The effect each source's content leaves through.
    let mut departures = Vec::new();
    for (resource, admitted) in resolved.iter().zip(&admitted) {
        let Some(resource) = resource.clone() else {
            departures.push(None);
            continue;
        };
        let resource = match admitted.as_deref() {
            None => resource,
            // Nothing the wildcard matches is admitted, so nothing departs.
            Some([]) => {
                departures.push(None);
                continue;
            }
            Some([path]) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: path.clone() },
            },
            Some(paths) => ResourceExpr::Union {
                alternatives: paths
                    .iter()
                    .map(|path| ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: path.clone() },
                    })
                    .collect(),
            },
        };
        departures.push(if copy {
            filesystem_effect(
                builder,
                "filesystem.read",
                resource,
                recursive_attributes(),
                node,
                model,
            )
        } else {
            let moved = filesystem_effect(
                builder,
                "filesystem.move",
                resource.clone(),
                Default::default(),
                node,
                model,
            );
            filesystem_effect(
                builder,
                "filesystem.delete",
                resource,
                Default::default(),
                node,
                model,
            );
            moved
        });
    }
    let Some((_, resource, directory)) = target else {
        return false;
    };
    let landing_path = |landing: &ResourceExpr| match landing {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    };
    // What each source lands beneath or instead of its landing: a wildcard
    // beneath the destination, a named source that brings its tree beneath
    // the entry it lands as.
    let shape = LandingShape {
        moves: !copy,
        tree,
        force,
        inside: directory == Some(true),
        filtered,
        admits: &admits,
        excludes: &excludes,
    };
    let landed = (0..items.len())
        .map(|index| {
            if rename || !builder.is_host_realm() {
                return None;
            }
            match &resolved[index] {
                Some(ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { glob, .. },
                }) if mirrors_wildcard(index) => Some(landed_entries(
                    Some((glob, wildcard_root(glob))),
                    source_kind(index),
                    listings[index].as_ref(),
                    &landing_path(&resource)?,
                    &shape,
                )),
                Some(ResourceExpr::Concrete { .. }) if tree && current(index) && !flattens => {
                    let (landing, true) = landings[index].as_ref()? else {
                        return None;
                    };
                    Some(landed_entries(
                        None,
                        source_kind(index),
                        listings[index].as_ref(),
                        &landing_path(landing)?,
                        &shape,
                    ))
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let withdrawn = |index: usize| {
        landed[index]
            .as_ref()
            .is_some_and(|landed| landed.withdrawn)
    };
    // The destination itself is written for every source but a wildcard whose
    // established selection lands only inside it, or nowhere.
    let written = if rename
        || (0..items.len())
            .any(|index| items[index].is_some() && !left_out[index] && !withdrawn(index))
    {
        filesystem_effect(
            builder,
            "filesystem.write",
            resource.clone(),
            recursive_attributes(),
            node,
            model,
        )
    } else {
        None
    };
    // A wildcard whose selection lands only inside the destination still
    // adds entries to it, and that write is the one endpoint its departure
    // reaches. `entries_only` states that the destination itself is not
    // what it writes: the entries are the writes listed beside it.
    let entries_written = if (0..items.len()).any(withdrawn) {
        let mut attributes = recursive_attributes();
        attributes.insert(
            "entries_only".into(),
            effinterp_proto::AttrValue::Bool(true),
        );
        filesystem_effect(
            builder,
            "filesystem.write",
            resource.clone(),
            attributes,
            node,
            model,
        )
    } else {
        None
    };
    for (index, departed) in departures.iter().enumerate() {
        let endpoint = if withdrawn(index) {
            entries_written
        } else {
            written
        };
        if let (Some(departed), Some(endpoint)) = (departed, endpoint) {
            builder.transfer_binding(TransferBinding::new(*departed, endpoint));
        }
    }
    if rename {
        return complete;
    }
    for (index, departed) in departures.iter().enumerate() {
        if !wildcard(index)
            && let Some((landing, _)) = &landings[index]
            && *landing != resource
        {
            let landed = filesystem_effect(
                builder,
                "filesystem.write",
                landing.clone(),
                recursive_attributes(),
                node,
                model,
            );
            // A move's one modeled endpoint is the destination it names; the
            // bridge reads several transfer destinations as an unknown
            // endpoint.
            if copy && let (Some(departed), Some(landed)) = (departed, landed) {
                builder.transfer_binding(TransferBinding::new(*departed, landed));
            }
        }
        let Some(landed) = &landed[index] else {
            continue;
        };
        let mut gaps = Vec::new();
        match landed.established {
            Ok(()) if landed.paths.len() > MAX_LANDED_ENTRIES => gaps.push(Unestablished::Model(
                "lands more entries than are written one by one, so its landing's subtree is written",
            )),
            Ok(()) => {}
            Err(gap) => gaps.push(gap),
        }
        if landed.uncertain {
            gaps.push(Unestablished::Model(
                "selects entries whose case or hidden-item matching on this host is not established, so every entry it may select is written",
            ));
        }
        for gap in gaps {
            complete = false;
            builder.boundary_with_coverage(
                match gap {
                    Unestablished::Unobserved => Boundary {
                        reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                        detail: Some(format!(
                            "PowerShell {command} source listing is unavailable, so what lands is not established"
                        )),
                        ..filesystem_model_gap(node, String::new())
                    },
                    Unestablished::Model(why) => {
                        filesystem_model_gap(node, format!("PowerShell {command} source {why}"))
                    }
                },
                CoverageLevel::Partial,
            );
        }
        // A source holding more than the engine lands one by one may write
        // anything beneath its landing.
        let overflow = (landed.paths.len() > MAX_LANDED_ENTRIES).then(|| ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath {
                glob: format!(
                    "{}/**",
                    crate::paths::escape_fs_glob_path(landed.landing.trim_end_matches('/'))
                ),
                narrowing: Default::default(),
            },
        });
        let resources = match overflow {
            Some(subtree) => vec![subtree],
            None => landed
                .paths
                .iter()
                .map(|path| ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: path.clone() },
                })
                .collect(),
        };
        for landed_resource in resources {
            let entry = filesystem_effect(
                builder,
                "filesystem.write",
                landed_resource,
                Default::default(),
                node,
                model,
            );
            if copy && let (Some(departed), Some(entry)) = (departed, entry) {
                builder.transfer_binding(TransferBinding::new(*departed, entry));
            }
        }
    }
    complete
}
