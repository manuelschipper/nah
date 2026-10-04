//! PowerShell `Remove-Item`: the entries each bound path deletes, with
//! `-Recurse`, wildcards and the `-Include`, `-Exclude` and `-Filter` filters.

use effinterp_proto::{
    ObservationOutcome, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
    ResourcePattern,
};

use crate::builder::PlanBuilder;
use crate::nest::Nest;

use super::cmdlet_parameters::{REMOVE_ITEM, bind_cmdlet_parameters};
use super::path_resolution::{
    binds_single_path, filesystem_effect, names_location_or_ancestor, resolved_path,
};
use super::ps_words::PsWord;
use super::wildcards::{admitted_entries, filters_admit, glob_components_below, wildcard_root};
use super::{Session, powershell_boundary};

/// `Remove-Item`: a delete of each path it binds, relative to the session
/// `location`. Returns whether the removal was fully understood.
pub(super) fn remove_item(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let bound = match bind_cmdlet_parameters(arguments, &REMOVE_ITEM) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let (paths, wildcards) = match bound.paths("Path") {
        Ok(Some(paths)) => paths,
        Ok(None) => {
            powershell_boundary(builder, node, "PowerShell Remove-Item has no literal path");
            return false;
        }
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let what_if = bound.switch("WhatIf");
    // Removing an item of the alias or function drive deletes that
    // definition, so the name stops resolving to what it named.
    let definitions = paths
        .iter()
        .filter_map(|path| {
            let (drive, name) = path.split_once(':')?;
            let alias = drive.eq_ignore_ascii_case("alias");
            (alias || drive.eq_ignore_ascii_case("function"))
                .then(|| (alias, name.trim_start_matches(['\\', '/'])))
        })
        .collect::<Vec<_>>();
    if !definitions.is_empty() {
        if !what_if {
            for (alias, name) in definitions {
                if alias {
                    session.define_alias(name);
                } else {
                    session.shadow(name);
                }
            }
        }
        return bound.complete(builder, node, "Remove-Item");
    }
    // -WhatIf reports the deletion instead of performing it.
    if what_if {
        return bound.complete(builder, node, "Remove-Item");
    }
    let mut complete =
        bound.complete(builder, node, "Remove-Item") & binds_single_path(builder, node, paths);
    let recursive = bound.switch("Recurse");
    // -Include, -Exclude and -Filter admit items by name. A wildcard removes
    // the entries they admit among those the host lists for it, as a filtered
    // Move-Item's source departs (`admitted_entries`). Under -Recurse an
    // entry -Exclude leaves in place is not entered, and each admitted entry
    // is removed with everything beneath it. Whether -Include and -Filter
    // also find entries beneath one they do not admit, and how the filters
    // apply to a path without a wildcard, is not established: the removal
    // then names everything the path does, and a boundary says the filters
    // were not applied.
    let filters = [
        bound.values("Include"),
        bound.values("Exclude"),
        bound.values("Filter"),
    ];
    let filtered = filters.iter().any(Option::is_some);
    let admits = |name: &str, fold: bool| filters_admit(&filters, name, fold);
    let force = bound.switch("Force");
    let unmodeled_before = builder.budget().unmodeled_steps();
    let mut removed = Vec::new();
    for path in paths {
        let Some(resource) = resolved_path(
            builder,
            nest,
            path,
            wildcards,
            location,
            node,
            "Remove-Item",
        ) else {
            complete = false;
            continue;
        };
        // PowerShell refuses to remove the current location or one of its
        // ancestors (RemoveItemInUse) before it touches any child, whatever
        // -Recurse and -Force say.
        if location.is_some_and(|location| names_location_or_ancestor(&resource, location)) {
            continue;
        }
        if !filtered {
            removed.push(resource);
            continue;
        }
        // Every host question is asked before any removal: a removal leaves
        // the host's later answers undecided.
        let admitted = match &resource {
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            } if (!recursive || filters[0].is_none() && filters[2].is_none())
                && builder.is_host_realm() =>
            {
                let root = wildcard_root(glob).to_string();
                let depth = Some(glob_components_below(glob, &root));
                let outcome = builder
                    .budget()
                    .observe_listing(&root, depth, unmodeled_before);
                builder.node(
                    ProvenanceKind::HostObservation {
                        query: effinterp_proto::ObservationQuery::Listing { path: root, depth },
                        outcome: outcome.clone(),
                    },
                    &[node],
                );
                match outcome {
                    ObservationOutcome::Listing(listing) => {
                        admitted_entries(glob, &listing.entries, force, &admits)
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        match admitted {
            Some(paths) => removed.extend(paths.into_iter().map(|path| ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            })),
            None => {
                complete = false;
                powershell_boundary(
                    builder,
                    node,
                    "PowerShell Remove-Item filters are not applied to what it removes",
                );
                removed.push(resource);
            }
        }
    }
    for resource in removed {
        filesystem_effect(
            builder,
            "filesystem.delete",
            resource,
            [(
                "recursive".into(),
                effinterp_proto::AttrValue::Bool(recursive),
            )]
            .into(),
            node,
            "powershell/remove-item@v1",
        );
    }
    complete
}
