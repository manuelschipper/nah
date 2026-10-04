//! What a `Copy-Item`, `Move-Item` or `Rename-Item` source lands at its
//! destination: the landed entries, read from the host's listing of the
//! source, and why a landing is not established.

use std::collections::BTreeSet;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ListedEntry,
    ObservationOutcome, PathKind, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;

use super::wildcards::wildcard_selects;

/// How a copy or move lands what one source holds.
pub(super) struct LandingShape<'a> {
    pub(super) moves: bool,
    /// Everything beneath a landed directory lands too.
    pub(super) tree: bool,
    /// A wildcard selects hidden entries, and a move replaces an existing
    /// file, only under -Force.
    pub(super) force: bool,
    /// The destination is an existing directory, so a wildcard's entries land
    /// inside it under their own names.
    pub(super) inside: bool,
    /// -Include, -Exclude or -Filter is given.
    pub(super) filtered: bool,
    /// Whether those filters admit an entry name; `None` where the name
    /// cannot be matched.
    pub(super) admits: &'a dyn Fn(&str, bool) -> Option<bool>,
    /// Whether -Exclude alone names an entry.
    pub(super) excludes: &'a dyn Fn(&str, bool) -> Option<bool>,
}

/// Most entries one source lands as writes of their own. Past it the landing's
/// whole subtree is written instead, so a large tree cannot spend the effect
/// budget that later commands need.
pub(super) const MAX_LANDED_ENTRIES: usize = 1024;

/// What one copied or moved source lands.
pub(super) struct Landed {
    /// Where the source's entries land beneath.
    pub(super) landing: String,
    /// Every path an entry of the source is written to.
    pub(super) paths: BTreeSet<String>,
    /// The listing establishes everything that lands. Otherwise the landing
    /// stays written, `paths` are only the entries known to land, and the
    /// error says why.
    pub(super) established: Result<(), Unestablished>,
    /// Only entries are written, not the landing itself: an established
    /// wildcard selection lands only inside it, or is empty.
    pub(super) withdrawn: bool,
    /// An entry is selected only under one reading of PowerShell's case or
    /// hidden-item rule on this host, and is written.
    pub(super) uncertain: bool,
}

/// Why a copy or move does not establish what lands.
#[derive(Clone, Copy, Debug)]
pub(super) enum Unestablished {
    /// The host did not list the source.
    Unobserved,
    /// The listing is in hand, and what the command makes of it is not
    /// modeled; the text completes "PowerShell <command> source ...".
    Model(&'static str),
}

/// A filesystem boundary for what a command does that is not modeled.
pub(super) fn model_gap(node: ProvenanceRef, detail: String) -> Boundary {
    Boundary {
        reason: BoundaryReason::MODEL_COVERAGE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("filesystem")],
        provenance: vec![node],
        limit: None,
        detail: Some(detail),
    }
}

/// The entries a copy or move lands, from the host's listing of its source:
/// `kind` is what the source (a wildcard's root) is, `listing` the host's
/// answer for it when it is a directory.
///
/// A named source lands at `landing`, and everything beneath it at the same
/// relative path. Whether the filters also choose among what a named
/// directory holds is not established: an entry they admit, beneath
/// directories -Exclude does not name, lands either way, and any other is
/// left open. A
/// wildcard (`pattern`, the glob and the directory it selects beneath)
/// selects each entry the whole pattern matches and the filters admit. Inside
/// an existing directory each lands under its own name, with everything
/// beneath it under `tree`; a moved entry lands only as a file replacing what
/// is there under -Force, since a moved directory fails or merges on an
/// existing one. Elsewhere the entries replace or become the landing, which
/// is not modeled. A link or special file is not modeled either: what lands
/// for it depends on how the command treats it.
pub(super) fn landed_entries(
    pattern: Option<(&str, &str)>,
    kind: Option<PathKind>,
    listing: Option<&ObservationOutcome>,
    landing: &str,
    shape: &LandingShape<'_>,
) -> Landed {
    let open = |gap| Landed {
        landing: landing.to_owned(),
        paths: BTreeSet::new(),
        established: Err(gap),
        withdrawn: false,
        uncertain: false,
    };
    // Only a directory holds entries; a file or a missing entry holds none.
    let entries: &[ListedEntry] = match (kind, listing) {
        (Some(PathKind::Directory), Some(ObservationOutcome::Listing(fact))) => &fact.entries,
        (Some(PathKind::Directory), _) | (None, _) => return open(Unestablished::Unobserved),
        (Some(_), _) => &[],
    };
    let join = |relative: &str| format!("{}/{relative}", landing.trim_end_matches('/'));
    let special = |entry: &ListedEntry| !matches!(entry.kind, PathKind::File | PathKind::Directory);
    const SPECIAL: Unestablished =
        Unestablished::Model("reaches a link or special entry, whose copy or move is not modeled");
    let beneath = |root: &str| {
        let prefix = format!("{root}/");
        entries
            .iter()
            .filter(move |entry| entry.path.starts_with(&prefix))
    };
    let Some((glob, root)) = pattern else {
        let admitted = |entry: &&ListedEntry| {
            let (above, name) = entry.path.rsplit_once('/').unwrap_or(("", &entry.path));
            !shape.filtered
                || (shape.admits)(name, true) == Some(true)
                    && (shape.admits)(name, false) == Some(true)
                    && above
                        .split('/')
                        .filter(|name| !name.is_empty())
                        .all(|name| {
                            (shape.excludes)(name, true) == Some(false)
                                && (shape.excludes)(name, false) == Some(false)
                        })
        };
        return Landed {
            paths: entries
                .iter()
                .filter(admitted)
                .map(|entry| join(&entry.path))
                .collect(),
            established: if !entries.iter().all(|entry| admitted(&entry)) {
                Err(Unestablished::Model(
                    "holds entries its filters may leave out, which is not modeled",
                ))
            } else if entries.iter().any(special) {
                Err(SPECIAL)
            } else {
                Ok(())
            },
            ..open(Unestablished::Unobserved)
        };
    };
    let mut landed = Landed {
        established: Ok(()),
        ..open(Unestablished::Unobserved)
    };
    let unestablished = |landed: &mut Landed, gap| {
        if landed.established.is_ok() {
            landed.established = Err(gap);
        }
    };
    let mut selected = false;
    for entry in entries {
        let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
        let Some(selection) = wildcard_selects(glob, root, entry, shape.force, shape.admits) else {
            return open(Unestablished::Model(
                "wildcard or filters could not be matched, which is not modeled",
            ));
        };
        let Some(uncertain) = selection else {
            continue;
        };
        landed.uncertain |= uncertain;
        selected = true;
        if !shape.inside {
            continue;
        }
        if special(entry) || shape.tree && beneath(&entry.path).any(special) {
            unestablished(&mut landed, SPECIAL);
        }
        if shape.moves {
            if shape.force && entry.kind == PathKind::File {
                landed.paths.insert(join(name));
            } else {
                unestablished(
                    &mut landed,
                    Unestablished::Model(
                        "moves an entry that fails, replaces or merges with what the destination holds, which is not modeled",
                    ),
                );
            }
            continue;
        }
        landed.paths.insert(join(name));
        if shape.tree {
            landed.paths.extend(
                beneath(&entry.path)
                    .map(|below| join(&format!("{name}{}", &below.path[entry.path.len()..]))),
            );
        }
    }
    if selected && !shape.inside {
        unestablished(
            &mut landed,
            Unestablished::Model("entries replace or become the destination, which is not modeled"),
        );
    }
    landed.withdrawn = landed.established.is_ok() && (shape.inside || !selected);
    landed
}

/// Whether the host says a destination is a directory, or a link to one.
/// `None` where it was not asked or did not answer.
pub(super) fn observed_directory(
    builder: &mut PlanBuilder,
    resource: &ResourceExpr,
    node: ProvenanceRef,
) -> Option<bool> {
    use effinterp_proto::{Fact, ObservationOutcome, ObservationQuery, PathKind};
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = resource
    else {
        return None;
    };
    let budget = builder.budget();
    if budget.observations.is_none() || !builder.is_host_realm() || !path.starts_with('/') {
        return None;
    }
    let outcome = budget.observe_path(path);
    builder.node(
        ProvenanceKind::HostObservation {
            query: ObservationQuery::Path { path: path.clone() },
            outcome: outcome.clone(),
        },
        &[node],
    );
    match outcome {
        ObservationOutcome::Path(fact) => Some(match &fact.followed {
            Fact::Known(target) => target.kind == Fact::Known(PathKind::Directory),
            Fact::Unavailable(_) => fact.kind == PathKind::Directory,
        }),
        ObservationOutcome::Listing(_) | ObservationOutcome::Refused(_) => None,
    }
}

/// The name a source entry keeps when it lands in a directory: its last
/// path component.
pub(super) fn entry_name(source: &str) -> Option<&str> {
    let name = source
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()?;
    (!name.is_empty() && name != "." && name != ".." && name != "~").then_some(name)
}
