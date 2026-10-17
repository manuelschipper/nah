// Attaches nah identity labels to effect plans.

use effinterp_proto::{AttrValue, Effect, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::{AbsolutePath, Ctx, Platform};
use nah_proto::effect_annotation::{EffectAnnotation, PathLabel};
use nah_proto::observation::{
    Observation, ObservationValue, Observed, PathKind, PathObservation, Root,
};
use nah_proto::runtime_protection::SelfProtectionProjection;

use nah_proto::labels::PathScope;
use nah_proto::labels::host_integrity::host_integrity_class;
use nah_proto::labels::scope::path_scope;
use nah_proto::labels::sensitivity::sensitivity;
use nah_proto::labels::tier;
use nah_proto::labels::{selects_home, selects_home_folder};

use crate::observation_request::observation_bound;
use crate::plan_view::{PathSelection, PlanView};

mod executed_identity;
pub(crate) mod listed_selection;
pub(crate) mod process_protection;

use listed_selection::listed_selection;

/// The annotation of every plan effect, in plan order, as a projection of the
/// plan records it.
pub fn annotate_plan_effects(
    plan: &Plan,
    observation: &Observation,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
) -> Result<Vec<EffectAnnotation>, nah_proto::ctx::CtxError> {
    let view = PlanView::new(plan, observation, ctx, self_protection)?;
    Ok(view.annotations())
}

/// The host facts a path label is judged against: the platform, the home
/// directory, the roots the user trusts and the paths self-protection holds
/// critical.
pub(crate) struct PathLabelContext<'a> {
    pub(crate) platform: Platform,
    pub(crate) home: &'a AbsolutePath,
    pub(crate) trusted_roots: &'a [AbsolutePath],
    pub(crate) critical_paths: &'a [AbsolutePath],
}

/// The path label of the selection one filesystem effect makes: its scope,
/// sensitivity, protection tier and host-integrity class, and whether the
/// label is of the entry or of the target its links lead to.
///
/// `observed` is the host observation of the path that bounds the selection
/// (`observation_bound`). The observation the plan itself recorded for the
/// effect is labeled when there is one, and `observed` must then agree with
/// it. With neither, or when they disagree, the label is `Unresolved`: the
/// path is unknown, never unlabeled. `selection` states which of the two is
/// labeled; `None` takes the followed target, except for a deletion of a
/// named symbolic link, which takes the entry.
pub(crate) fn annotate_path_relation(
    plan: &Plan,
    effect: &Effect,
    observed: Option<&PathObservation>,
    roots: &[Root],
    context: PathLabelContext<'_>,
    selection: Option<PathSelection>,
) -> (PathSelection, PathLabel) {
    let PathLabelContext {
        platform,
        home,
        trusted_roots,
        critical_paths,
    } = context;
    let (requested, pattern) = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => (path.as_str(), false),
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. },
        } => (pattern.as_str(), true),
        resource => match crate::observation_request::subtree_root(resource) {
            Some(root) => (root, false),
            None => {
                return (
                    selection.unwrap_or(PathSelection::FollowedTarget),
                    PathLabel::Unresolved,
                );
            }
        },
    };
    // A subset its producer chose by a test that names nothing may be empty
    // and is never all of the pattern's matches, so the pattern's reach says
    // nothing of what the effect takes.
    let subset = crate::observation_request::selection_narrowing(&effect.resource)
        .map(|narrowing| narrowing.subset)
        .unwrap_or_default();
    if subset == effinterp_proto::FsSubset::Unnamed {
        return (
            selection.unwrap_or(PathSelection::FollowedTarget),
            PathLabel::Unresolved,
        );
    }
    let Some((query_path, selection_suffix)) = observation_bound(&effect.resource) else {
        return (
            selection.unwrap_or(PathSelection::FollowedTarget),
            PathLabel::Unresolved,
        );
    };
    let recorded;
    // The engine ran out of requests before it could ask about this path. It
    // drew no conclusion from an answer, so the bridge's own observation of
    // the path stands as it does for an effect the engine never asked about,
    // and a private key spelled `~/.ssh/id_rsa` keeps its label.
    let engine_answer = crate::observation_request::effect_path_observation(plan, effect)
        .filter(|(_, outcome)| !crate::observation_request::refused_by_limit(outcome));
    let (requested, path) = if let Some((original, outcome)) = engine_answer {
        let effinterp_proto::ObservationOutcome::Path(fact) = outcome else {
            return (
                selection.unwrap_or(PathSelection::FollowedTarget),
                PathLabel::Unresolved,
            );
        };
        // A symlink's entry cannot stand in for a refused followed identity.
        if fact.kind == effinterp_proto::PathKind::Symlink && fact.followed.known().is_none() {
            return (
                selection.unwrap_or(PathSelection::FollowedTarget),
                PathLabel::Unresolved,
            );
        }
        let Some(value) = crate::observation_request::recorded_path(fact, platform) else {
            return (
                selection.unwrap_or(PathSelection::FollowedTarget),
                PathLabel::Unresolved,
            );
        };
        recorded = value;
        // Missing later identity is not a contradiction of the recorded answer.
        if let Some(later) = observed.and_then(PathObservation::realpath)
            && Some(later) != recorded.realpath()
        {
            return (
                selection.unwrap_or(PathSelection::FollowedTarget),
                PathLabel::Unresolved,
            );
        }
        (original, &recorded)
    } else {
        let Some(path) = observed else {
            return (
                selection.unwrap_or(PathSelection::FollowedTarget),
                PathLabel::Unresolved,
            );
        };
        (requested, path)
    };
    let access_control = access_control_change(effect);
    let operation = filesystem_operation(effect);
    let selection = selection.unwrap_or_else(|| {
        if !pattern && operation == FilesystemOperation::Delete && path.kind() == PathKind::Symlink
        {
            PathSelection::Entry
        } else {
            PathSelection::FollowedTarget
        }
    });
    let target = match selection {
        PathSelection::Entry => path.resolved().clone(),
        PathSelection::FollowedTarget => path.realpath().unwrap_or_else(|| path.resolved()).clone(),
    };
    let scope = path_scope(&target, roots, home, platform);
    let recursive = effect.attributes.get("recursive") == Some(&AttrValue::Bool(true));
    // The observed directory bounds a pattern; it is not itself selected.
    // Retain the suffix when labeling the canonical spelling so HOME/* does
    // not acquire effects on hidden children merely because HOME was observed.
    // The glob text after its bound. A bound spelled with escapes is not a
    // prefix of the glob's text, so the decoded bound's own suffix stands in.
    let pattern_suffix = requested.strip_prefix(query_path.as_ref()).or_else(|| {
        matches!(
            &effect.resource,
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
            } if glob == requested
        )
        .then_some(selection_suffix)
    });
    // A subset chosen by the names its glob spells is labeled by those
    // names. The listing, when there is one, still reads the glob as it is.
    let listed_suffix = pattern_suffix;
    let named = crate::observation_request::named_subset_reading(&effect.resource, requested).map(
        |requested| {
            (
                requested,
                pattern_suffix.map(|suffix| suffix.replace("/**/", "/")),
            )
        },
    );
    let (requested, pattern_suffix) = match &named {
        Some((requested, suffix)) => (requested.as_str(), suffix.as_deref()),
        None => (requested, pattern_suffix),
    };
    let selected_target = if pattern {
        let Some(suffix) = pattern_suffix else {
            return (selection, PathLabel::Unresolved);
        };
        let Ok(selected) = AbsolutePath::new(platform, format!("{}{suffix}", target.as_str()))
        else {
            return (selection, PathLabel::Unresolved);
        };
        selected
    } else {
        target.clone()
    };
    // The engine names an effect by its entry, every parent directory
    // resolved, and states the path the command spelled when the two differ.
    // The lexical classes read that spelling beside the resolved target, so
    // `~/.ssh/authorized_keys` keeps its class where `~/.ssh` is a link.
    let spelled = match &named {
        Some(_) => requested,
        None => spelled_path(effect).unwrap_or(requested),
    };
    let sensitivity = sensitivity(spelled, &selected_target, home, platform, pattern);
    // Recursive metadata mutation takes the whole container: a stated
    // access-control action (chmod -R, chown -R), one applied to a directory
    // and its whole subtree (find DIR -exec chmod ... {}), or a metadata write.
    // Only the exact two-member union of DIR and DIR/** counts as the whole
    // subtree. This relies on effinterp-engine's find model
    // (`models/find.rs`), which emits that union once per root the tests may
    // select and states on it the entry kinds and names that -type and
    // ! -name leave out; the tier reads that narrowing below. It emits no
    // bounded selection for a HOME search with -path.
    let subtree = crate::observation_request::subtree_root(&effect.resource).is_some();
    let whole_container = operation == FilesystemOperation::Delete
        || access_control && (recursive || subtree)
        || recursive && effect.attributes.get("metadata") == Some(&AttrValue::Bool(true));
    let unnarrowed = effinterp_proto::FsNarrowing::default();
    let narrowing =
        crate::observation_request::selection_narrowing(&effect.resource).unwrap_or(&unnarrowed);
    // The narrowing says which entries the operation is applied to. One that
    // reaches inside what it is applied to takes the entries the narrowing
    // left out as well: a recursive operation, a move or the removal it
    // states for what it moved away, which carry a directory's contents with
    // them, or an access-control change that does not provably keep a
    // directory's contents usable. A removal that does not recurse (`rm`,
    // `unlink`, `rmdir`) leaves a directory's contents where they are, so it
    // keeps the narrowing.
    let applied_narrowing = if recursive
        || operation == FilesystemOperation::Delete
            && !crate::observation_request::removes_entries_only(plan, effect)
        || effect.operation.as_str() == "filesystem.move"
        || access_control && !keeps_enclosed_access(effect)
    {
        &unnarrowed
    } else {
        narrowing
    };
    let tier_of = |operation| {
        tier::nah_narrowed_protection_tier(
            operation,
            &selected_target,
            &selected_target,
            roots,
            trusted_roots,
            home,
            critical_paths,
            platform,
            pattern,
            whole_container,
            applied_narrowing,
        )
    };
    // Revoking access to a directory takes away everything inside it, so an
    // access-control change carries the tier of the paths it encloses as well
    // as its own, unless its literal mode provably keeps them usable.
    let protection = if access_control {
        let enclosed = (recursive || subtree || pattern || !keeps_enclosed_access(effect))
            .then(|| tier_of(FilesystemOperation::Delete))
            .flatten();
        strongest_protection(tier_of(operation), enclosed)
    } else {
        tier_of(operation)
    };
    let host_integrity = host_integrity_class(
        operation,
        spelled,
        &selected_target,
        home,
        platform,
        pattern,
        recursive,
    );
    // A removal across a root-wide selection takes every file below its
    // root, as one of the pattern `ROOT/**` does, although the operation does
    // not recurse: `find ~/.ssh -type f -exec rm {} +` removes the keys and
    // leaves the directory. A selection that leaves out names or regular
    // files is not read this way, since the classes do not say which entry
    // kinds and names they protect.
    let removes_files = subtree
        && operation == FilesystemOperation::Delete
        && narrowing.excluded_names.is_empty()
        && (narrowing.kinds.is_empty()
            || narrowing
                .kinds
                .contains(&effinterp_proto::FsEntryKind::File));
    let host_integrity = host_integrity.max(
        removes_files
            .then(|| {
                let below = format!("{}/**", target.as_str().trim_end_matches('/'));
                let selected = AbsolutePath::new(platform, below.as_str()).ok()?;
                host_integrity_class(
                    operation, &below, &selected, home, platform, true, recursive,
                )
            })
            .flatten(),
    );
    // A name selected at any depth reaches the listed entries it matches,
    // not every protected path that shares the literal prefix before its
    // `**`: `HOME/**/.cache` does not reach `~/.ssh`, and `HOME/**/.ss*`
    // does.
    // A root-wide selection is its root and every entry below it. Where its
    // producer says it takes symbolic links (`find -L`, `find -type l`), the
    // listing adds what they lead to exactly as it does for `ROOT/**`.
    let takes_links = subtree
        && narrowing
            .kinds
            .contains(&effinterp_proto::FsEntryKind::Symlink);
    let selection_listing = (pattern || takes_links)
        .then(|| {
            listed_selection(
                if pattern { listed_suffix } else { Some("/**") },
                observed,
                &target,
                platform,
                operation == FilesystemOperation::Delete
                    || effect.operation.as_str() == "filesystem.move",
                operation == FilesystemOperation::Delete,
                operation == FilesystemOperation::Delete && !recursive,
                crate::observation_request::writes_through_links(effect, &effect.resource),
            )
        })
        .flatten();
    let (protection, host_integrity) = match &selection_listing {
        Some((whole, members)) => {
            let (listed_protection, listed_host_integrity) = (
                members
                    .iter()
                    .map(|member| {
                        let tier_of = |operation| {
                            tier::nah_protection_tier(
                                operation,
                                member,
                                member,
                                roots,
                                trusted_roots,
                                home,
                                critical_paths,
                                platform,
                                false,
                                whole_container,
                            )
                        };
                        if access_control {
                            strongest_protection(
                                tier_of(operation),
                                tier_of(FilesystemOperation::Delete),
                            )
                        } else {
                            tier_of(operation)
                        }
                    })
                    .fold(None, strongest_protection),
                members
                    .iter()
                    .filter_map(|member| {
                        host_integrity_class(
                            operation,
                            member.as_str(),
                            member,
                            home,
                            platform,
                            false,
                            recursive,
                        )
                    })
                    .max(),
            );
            // Every entry below the bound stays reached by the pattern itself;
            // the listing adds what its links lead to.
            if *whole {
                (
                    strongest_protection(protection, listed_protection),
                    host_integrity.max(listed_host_integrity),
                )
            } else {
                (listed_protection, listed_host_integrity)
            }
        }
        None => (protection, host_integrity),
    };
    // A write through a matched link changes the file the link leads to, so
    // it carries that file's sensitivity as a write to the named link does.
    let sensitivity = match &selection_listing {
        Some((_, members))
            if sensitivity == nah_proto::labels::Sensitivity::None
                && crate::observation_request::writes_through_links(effect, &effect.resource) =>
        {
            members
                .iter()
                .map(|member| {
                    nah_proto::labels::sensitivity::sensitivity(
                        member.as_str(),
                        member,
                        home,
                        platform,
                        false,
                    )
                })
                .find(|value| *value != nah_proto::labels::Sensitivity::None)
                .unwrap_or(sensitivity)
        }
        _ => sensitivity,
    };
    let selects_root = matches!(&scope, PathScope::Project { root } if root == &target);
    let selects_home = selects_home(target.as_str(), home.as_str(), platform, false)
        || selects_home(spelled, home.as_str(), platform, pattern);
    let selects_home_folder = selects_home_folder(target.as_str(), home.as_str(), platform, false)
        || selects_home_folder(spelled, home.as_str(), platform, pattern);
    (
        selection,
        PathLabel::Resolved {
            path: target,
            scope,
            sensitivity,
            protection,
            host_integrity,
            selects_root,
            selects_home,
            selects_home_folder,
        },
    )
}

/// The path the command spelled, where the engine renamed the effect's
/// resource from it (`spelled_path`, set in `PlanBuilder::effect`).
pub(crate) fn spelled_path(effect: &Effect) -> Option<&str> {
    match effect.attributes.get("spelled_path") {
        Some(AttrValue::String(path)) => Some(path),
        _ => None,
    }
}

/// The host-integrity class a concrete path effect reaches by its spelling
/// alone. It stands in when the host could not observe the path (an unreadable
/// parent such as `/etc/sudoers.d`): the spelling still names a protected
/// surface, so the class holds even without the followed identity. `None`
/// establishes nothing; it is not evidence that no class applies.
pub(crate) fn lexical_host_integrity(
    effect: &Effect,
    home: &AbsolutePath,
    platform: Platform,
) -> Option<nah_proto::labels::HostIntegrityClass> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = &effect.resource
    else {
        return None;
    };
    let target = AbsolutePath::new(platform, path.as_str()).ok()?;
    host_integrity_class(
        filesystem_operation(effect),
        spelled_path(effect).unwrap_or(path),
        &target,
        home,
        platform,
        false,
        effect.attributes.get("recursive") == Some(&AttrValue::Bool(true)),
    )
}

/// The stronger of two protection tiers: Permanent over Critical over
/// Proposal. `NahProtectionTier` declares no order of its own.
fn strongest_protection(
    left: Option<nah_proto::labels::NahProtectionTier>,
    right: Option<nah_proto::labels::NahProtectionTier>,
) -> Option<nah_proto::labels::NahProtectionTier> {
    use nah_proto::labels::NahProtectionTier::{Critical, Permanent, Proposal};
    match (left, right) {
        (Some(Permanent), _) | (_, Some(Permanent)) => Some(Permanent),
        (Some(Critical), _) | (_, Some(Critical)) => Some(Critical),
        (Some(Proposal), _) | (_, Some(Proposal)) => Some(Proposal),
        (None, None) => None,
    }
}

/// Reports whether the effect states a permission or ownership change. A bare
/// metadata effect does not say whether it reads or mutates, so only a stated
/// access-control action counts.
pub(crate) fn access_control_change(effect: &Effect) -> bool {
    effect.operation.as_str() == "filesystem.metadata"
        && matches!(
            effect.attributes.get("action"),
            Some(AttrValue::String(action))
                if matches!(action.as_str(), "chmod" | "chown" | "chgrp" | "chattr" | "setfacl")
        )
}

/// Whether a chmod's literal octal `spec` leaves the entries a directory
/// encloses as reachable and as safe as before. Nah observes no ownership, so
/// the account that runs Nah may be the owner, in the group, or neither (a
/// root-owned `/usr/local/bin`): every class keeps search, the owner keeps
/// read and write too, neither group nor others may write, so no one else can
/// replace what it holds, and no setuid, setgid or sticky bit is set.
/// chmod(1) applies a numeric mode exactly, whatever the umask. A symbolic
/// mode depends on the prior mode, so it never qualifies.
fn keeps_enclosed_access(effect: &Effect) -> bool {
    matches!(effect.attributes.get("action"), Some(AttrValue::String(action)) if action == "chmod")
        && matches!(
            effect.attributes.get("spec"),
            Some(AttrValue::String(spec))
                if !spec.is_empty()
                    && spec.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
                    && u32::from_str_radix(spec, 8)
                        .is_ok_and(|mode| mode & 0o711 == 0o711 && mode & 0o7022 == 0)
        )
}

/// The filesystem operation a path effect is labeled as. A stated
/// access-control change is a write, a bare metadata effect a read, and any
/// operation that is neither a read nor a delete a write.
fn filesystem_operation(effect: &Effect) -> FilesystemOperation {
    if access_control_change(effect) {
        return FilesystemOperation::Write;
    }
    match effect.operation.as_str().rsplit('.').next() {
        Some("read" | "metadata") => FilesystemOperation::Read,
        Some("delete" | "remove") => FilesystemOperation::Delete,
        _ => FilesystemOperation::Write,
    }
}

/// The project roots the observation found; empty when it holds no
/// successful roots answer.
pub(crate) fn observed_roots(observation: &Observation) -> Vec<Root> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Roots {
                observed: Observed::Ok { value },
            } => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_default()
}
