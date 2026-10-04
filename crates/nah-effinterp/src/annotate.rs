// Attaches nah identity labels to effect plans.

use effinterp_proto::{AttrValue, Effect, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::{AbsolutePath, Ctx, Platform};
use nah_proto::effect_annotation::{EffectAnnotation, PathLabel};
use nah_proto::effects::Knowledge;
use nah_proto::observation::{
    Observation, ObservationValue, Observed, PathKind, PathObservation, Root,
};
use nah_proto::runtime_protection::SelfProtectionProjection;

use nah_proto::labels::PathScope;
use nah_proto::labels::host_integrity::host_integrity_class;
use nah_proto::labels::scope::path_scope;
use nah_proto::labels::selects_home;
use nah_proto::labels::sensitivity::sensitivity;
use nah_proto::labels::tier;

use crate::observation_request::observation_bound;
use crate::plan_view::{PathSelection, PlanView};
use crate::runtime_cli;

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

pub(crate) struct PathLabelContext<'a> {
    pub(crate) platform: Platform,
    pub(crate) home: &'a AbsolutePath,
    pub(crate) trusted_roots: &'a [AbsolutePath],
    pub(crate) critical_paths: &'a [AbsolutePath],
}

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
    let (requested, path) = if let Some((original, outcome)) =
        crate::observation_request::effect_path_observation(plan, effect)
    {
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
    let sensitivity = sensitivity(requested, &selected_target, home, platform, pattern);
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
        requested,
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
        || selects_home(requested, home.as_str(), platform, pattern);
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
        },
    )
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
        path,
        &target,
        home,
        platform,
        false,
        effect.attributes.get("recursive") == Some(&AttrValue::Bool(true)),
    )
}

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
fn listed_selection(
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
    let followed = |path: &str| {
        links
            .iter()
            .filter(|(visible, _)| {
                path.strip_prefix(visible.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
            .max_by_key(|(visible, _)| visible.as_str().len())
            .map_or_else(
                || path.to_owned(),
                |(visible, target)| {
                    format!("{}{}", target.as_str(), &path[visible.as_str().len()..])
                },
            )
    };
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

pub(crate) fn annotate_process_with_authority(
    plan: &Plan,
    effect: &Effect,
    home: &AbsolutePath,
    platform: nah_proto::ctx::Platform,
) -> Option<String> {
    let (executable, _, argv) = process_argv(plan, effect)?;
    let literal = literal_argv(argv)?;
    let control = if nah_proto::labels::normalized_program(executable) == "nah" {
        nah_control(plan, effect, argv)
    } else {
        stated_control(plan, effect)
    };
    runtime_cli::recognize_runtime_cli(executable, &literal, control.is_some(), home, platform)
        .map(str::to_owned)
}

/// The entry id of the engine's model of Nah's own CLI
/// (`effinterp-engine/models/v1/tranche/command-state/nah.json`).
const NAH_MODEL: &str = "cli/nah@v1";

/// The provenance nodes where the engine applied its model of Nah's CLI to
/// this launch's program argument; empty when it analyzed the launch without it.
fn nah_model_applications(plan: &Plan, effect: &Effect) -> Vec<usize> {
    use effinterp_proto::ProvenanceKind::{Argument, Execution, ModelApplication};
    let node =
        |reference: &effinterp_proto::ProvenanceRef| plan.provenance.get(reference.0 as usize);
    plan.provenance
        .iter()
        .enumerate()
        .filter(|(_, application)| {
            matches!(&application.kind, ModelApplication { model }
            if model.split_once('#').map_or(model.as_str(), |(id, _)| id) == NAH_MODEL)
                && application
                    .antecedents
                    .iter()
                    .filter_map(node)
                    .any(|argument| {
                        matches!(argument.kind, Argument { index: 0 })
                    && argument.antecedents.iter().filter_map(node).any(|execution| {
                        matches!(execution.kind, Execution { node } if node == effect.execution.0)
                    })
                    })
        })
        .map(|(index, _)| index)
        .collect()
}

/// Whether the engine stated this effect through a model it applied although
/// PATH left the launched executable's identity unresolved. Self-protection
/// still reads such an effect's typed facts, but it does not establish what
/// the program touches for the other guards.
pub(crate) fn model_identity_unresolved(plan: &Plan, effect: &Effect) -> bool {
    let mut marked = Vec::with_capacity(plan.provenance.len());
    for node in &plan.provenance {
        marked.push(
            matches!(&node.kind, effinterp_proto::ProvenanceKind::ModelApplication { model }
                if model == effinterp_engine::UNRESOLVED_IDENTITY_MODEL)
                || node
                    .antecedents
                    .iter()
                    .any(|antecedent| marked.get(antecedent.0 as usize) == Some(&true)),
        );
    }
    effect
        .provenance
        .iter()
        .any(|reference| marked.get(reference.0 as usize) == Some(&true))
}

/// The change to Nah's own state or hook wiring that the engine's model of a
/// launched program states on the effects it gives that launch, as their
/// `nah_control` attribute. A nap suspends protection and is Permanent;
/// every other change is Critical.
fn stated_control(plan: &Plan, effect: &Effect) -> Option<nah_proto::labels::NahProtectionTier> {
    use nah_proto::labels::NahProtectionTier::{Critical, Permanent};
    plan.effects
        .iter()
        .filter(|candidate| candidate.execution == effect.execution && candidate.realm.is_host())
        .filter_map(|candidate| match candidate.attributes.get("nah_control") {
            Some(AttrValue::String(kind)) if kind == "nap" => Some(Permanent),
            Some(AttrValue::String(_)) => Some(Critical),
            _ => None,
        })
        .fold(None, |strongest, tier| {
            strongest_protection(strongest, Some(tier))
        })
}

/// The Nah control command a launch would run if its program is Nah. The
/// engine's model of Nah's CLI states it for a launch the engine analyzed with
/// that model. A launch it did not (a `nah` whose PATH it could not search, or
/// a program Nah may identify as its own binary under another name) takes the
/// tier of Nah's own command table over the literal prefix of its arguments,
/// so self-protection does not go silent where the engine is. Neither does
/// a launch whose arguments the model reports it could not recognize, such as
/// an unknown flag, which suppresses the model's stated changes.
pub(crate) fn nah_control(
    plan: &Plan,
    effect: &Effect,
    argv: &[ResourceExpr],
) -> Option<nah_proto::labels::NahProtectionTier> {
    let applications = nah_model_applications(plan, effect);
    let table = || nah_proto::labels::nah_prefix_protection_tier(&literal_words(argv));
    if applications.is_empty() {
        return table();
    }
    let unrecognized = plan.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .provenance
                .iter()
                .any(|node| applications.contains(&(node.0 as usize)))
    });
    let stated = stated_control(plan, effect);
    if unrecognized {
        strongest_protection(stated, table())
    } else {
        stated
    }
}

/// Selects the structural tier an executed process carries. A runtime's model
/// states a change to Nah's wiring, and Cargo's the binaries it installs or
/// removes. Nah's control commands (`nah_control`) count only for a process
/// identified as an installed nah binary. The identity is the engine's
/// resolved path, read through Nah's host observation of it when this plan
/// has not changed that path before the launch. `Unknown` means the arguments
/// would be a nah control command but the process could not be identified.
pub(crate) fn process_protection_tier(
    view: &PlanView<'_>,
    effect: &Effect,
) -> Knowledge<Option<nah_proto::labels::NahProtectionTier>> {
    let plan = view.plan();
    let Some((executable, path, argv)) = process_argv(plan, effect) else {
        return Knowledge::Known(None);
    };
    let executable =
        nah_proto::labels::package_launch_program(executable, launched_package(view, effect));
    let authority = view.authority();
    // Runtime and cargo invocations are recognized by the program they name.
    // A `nah` spelling is excluded here: Nah's control commands own it.
    let spelled_nah = nah_proto::labels::normalized_program(executable) == "nah";
    let literal = literal_argv(argv);
    if !spelled_nah
        && let Some(tier) = stated_control(plan, effect)
            .or_else(|| cargo_protection_tier(view, effect))
            .or_else(|| {
                let argv = literal.as_ref()?;
                nah_proto::runtime_protection::runtime_launch_bypass(
                    executable,
                    argv,
                    Some(authority.home().as_str()),
                    Some(authority.platform()),
                )
                .then_some(nah_proto::labels::NahProtectionTier::Critical)
            })
            .or_else(|| environment_protection_tier(view, effect, executable, literal.as_ref()?))
    {
        return Knowledge::Known(Some(tier));
    }
    // An argument the engine could not resolve (`nah guard disable "$X"`)
    // still leaves a program spelled `nah` its control command.
    let control = (literal.is_some() || spelled_nah)
        .then(|| nah_control(plan, effect, argv))
        .flatten();
    let Some(control) = control else {
        return Knowledge::Known(None);
    };
    let installed = |path: &str| {
        tier::is_installed_nah(
            path,
            authority.installed_executables(),
            authority.home(),
            authority.platform(),
        )
    };
    match path.map(|path| (path, executed_identity(view, effect, path))) {
        Some((path, _)) if installed(path) => Knowledge::Known(Some(control)),
        // A PATH search the engine certified names the realpath of the file it
        // selects, so that path is the identity.
        Some(_) if path_search_certified(plan, effect) => Knowledge::Known(None),
        Some((_, Some(identity))) if installed(identity) => Knowledge::Known(Some(control)),
        // On a Windows host a POSIX-rooted path such as `/usr/bin/nah` names
        // whatever the shell running it maps it to (Git Bash's mount table,
        // WSL, a terminal session elsewhere), not the entry at the root of the
        // cwd's drive that Nah observed, so that entry not being Nah does not
        // show the launch is not Nah. A `//` path is UNC.
        Some((path, Some(_)))
            if authority.platform() != nah_proto::ctx::Platform::Windows
                || !path.starts_with('/')
                || path.starts_with("//") =>
        {
            Knowledge::Known(None)
        }
        // Self-protection fails closed: a `nah` without an identity
        // certificate keeps the tier its spelling gave it, because treating it
        // as unrelated could let a real nah control command through, while
        // stopping an unrelated executable named `nah` costs little. That is a
        // bare `nah` whose PATH search certified nothing (PATH unknown, unset
        // or computed; nothing found; or a candidate this plan changed before
        // the launch, the host did not answer, or that is not an executable
        // file), and a path this plan rewrote before running it
        // (`cp other nah; ./nah trust`) or whose host observation failed.
        _ if spelled_nah => Knowledge::Known(Some(control)),
        _ => Knowledge::Unknown,
    }
}

/// The package operand a package launcher (`npx`, `bunx`, `bun x`, `pnpm dlx`)
/// ran this launch for: its argv[0], when the edge that created its execution
/// carries the engine's binary-inference certificate. An explicit command
/// (`npx --package=P -- CMD`) and any other launch have none, even one whose
/// path spells a package name.
fn launched_package<'a>(view: &PlanView<'a>, effect: &Effect) -> Option<&'a str> {
    let plan = view.plan();
    let edge = view.parent_edge(effect.execution)?;
    let launched = edge.kind == effinterp_proto::ExecutionEdgeKind::ToolModel
        && edge.evidence.iter().any(|reference| {
            matches!(
                plan.provenance.get(reference.0 as usize).map(|node| &node.kind),
                Some(effinterp_proto::ProvenanceKind::ModelApplication { model })
                    if model == effinterp_engine::PACKAGE_BINARY_INFERENCE_MODEL
            )
        });
    match plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)?
        .argv
        .first()?
    {
        ResourceExpr::Literal { value } if launched => Some(value),
        _ => None,
    }
}

/// Whether the engine's PATH search certified this launch's executable path.
fn path_search_certified(plan: &Plan, effect: &Effect) -> bool {
    effect.provenance.iter().any(|reference| {
        matches!(
            plan.provenance.get(reference.0 as usize).map(|node| &node.kind),
            Some(effinterp_proto::ProvenanceKind::ModelApplication { model })
                if model == effinterp_engine::PATH_SEARCH_MODEL
        )
    })
}

/// The file an executed path names, from Nah's host observation of it. That
/// observation describes the host before the plan runs, so it identifies the
/// launch only when no effect this plan orders before the launch writes,
/// creates, moves, deletes or mounts the path, a directory above it, or a
/// selection whose bounds are unknown. The engine has already replaced a path
/// this plan linked with the link's target. A path this plan last changed by
/// copying or hard-linking an installed nah binary onto it
/// (`cp nah alias; ./alias`, `cat nah > alias; ./alias`) names that binary,
/// identified as of the copy.
fn executed_identity<'a>(view: &PlanView<'a>, effect: &Effect, path: &str) -> Option<&'a str> {
    let platform = view.authority().platform();
    let change = view
        .plan()
        .effects
        .iter()
        .take_while(|earlier| !std::ptr::eq(*earlier, effect))
        .filter(|earlier| {
            earlier.realm.is_host()
                && earlier.operation.domain() == "filesystem"
                && !matches!(
                    earlier.operation.as_str(),
                    "filesystem.read" | "filesystem.metadata"
                )
        })
        .filter(|earlier| {
            crate::observation_request::observation_bound(&earlier.resource).is_none_or(
                |(bound, _)| {
                    nah_proto::labels::lexically_contains(&bound, path, platform)
                        || nah_proto::labels::lexically_contains(
                            observed_entry_path(view, &bound),
                            observed_entry_path(view, path),
                            platform,
                        )
                },
            )
        })
        .last();
    let Some(change) = change else {
        let observed = view.observed_path(path)?;
        return Some(observed.realpath().unwrap_or(observed.resolved()).as_str());
    };
    let installed = |path: &str| {
        tier::is_installed_nah(
            path,
            view.authority().installed_executables(),
            view.authority().home(),
            platform,
        )
    };
    // A copy establishes only that the path is Nah. Several files copied
    // onto one path leave any of them there, and a source that is not Nah
    // leaves the launch as unidentified as any other rewritten path, so a
    // program spelled `nah` still fails closed.
    transferred_sources(view, change, path)
        .into_iter()
        .filter_map(|source| {
            if installed(source) {
                Some(source)
            } else {
                executed_identity(view, change, source)
            }
        })
        .find(|identity| installed(identity))
}

/// The files whose content `change`, a write or creation of exactly `path`,
/// puts there: the sources of the copy or hard link the engine modeled as a
/// resource transfer into it, or the one file a verbatim stream copy writes
/// there (`stream_copy_source`). Empty when `change` is any other kind of
/// change or covers more than that one path.
fn transferred_sources<'a>(view: &PlanView<'a>, change: &'a Effect, path: &str) -> Vec<&'a str> {
    let platform = view.authority().platform();
    let names_path = matches!(
        &change.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: written },
        } if nah_proto::labels::lexical_path::same_path(written, path, platform)
            || nah_proto::labels::lexical_path::same_path(
                observed_entry_path(view, written),
                observed_entry_path(view, path),
                platform,
            )
    );
    if !names_path
        || !matches!(
            change.operation.as_str(),
            "filesystem.write" | "filesystem.create"
        )
    {
        return Vec::new();
    }
    if !transfer_lands(view, change, path) {
        return Vec::new();
    }
    let written: Vec<_> = view
        .occurrences_for_execution(change.execution)
        .filter(|node| {
            node.realm == change.realm
                && node.condition == change.condition
                && node.provenance == change.provenance
                && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    ..
                } if operation == &change.operation && resource == &change.resource)
        })
        .collect();
    let transferred: Vec<&str> = written
        .iter()
        .flat_map(|node| view.incoming_edges(&node.id))
        .filter(|edge| edge.reason == effinterp_proto::CausalReason::ResourceTransfer)
        .filter_map(|edge| view.causal_node(&edge.from))
        .filter_map(|source| match &source.occurrence {
            effinterp_proto::OccurrenceKind::ResourceInteraction {
                operation,
                resource:
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    },
                ..
            } if source.realm.is_host() && operation.as_str() == "filesystem.read" => {
                Some(path.as_str())
            }
            _ => None,
        })
        .collect();
    if !transferred.is_empty() {
        return transferred;
    }
    match written.as_slice() {
        [written] => stream_copy_source(view, change, written)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// The one file whose bytes `change` writes unchanged through standard
/// streams: `cat nah > alias`, `cat nah | tee alias`, `tee alias < nah`.
/// Such a write leaves the file's content at the written path as a copy
/// does, although the engine models it as a flow, not a transfer.
///
/// An exact causal edge states that the output depends on the input, not
/// that it equals it (`base64 nah > alias` has one too), so every process
/// whose standard output the bytes pass through must be one that copies
/// its input verbatim (`copies_verbatim`). Every dependency on the way must
/// be exact, the write must replace the file rather than append to it, and
/// exactly one file may feed it: two files, or standard input the call
/// inherits, leave content no single file names.
fn stream_copy_source<'a>(
    view: &PlanView<'a>,
    change: &Effect,
    written: &'a effinterp_proto::OccurrenceNode,
) -> Option<&'a str> {
    use effinterp_proto::{CausalAssurance, CausalReason, OccurrenceKind, Port};
    if change.operation.as_str() != "filesystem.write"
        || change.attributes.get("append") == Some(&AttrValue::Bool(true))
    {
        return None;
    }
    let inputs = |node: &'a effinterp_proto::OccurrenceNode| {
        view.incoming_edges(&node.id)
            .filter(|edge| edge.reason == CausalReason::ValueDependency)
            .filter_map(|edge| Some((edge, view.causal_node(&edge.from)?)))
    };
    let mut sources = std::collections::BTreeSet::new();
    let mut reached = std::collections::BTreeSet::new();
    let mut conservative = Vec::new();
    let mut pending = vec![written];
    while let Some(node) = pending.pop() {
        if !reached.insert(&node.id) {
            continue;
        }
        match &node.occurrence {
            _ if std::ptr::eq(node, written) => {}
            OccurrenceKind::ResourceInteraction {
                operation,
                resource:
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    },
                ..
            } if node.realm.is_host() && operation.as_str() == "filesystem.read" => {
                sources.insert(path.as_str());
                continue;
            }
            OccurrenceKind::Port { port: Port::Stdout } => {
                if !copies_verbatim(view, node.execution?) {
                    return None;
                }
            }
            OccurrenceKind::Port { port: Port::Stdin } => {}
            _ => return None,
        }
        let mut exact = Vec::new();
        for (edge, from) in inputs(node) {
            // What a process adds to its own output; a verbatim copier adds
            // nothing.
            if from.execution == node.execution
                && matches!(&from.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.as_str() == "process.exec")
            {
                continue;
            }
            if edge.assurance == CausalAssurance::Exact {
                exact.push(from);
            } else {
                conservative.push(&from.id);
            }
        }
        // A redirection replaces the standard input its command would
        // otherwise inherit from the call, so that inherited input is left
        // out only where it meets a redirection at a standard input. Reached
        // anywhere else (`cat nah - > alias`) it is input no file names.
        if exact.len() > 1 && matches!(&node.occurrence, OccurrenceKind::Port { port: Port::Stdin })
        {
            exact.retain(|from| {
                !matches!(&from.occurrence, OccurrenceKind::Port { port: Port::Stdin })
                    || inputs(from).next().is_some()
            });
        }
        if exact.is_empty() {
            return None;
        }
        pending.extend(exact);
    }
    // A conservative dependency on something the exact flow does not pass
    // through may add or change bytes.
    if conservative.iter().any(|id| !reached.contains(id)) {
        return None;
    }
    let mut sources = sources.into_iter();
    sources.next().filter(|_| sources.next().is_none())
}

/// Whether the process writes exactly its input to its standard output:
/// `tee`, or `cat` without an option that numbers, squeezes or marks what it
/// prints.
fn copies_verbatim(view: &PlanView<'_>, execution: effinterp_proto::ExecutionNodeRef) -> bool {
    let Some(words) = literal_argv(&view.execution(execution).argv) else {
        return false;
    };
    let mut words = words.iter();
    match words.next().and_then(|program| program.rsplit('/').next()) {
        Some("tee") => true,
        Some("cat") => words
            .take_while(|word| *word != "--")
            .all(|word| !word.starts_with('-') || matches!(word.as_str(), "-" | "-u")),
        _ => false,
    }
}

/// `path` as its host observation resolved it, with the directory links
/// above it followed, so `/tmp/x` and `/private/tmp/x` compare equal.
fn observed_entry_path<'a>(view: &PlanView<'a>, path: &'a str) -> &'a str {
    view.observed_entry(path)
        .map_or(path, |observed| observed.resolved().as_str())
}

/// Whether the copy or link that `change` records can have put its source at
/// `path`. The engine names the destination operand as written and marks no
/// refusal, so the bridge rules out what it can see: a destination that is a
/// directory (the copy lands under it), a parent that is not the copy's
/// working directory, not observed and not created earlier in the plan (the
/// copy fails), and a `cp` or `mv` that
/// keeps an existing destination (`-n`) or replaces only an older one (`-u`),
/// which lands for certain only on a path that did not exist. BSD `cp` and
/// `mv` reject `-u`.
fn transfer_lands(view: &PlanView<'_>, change: &Effect, path: &str) -> bool {
    use nah_proto::observation::PathKind;
    let platform = view.authority().platform();
    let observed = view.observed_entry(path).map(|observed| observed.kind());
    if observed == Some(PathKind::Directory) {
        return false;
    }
    let Some(parent) = crate::observation_request::parent_directory(path) else {
        return false;
    };
    // The copying process runs in its working directory, so that exists.
    let runs_in_parent = matches!(
        view.execution(change.execution).cwd,
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: cwd },
        }) if nah_proto::labels::lexical_path::same_path(cwd, parent, platform)
    );
    let parent_exists = runs_in_parent
        || view.observed_directory(parent)
        || view
            .plan()
            .effects
            .iter()
            .take_while(|earlier| !std::ptr::eq(*earlier, change))
            .any(|earlier| {
                earlier.operation.as_str() == "filesystem.create"
                    && matches!(
                        &earlier.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: created },
                        } if nah_proto::labels::lexical_path::same_path(created, parent, platform)
                    )
            });
    if !parent_exists {
        return false;
    }
    let words = literal_words(&view.execution(change.execution).argv);
    let mut words = words.iter().flatten();
    let copies = words
        .next()
        .is_some_and(|program| matches!(program.rsplit('/').next(), Some("cp" | "mv")));
    let (mut keeps, mut updates) = (false, false);
    for word in words.take_while(|word| *word != "--") {
        match word.strip_prefix("--") {
            Some(long) => {
                keeps |= long == "no-clobber";
                updates |= long == "update" || long.starts_with("update=");
            }
            // A cluster of single-letter flags; `-t` and `-S` take the rest
            // of their word as a value.
            None if word.starts_with('-') => {
                let flags = word[1..].split(['t', 'S']).next().unwrap_or_default();
                keeps |= flags.contains('n');
                updates |= flags.contains('u');
            }
            None => {}
        }
    }
    if !copies || !(keeps || updates) {
        return true;
    }
    observed == Some(PathKind::Missing) && !(updates && platform == nah_proto::ctx::Platform::Macos)
}

/// Cargo replacing or removing Nah's binary. An uninstall removes it when it
/// selects Nah's package or a binary named `nah`, and one that asks for either
/// still counts when the install root's registry does not record it, a
/// `--config` leaves that root unknown, or an option the model does not read
/// is present. A binary named `nah` counts by its stated name, whatever root
/// Cargo computes.
/// An install writes it when it selects Nah's package, Nah's source tree or a
/// binary named `nah`, and the binary directory is an ancestor of protected
/// Nah state or already holds one of Nah's standard installed binaries (such
/// as `/usr/local/bin/nah` under `--root /usr/local`), which the install
/// replaces even though that directory was never observed. Cargo's model
/// states the selection on each binary it writes or removes.
fn cargo_protection_tier(
    view: &PlanView<'_>,
    effect: &Effect,
) -> Option<nah_proto::labels::NahProtectionTier> {
    use nah_proto::labels::lexical_path::{
        installed_binary_paths, join_lexical_path, lexically_normalized, same_path,
    };
    let authority = view.authority();
    let (home, platform) = (authority.home().as_str(), authority.platform());
    let binary = if platform == nah_proto::ctx::Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    let installed = installed_binary_paths(home, platform);
    fn text<'a>(candidate: &'a Effect, key: &str) -> Option<&'a str> {
        match candidate.attributes.get(key) {
            Some(AttrValue::String(value)) => Some(value.as_str()),
            _ => None,
        }
    }
    view.plan()
        .effects
        .iter()
        .any(|candidate| {
            if candidate.execution != effect.execution
                || !candidate.realm.is_host()
                || text(candidate, "package_manager") != Some("cargo")
            {
                return false;
            }
            let path = match &candidate.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some(path.as_str()),
                _ => None,
            };
            // The binary directory, when the selection is Nah's binary.
            let selection = text(candidate, "selection");
            let directory = match selection {
                Some("package_binaries" | "installed_binaries") => text(candidate, "package")
                    .is_some_and(nah_proto::labels::nah_package_spec)
                    .then_some(path),
                Some("requested") => (text(candidate, "package")
                    .is_some_and(nah_proto::labels::nah_package_spec)
                    || text(candidate, "binary") == Some("nah"))
                .then_some(path),
                Some("manifest_binaries") => text(candidate, "source_path")
                    .is_some_and(nah_proto::labels::nah_source_path)
                    .then_some(path),
                Some("named") => (text(candidate, "binary") == Some("nah")).then(|| {
                    path.and_then(|path| path.rsplit_once(['/', '\\']))
                        .map(|(directory, _)| directory)
                }),
                _ => None,
            };
            let Some(directory) = directory else {
                return false;
            };
            match candidate.operation.as_str() {
                "filesystem.delete" => true,
                // An uninstall asked to remove Nah counts even when Cargo will
                // refuse it or the root it removes from is unknown.
                "filesystem.read" => selection == Some("requested"),
                "filesystem.write" => directory.is_some_and(|directory| {
                    nah_proto::labels::protected_path_ancestor(
                        directory,
                        home,
                        authority.critical_paths(),
                        platform,
                    ) || installed.iter().any(|installed| {
                        same_path(
                            installed,
                            &lexically_normalized(
                                &join_lexical_path(directory, binary, platform),
                                platform,
                            ),
                            platform,
                        )
                    })
                }),
                _ => false,
            }
        })
        .then_some(nah_proto::labels::NahProtectionTier::Critical)
}

/// Classifies the hook bypass a runtime's launch environment configures. The
/// execution node states the environment the child actually receives, and the
/// analyzed subject states the environment it inherited.
fn environment_protection_tier(
    view: &PlanView<'_>,
    effect: &Effect,
    executable: &str,
    argv: &[String],
) -> Option<nah_proto::labels::NahProtectionTier> {
    if nah_proto::labels::runtime_terminal_information(argv) {
        return None;
    }
    let plan = view.plan();
    let node = view.execution(effect.execution);
    let configured = |name: &str| match node.environment.get(name) {
        Some(Some(ResourceExpr::Literal { value })) => Some(value.as_str()),
        _ => None,
    };
    let inherited = |name: &str| {
        subject_context(&plan.subject).and_then(|context| context.env.get(name).map(String::as_str))
    };
    let cwd = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { cwd: Some(cwd), .. },
        } => match cwd.as_ref() {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        },
        _ => None,
    };
    nah_proto::runtime_protection::environment_operation(
        executable,
        configured,
        inherited,
        view.authority().home().as_str(),
        cwd,
        view.authority().critical_paths(),
        view.authority().platform(),
    )
    .map(|_| nah_proto::labels::NahProtectionTier::Critical)
}

fn subject_context(subject: &effinterp_proto::Subject) -> Option<&effinterp_proto::HostContext> {
    use effinterp_proto::Subject;
    match subject {
        Subject::Exec { context, .. }
        | Subject::Shell { context, .. }
        | Subject::Source { context, .. }
        | Subject::ToolCall { context, .. } => Some(context),
        Subject::Sql { .. } => None,
    }
}

/// The structural tier of a program typed into another terminal and not yet
/// submitted. Only a program spelled `nah` is classified: the receiver's PATH
/// decides which file that name runs, and nothing here observes it.
pub(crate) fn terminal_input_tier(effect: &Effect) -> Option<nah_proto::labels::NahProtectionTier> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::Process {
            executable, argv, ..
        },
    } = &effect.resource
    else {
        return None;
    };
    if nah_proto::labels::normalized_program(executable) != "nah" {
        return None;
    }
    nah_proto::labels::nah_prefix_protection_tier(&literal_words(argv))
}

/// A launched process's program, spelled path and argument expressions.
fn process_argv<'a>(
    plan: &'a Plan,
    effect: &'a Effect,
) -> Option<(&'a str, Option<&'a str>, &'a [ResourceExpr])> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::Process {
                executable,
                path,
                argv,
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let argv = if argv.is_empty() {
        plan.execution_graph
            .nodes
            .get(effect.execution.0 as usize)
            .map(|node| node.argv.as_slice())
            .unwrap_or_default()
    } else {
        argv
    };
    Some((executable, path.as_deref(), argv))
}

fn literal_argv(argv: &[ResourceExpr]) -> Option<Vec<String>> {
    literal_words(argv).into_iter().collect()
}

/// Each argument's literal text, `None` for an argument that is not a literal.
fn literal_words(argv: &[ResourceExpr]) -> Vec<Option<String>> {
    argv.iter()
        .map(|argument| match argument {
            ResourceExpr::Literal { value } => Some(value.clone()),
            _ => None,
        })
        .collect()
}

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
