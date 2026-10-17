//! Which sensitivity labels a selection's content carries, and how they
//! propagate along exact content and alias relations to later reads.

use nah_proto::effects;
use nah_proto::effects::Knowledge::{Known, Unknown};
use nah_proto::observation::Observation;
use std::collections::{BTreeMap, BTreeSet};

use super::content_flow::clone_fact_occurrences;
use super::fact_projection::EffectProjection;
use super::invocation_calls::add_gap;
use super::observed_labels::ObservedLabels;
use super::recursive_read_filters::{
    excluded_name_list, excludes_component, honoured_ignores, ignore_rules_stand,
    observed_ignored_entries, observed_unset, path_below_observed_root, skipped_by_excluded_names,
    skipped_by_ignore_files, skipped_by_path_filters, skipped_by_search_filters,
};
use super::resource_projection::unconditionally_selects_path;

/// Label each selection's content, propagate the labels along the relations
/// that preserve content, and return the labels the shipped guards read.
pub(super) fn propagate_sensitivity<'a>(
    view: &'a crate::plan_view::PlanView<'a>,
    observation: &'a Observation,
    invocation_cwd: &'a str,
    git_config_credentials: &BTreeMap<String, Option<bool>>,
    native_search_reads_ignore_files: bool,
    graph: &mut effects::EffectGraph,
    effects: &EffectProjection,
) -> ObservedLabels<'a> {
    use effects::{
        CallId, Certainty, Domain, FactId, FactPayload, FilesystemOperation, GapPhase, Reach,
        RelationKind, ResourceId, ResourceKind,
    };
    let plan = view.plan();
    let EffectProjection {
        member_effects,
        effect_resources,
        effect_facts,
        ..
    } = effects;
    // Sensitivity belongs to the selected content. Observed descendants can
    // supply it without claiming that an incomplete scan found a secret file.
    let mut sensitivities = vec![Vec::new(); graph.occurrences.len()];
    let mut selected_sensitivities = Vec::new();
    let mut observed_labels = ObservedLabels {
        view,
        observation,
        invocation_cwd,
        paths: BTreeMap::new(),
        directories: BTreeMap::new(),
        selections: Vec::new(),
    };
    let platform = view.authority().platform();
    // The runtime's search tool leaves out what ignore files name unless a
    // ripgrep configuration file may turn that off.
    let native_search_ignores = native_search_reads_ignore_files
        && observed_unset(
            observation,
            super::input_selection::RIPGREP_CONFIGURATION_VARIABLE,
        );
    // What each earlier effect copied, for the later reads of the copy.
    let mut copies = Vec::<CopiedContent>::new();
    for (index, effect) in plan
        .effects
        .iter()
        .chain(member_effects.iter().map(|(_, effect)| effect))
        .enumerate()
    {
        // The plan lists effects in the order the invocation reaches them; a
        // union's member stands where its owner does.
        let order = if index < plan.effects.len() {
            index
        } else {
            member_effects[index - plan.effects.len()].0
        };
        // An unconditional overwrite or delete ends the bytes an earlier copy
        // left at that path, so a later read of it takes none of them. The
        // engine names a copy into a directory as a write of that directory:
        // a write that is itself a copy's destination adds an entry beside
        // the copied ones, which stand. Any other write to the destination
        // replaces a copied file.
        if effect.condition.is_none()
            && let effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } = &effect.resource
            && matches!(
                effect.operation.as_str(),
                "filesystem.write" | "filesystem.delete"
            )
        {
            let deletes = effect.operation.as_str() == "filesystem.delete";
            let copies_into = graph.relations.iter().any(|relation| {
                relation.kind == RelationKind::ContentPreservingTransfer
                    && graph.occurrences[relation.to.0 as usize].fact == Some(effect_facts[index])
            });
            copies.retain_mut(|copy| {
                if copy.written >= order || *copy.realm != effect.realm {
                    return true;
                }
                if deletes
                    && nah_proto::labels::lexically_contains(path, copy.destination, platform)
                    || !deletes
                        && !copies_into
                        && nah_proto::labels::lexical_path::same_path(
                            path,
                            copy.destination,
                            platform,
                        )
                {
                    return false;
                }
                let named = copy.entries.len();
                let destination = copy.destination;
                copy.entries.retain(|entry| {
                    !nah_proto::labels::lexical_path::same_path(
                        &copied_entry_path(destination, entry),
                        path,
                        platform,
                    )
                });
                named == 0 || !copy.entries.is_empty()
            });
        }
        let target = effect_resources[index];
        let Some(labels) = &graph.resources[target.0 as usize].labels else {
            continue;
        };
        let mut selected = match labels.sensitivity {
            Known(value) if value != nah_proto::labels::Sensitivity::None => vec![value],
            _ => vec![],
        };
        // What this effect alone reads: through links, or as the copy an
        // earlier effect wrote. Other effects on the same directory do not
        // inherit it.
        let mut through_links = Vec::new();
        // The names of the entries a glob selects that carry a label.
        let mut labeled_entries = BTreeSet::new();
        // The paths, below the tree a recursive read takes, of the entries
        // that carry a label or are links leading to one that does, each
        // with that label. A copy of the tree keeps each under the same
        // relative path, and a copied link still leads to its target.
        let mut tree_entries = Vec::new();
        // The observed root of that tree.
        let mut tree_root = None;
        // One listing answers every effect on its path, following links when
        // any of them does. Only an effect that itself reads through a link
        // takes what the link leads to.
        let reads_through_links = crate::observation_request::reads_through_links(effect);
        // A move takes everything under what it names, so its content is the
        // observed entries exactly as a recursive read's is.
        if matches!(
            effect.operation.as_str(),
            "filesystem.read" | "filesystem.move"
        ) && (effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true))
                || crate::observation_request::subtree_root(&effect.resource).is_some()
                || effect.operation.as_str() == "filesystem.move"
                // A glob's content is the entries it selects, not the
                // directory word that bounds it.
                || matches!(&effect.resource, effinterp_proto::ResourceExpr::Pattern { .. }))
        {
            let observed = crate::observation_request::observation_bound(&effect.resource)
                .and_then(|(path, _)| view.observed_path_for(effect, &path));
            tree_root = observed;
            if let Some(descendants) = observed.and_then(|path| path.descendants()) {
                let mut unselected = observed
                    .map(|root| skipped_by_path_filters(effect, root, descendants.paths()))
                    .unwrap_or_default();
                if let Some(root) = observed {
                    unselected.extend(skipped_by_search_filters(effect, root, descendants.paths()));
                    // The ignored entries were observed before the invocation
                    // runs, so they stand only while nothing else it does
                    // changes them.
                    if effect.realm.is_host()
                        && let Some(honoured) = honoured_ignores(effect, native_search_ignores)
                        && let effinterp_proto::ResourceExpr::Concrete {
                            identity: effinterp_proto::ResourceIdentity::FsPath { path },
                        } = &effect.resource
                        && let Some(ignored) = observed_ignored_entries(observation, path)
                        && ignore_rules_stand(view, reads_through_links, ignored.rule_files())
                    {
                        unselected.extend(skipped_by_ignore_files(
                            effect,
                            honoured,
                            root,
                            descendants.paths(),
                            ignored,
                        ));
                    }
                }
                for path in descendants.paths() {
                    if observed.is_some_and(|root| skipped_by_excluded_names(effect, root, path))
                        || unselected.contains(path)
                    {
                        continue;
                    }
                    if unconditionally_selects_path(effect, path, view.authority().platform())
                        || labels
                            .reach
                            .iter()
                            .any(|entry| entry.identity == *path && entry.reach == Reach::Yes)
                    {
                        // An entry a link-following listing reached through a
                        // link holds the bytes of the path that link leads
                        // to, whatever the entry's own name says.
                        let followed = reads_through_links
                            .then(|| {
                                crate::annotate::listed_selection::followed_through_links(
                                    descendants.links(),
                                    path.as_str(),
                                )
                            })
                            .flatten()
                            .and_then(|followed| {
                                nah_proto::ctx::AbsolutePath::new(
                                    view.authority().platform(),
                                    followed,
                                )
                                .ok()
                            });
                        for (labeled, found) in std::iter::once((path, &mut selected))
                            .chain(followed.as_ref().map(|path| (path, &mut through_links)))
                        {
                            let value = nah_proto::labels::sensitivity::sensitivity(
                                labeled.as_str(),
                                labeled,
                                view.authority().home(),
                                view.authority().platform(),
                                false,
                            );
                            if value == nah_proto::labels::Sensitivity::None {
                                continue;
                            }
                            labeled_entries.insert(entry_name(path.as_str()).to_owned());
                            if !found.contains(&value) {
                                found.push(value);
                            }
                        }
                        let label = |path: &nah_proto::ctx::AbsolutePath| {
                            nah_proto::labels::sensitivity::sensitivity(
                                path.as_str(),
                                path,
                                view.authority().home(),
                                platform,
                                false,
                            )
                        };
                        if let Some(below) =
                            observed.and_then(|root| path_below_observed_root(root, path))
                        {
                            tree_entries.extend(
                                std::iter::once(label(path))
                                    .chain(
                                        crate::annotate::listed_selection::followed_through_links(
                                            descendants.links(),
                                            path.as_str(),
                                        )
                                        .and_then(|target| {
                                            nah_proto::ctx::AbsolutePath::new(platform, target).ok()
                                        })
                                        .map(|target| label(&target)),
                                    )
                                    .filter(|value| *value != nah_proto::labels::Sensitivity::None)
                                    .map(|value| (value, below.to_owned())),
                            );
                        }
                    }
                }
            }
            // A listed entry the pattern may or may not select, such as one
            // under an extglob group that cannot be enumerated, is unknown
            // content: neither labeled nor shown to be left out.
            if observed
                .and_then(|path| path.descendants())
                .is_some_and(|descendants| {
                    descendants.paths().iter().any(|path| {
                        labels
                            .reach
                            .iter()
                            .any(|entry| entry.identity == *path && entry.reach == Reach::Unknown)
                    })
                })
            {
                add_gap(
                    graph,
                    CallId(effect.execution.0),
                    Some(Domain::Filesystem),
                    GapPhase::Translation,
                    "pattern-selection-unavailable",
                );
            }
            if observed
                .and_then(|path| path.descendants())
                .is_none_or(|descendants| !descendants.complete())
            {
                // An incomplete scan proves neither secret content nor hard
                // links; it leaves the gap, not a sensitivity label.
                graph.resources[target.0 as usize]
                    .labels
                    .as_mut()
                    .unwrap()
                    .descendants_complete = Known(false);
                add_gap(
                    graph,
                    CallId(effect.execution.0),
                    Some(Domain::Filesystem),
                    GapPhase::Observation,
                    "descendant-scan-incomplete",
                );
            }
            // A path a move names is listed without following links, and a
            // reader of the same path reads a second listing that follows
            // them (`plan_observation_request`). A reader the move's listing
            // answers instead, because it comes after the move or the second
            // listing failed, saw none of what an unfollowed link there leads
            // to. A move's own read, its copy half, takes the link as the
            // move does.
            let moves_listing = crate::observation_request::observation_bound(&effect.resource)
                .and_then(|(path, _)| view.observed_path(&path));
            if reads_through_links
                && effect.operation.as_str() == "filesystem.read"
                && observed
                    .zip(moves_listing)
                    .is_some_and(|(read, moved)| std::ptr::eq(read, moved))
                && observed
                    .and_then(|path| path.descendants())
                    .is_some_and(|descendants| descendants.unlisted_entries())
                && !crate::observation_request::stated_by_move(plan, effect)
                && plan.effects.iter().any(|moved| {
                    moved.operation.as_str() == "filesystem.move"
                        && crate::observation_request::observation_bound(&moved.resource)
                            .map(|(path, _)| path)
                            == crate::observation_request::observation_bound(&effect.resource)
                                .map(|(path, _)| path)
                })
            {
                add_gap(
                    graph,
                    CallId(effect.execution.0),
                    Some(Domain::Filesystem),
                    GapPhase::Observation,
                    "descendant-scan-incomplete",
                );
            }
        }
        let reads = matches!(
            effect.operation.as_str(),
            "filesystem.read" | "filesystem.move"
        );
        // A repository's configuration carries no label by its path
        // (`labels::sensitivity`): it is a secret source only when the bytes
        // served for it hold a credential. Bytes that were not served prove
        // neither, so that read is a gap rather than a clean one.
        if reads
            && effect.realm.is_host()
            && let effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } = &effect.resource
            && (nah_proto::labels::git_config::is_git_config_path(path, platform)
                || git_config_credentials.contains_key(path))
        {
            match git_config_credentials.get(path) {
                Some(Some(true)) => {
                    if !selected.contains(&nah_proto::labels::Sensitivity::OtherSensitive) {
                        selected.push(nah_proto::labels::Sensitivity::OtherSensitive);
                    }
                }
                Some(Some(false)) => {}
                _ => add_gap(
                    graph,
                    CallId(effect.execution.0),
                    Some(Domain::Filesystem),
                    GapPhase::Observation,
                    "observation-unavailable",
                ),
            }
        }
        // A label follows the content: a read that selects the copy an
        // earlier effect wrote reads what that effect read, whatever the
        // copy is named and whether or not this read follows links.
        let mut copied = false;
        if reads {
            for copy in &copies {
                if copy.written < order
                    && *copy.realm == effect.realm
                    && copy.selected_by(view, effect, platform)
                {
                    copied = true;
                    // A glob that selects copied entries copies them on
                    // under the same names.
                    if let effinterp_proto::ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
                    } = &effect.resource
                    {
                        labeled_entries.extend(
                            copy.entries
                                .iter()
                                .filter(|entry| {
                                    effinterp_proto::glob_match(
                                        glob,
                                        &copied_entry_path(copy.destination, entry),
                                    ) == Ok(true)
                                })
                                .cloned(),
                        );
                    }
                    for value in &copy.labels {
                        if !through_links.contains(value) {
                            through_links.push(*value);
                        }
                    }
                }
            }
        }
        // Where this read's own content transfer wrote what it read. The
        // engine names a copy's destination without the entry it creates
        // there, so the entry names are the ones the content was read under.
        let carried = selected
            .iter()
            .chain(&through_links)
            .copied()
            .collect::<Vec<_>>();
        if reads && !carried.is_empty() && index < plan.effects.len() {
            let entries =
                match &effect.resource {
                    effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    } if effect.attributes.get("recursive")
                        != Some(&effinterp_proto::AttrValue::Bool(true)) =>
                    {
                        // The path a link was followed from names the copy, not
                        // the path the engine resolved it to.
                        let spelled = plan
                        .provenance
                        .iter()
                        .filter_map(|node| match &node.kind {
                            effinterp_proto::ProvenanceKind::HostObservation {
                                query: effinterp_proto::ObservationQuery::Path { path: spelled },
                                outcome: effinterp_proto::ObservationOutcome::Path(fact),
                            } if fact.followed.known().is_some_and(|target| target.path == *path)
                                && node
                                    .antecedents
                                    .iter()
                                    .any(|reference| effect.provenance.contains(reference)) =>
                            {
                                Some(entry_name(spelled).to_owned())
                            }
                            _ => None,
                        })
                        .collect::<BTreeSet<_>>();
                        if spelled.is_empty() {
                            BTreeSet::from([entry_name(path).to_owned()])
                        } else {
                            spelled
                        }
                    }
                    effinterp_proto::ResourceExpr::Pattern { .. } => labeled_entries,
                    _ => BTreeSet::new(),
                };
            let tree = matches!(
                &effect.resource,
                effinterp_proto::ResourceExpr::Concrete { .. }
            ) && effect.attributes.get("recursive")
                == Some(&effinterp_proto::AttrValue::Bool(true));
            // A move states its transfer on the delete it pairs with, which
            // names the same source in the same execution.
            let sources = plan
                .effects
                .iter()
                .enumerate()
                .filter(|(_, source)| {
                    source.execution == effect.execution && source.resource == effect.resource
                })
                .map(|(source, _)| effect_facts[source])
                .collect::<Vec<_>>();
            for relation in &graph.relations {
                if relation.kind != RelationKind::ContentPreservingTransfer
                    || !graph.occurrences[relation.from.0 as usize]
                        .fact
                        .is_some_and(|fact| sources.contains(&fact))
                {
                    continue;
                }
                let Some(written) = graph.occurrences[relation.to.0 as usize]
                    .fact
                    .and_then(|fact| effect_facts.iter().position(|id| *id == fact))
                    .filter(|written| *written < plan.effects.len())
                else {
                    continue;
                };
                let destination = &plan.effects[written];
                if let effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } = &destination.resource
                    && matches!(
                        destination.operation.as_str(),
                        "filesystem.write" | "filesystem.create"
                    )
                    && destination.realm == effect.realm
                {
                    if tree {
                        // Each label rides the tree's own entries, so a later
                        // read that skips `.env` takes nothing from it.
                        copies.extend(carried.iter().map(|label| {
                            CopiedContent {
                                written,
                                realm: &effect.realm,
                                destination: path,
                                entries: tree_entries
                                    .iter()
                                    .filter(|(value, _)| value == label)
                                    .map(|(_, entry)| entry.clone())
                                    .collect(),
                                tree,
                                source: tree_root,
                                labels: vec![*label],
                            }
                        }));
                    } else {
                        copies.push(CopiedContent {
                            written,
                            realm: &effect.realm,
                            destination: path,
                            entries: entries.clone(),
                            tree,
                            source: None,
                            labels: carried.clone(),
                        });
                    }
                }
            }
        }
        let shared = selected.clone();
        through_links.retain(|value| !shared.contains(value));
        selected.extend(through_links.iter().copied());
        // A path the observation does not answer for keeps its own labels
        // unknown. What a read takes from an earlier copy is known whatever
        // the path holds, as it is for a directory created in the same call.
        if effect.realm.is_host()
            && let Some(labels) = &graph.resources[target.0 as usize].labels
            && (labels.sensitivity != Unknown || copied)
        {
            // A finite union's member labels its owner's selection.
            let owner = &plan.effects[order].id;
            match &effect.resource {
                effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } => {
                    if labels.sensitivity != Unknown {
                        observed_labels.record_path_labels(owner, path, labels, &shared);
                    }
                    observed_labels.record_labels_through_links(owner, path, &through_links);
                }
                selection @ effinterp_proto::ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { .. },
                } => observed_labels.record_selection_labels(owner, selection, labels, &selected),
                selection if crate::observation_request::subtree_root(selection).is_some() => {
                    observed_labels.record_selection_labels(owner, selection, labels, &selected)
                }
                _ => {}
            }
        }
        let fact = effect_facts[index];
        for occurrence in &graph.occurrences {
            if occurrence.fact == Some(fact)
                && occurrence.condition.is_none()
                && graph.facts[fact.0 as usize].certainty == Certainty::Exact
                && graph.facts[fact.0 as usize].condition.is_none()
            {
                // Relations carry only what the path itself holds: what
                // this effect read through links stays with its own fact.
                sensitivities[occurrence.id.0 as usize] = shared.clone();
            }
        }
        selected_sensitivities.push((fact, selected));
    }
    // Content and alias certificates can carry labels to a later selected read.
    // Ordinary conservative byte edges and conditional edges prove no such route.
    loop {
        let mut changed = false;
        for relation in &graph.relations {
            let from = &graph.occurrences[relation.from.0 as usize];
            let to = &graph.occurrences[relation.to.0 as usize];
            if relation.certainty != Certainty::Exact
                || relation.condition.is_some()
                || from.condition.is_some()
                || to.condition.is_some()
            {
                continue;
            }
            let eligible = match relation.kind {
                // A state that the plan separately carries into a delete or
                // overwrite cannot label a later read through a parallel
                // content edge: that mutation ended the selected bytes.
                RelationKind::ContentPreservingTransfer => !graph.relations.iter().any(|edge| {
                    edge.from == from.id
                        && edge.kind == RelationKind::StateTransition
                        && edge.condition.is_none()
                        && graph.occurrences[edge.to.0 as usize]
                            .fact
                            .is_some_and(|id| {
                                matches!(
                                    graph.facts[id.0 as usize].payload,
                                    FactPayload::FilesystemAccess {
                                        operation: FilesystemOperation::Delete
                                            | FilesystemOperation::Write,
                                        ..
                                    }
                                )
                            })
                }),
                RelationKind::Alias => true,
                RelationKind::StateTransition => {
                    from.resource.zip(to.resource).is_some_and(|(a, b)| {
                        let a = &graph.resources[a.0 as usize];
                        let b = &graph.resources[b.0 as usize];
                        a.realm == b.realm
                            && a.identity.kind == ResourceKind::HostPath
                            && a.identity.name != Unknown
                            && a.identity == b.identity
                    })
                }
                _ => false,
            };
            if !eligible {
                continue;
            }
            for value in sensitivities[from.id.0 as usize].clone() {
                let destination = &mut sensitivities[to.id.0 as usize];
                if !destination.contains(&value) {
                    destination.push(value);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    for (id, mut selected) in selected_sensitivities {
        let original = graph.facts[id.0 as usize].clone();
        let FactPayload::FilesystemAccess {
            operation: FilesystemOperation::Read | FilesystemOperation::Move,
            target,
            ..
        } = original.payload
        else {
            continue;
        };
        for occurrence in &graph.occurrences {
            if occurrence.fact == Some(id) {
                for value in &sensitivities[occurrence.id.0 as usize] {
                    if !selected.contains(value) {
                        selected.push(*value);
                    }
                }
            }
        }
        for value in selected {
            let mut resource = graph.resources[target.0 as usize].clone();
            if resource
                .labels
                .as_ref()
                .is_some_and(|labels| labels.sensitivity == Known(value))
            {
                continue;
            }
            resource.id = ResourceId(graph.resources.len() as u32);
            resource.labels.as_mut().unwrap().sensitivity = Known(value);
            let mut fact = original.clone();
            fact.id = FactId(graph.facts.len() as u32);
            if let FactPayload::FilesystemAccess { target, .. } = &mut fact.payload {
                *target = resource.id;
            }
            clone_fact_occurrences(graph, id, fact.id, Some(resource.id));
            graph.resources.push(resource);
            graph.facts.push(fact);
        }
    }
    observed_labels
}

/// The content one effect's read transferred into a path it wrote, with the
/// labels that content carries.
struct CopiedContent<'a> {
    /// The plan index of the effect that wrote the copy.
    written: usize,
    realm: &'a effinterp_proto::ExecutionRealm,
    /// The path the write names: the copy itself, or the directory it was
    /// copied into.
    destination: &'a str,
    /// The names the content keeps when `destination` is a directory: a
    /// copied file's name, or the paths below a copied tree of its labeled
    /// entries and of its links to one. Empty when the read names none.
    entries: BTreeSet<String>,
    /// The copy is of a whole tree, so `destination` is a directory and its
    /// content is `entries`, never the directory itself.
    tree: bool,
    /// The observed root of a copied tree, whose listing shows which of the
    /// copy's entries are files.
    source: Option<&'a nah_proto::observation::PathObservation>,
    labels: Vec<nah_proto::labels::Sensitivity>,
}

impl CopiedContent<'_> {
    /// Whether `effect` selects the copy: one of its entries by path or by
    /// glob, or a tree that holds the destination. A read of the destination
    /// path itself is already tied to the write by the engine's own flow.
    fn selected_by(
        &self,
        view: &crate::plan_view::PlanView<'_>,
        effect: &effinterp_proto::Effect,
        platform: nah_proto::ctx::Platform,
    ) -> bool {
        // The copy is named as its writer spelled it, and a reader by the
        // path its observation resolved, so a destination below a linked
        // directory (`/tmp` on macOS) is compared as resolved too.
        let resolved = view
            .observed_entry(self.destination)
            .map(|observed| observed.resolved().as_str())
            .filter(|resolved| *resolved != self.destination);
        let destinations = || std::iter::once(self.destination).chain(resolved);
        // A listing leaves links it did not follow unnamed, and a copied
        // link still leads to its target. So a read that follows links takes
        // the tree's labels from a path below the copy that the source's
        // listing does not show as a file; `path` is that path, or the
        // directory a glob or a recursive read starts from, with `whole`.
        let through_unlisted_link = |path: &str, whole: bool| {
            crate::observation_request::reads_through_links(effect)
                && self.source.is_some_and(|root| {
                    root.descendants().is_some_and(|listing| {
                        (listing.unlisted_entries() || !listing.complete())
                            && destinations().any(|destination| {
                                path.strip_prefix(destination.trim_end_matches('/'))
                                    .and_then(|rest| rest.strip_prefix('/'))
                                    .is_some_and(|inside| {
                                        whole
                                            || !listing.paths().iter().any(|listed| {
                                                path_below_observed_root(root, listed)
                                                    == Some(inside)
                                            })
                                    })
                            })
                    })
                })
        };
        match &effect.resource {
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } => {
                let recursive = effect.attributes.get("recursive")
                    == Some(&effinterp_proto::AttrValue::Bool(true))
                    || effect.operation.as_str() == "filesystem.move";
                let excluded = excluded_name_list(effect).unwrap_or_default();
                through_unlisted_link(path, recursive)
                    || destinations().any(|destination| {
                        // The engine ties a read of a copied file to its write
                        // only where both name it alike, so a respelled one is
                        // tied here. A directory is not its content.
                        let respelled = !self.tree
                            && destination != self.destination
                            && !view.observed_directory(destination)
                            && nah_proto::labels::lexical_path::same_path(
                                path,
                                destination,
                                platform,
                            );
                        // A recursive read takes a copied tree's entry when the
                        // entry lies below it and none of the names it skips is
                        // on the way down to it.
                        let reaches = |entry: &String| {
                            let entry_path = copied_entry_path(destination, entry);
                            nah_proto::labels::lexically_contains(path, &entry_path, platform)
                                && !(self.tree
                                    && entry_path
                                        .strip_prefix(path.trim_end_matches('/'))
                                        .unwrap_or(entry)
                                        .split('/')
                                        .any(|component| excludes_component(&excluded, component)))
                        };
                        respelled
                            || self.entries.iter().any(|entry| {
                                nah_proto::labels::lexical_path::same_path(
                                    &copied_entry_path(destination, entry),
                                    path,
                                    platform,
                                )
                            })
                            || recursive
                                && if self.entries.is_empty() {
                                    nah_proto::labels::lexically_contains(
                                        path,
                                        destination,
                                        platform,
                                    )
                                } else {
                                    self.entries.iter().any(reaches)
                                }
                    })
            }
            effinterp_proto::ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
            } => {
                through_unlisted_link(glob, true)
                    || destinations().any(|destination| {
                        self.entries.iter().any(|entry| {
                            effinterp_proto::glob_match(
                                glob,
                                &copied_entry_path(destination, entry),
                            ) == Ok(true)
                        })
                    })
            }
            selection => crate::observation_request::subtree_root(selection).is_some_and(|root| {
                destinations().any(|destination| {
                    nah_proto::labels::lexically_contains(root, destination, platform)
                })
            }),
        }
    }
}

/// The path of `entry` inside the directory `destination`.
fn copied_entry_path(destination: &str, entry: &str) -> String {
    format!("{}/{entry}", destination.trim_end_matches('/'))
}

/// The final component of a path.
fn entry_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}
