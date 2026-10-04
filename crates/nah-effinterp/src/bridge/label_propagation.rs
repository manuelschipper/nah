//! Which sensitivity labels a selection's content carries, and how they
//! propagate along exact content and alias relations to later reads.

use nah_proto::effects;
use nah_proto::effects::Knowledge::{Known, Unknown};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationQuery, ObservationValue, Observed, PathKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::content_flow::clone_fact_occurrences;
use super::fact_projection::EffectProjection;
use super::guard_host_facts::observed_git_root;
use super::invocation_calls::add_gap;
use super::resource_projection::unconditionally_selects_path;

/// Label each selection's content, propagate the labels along the relations
/// that preserve content, and return the labels the shipped guards read.
pub(super) fn propagate_sensitivity<'a>(
    view: &'a crate::plan_view::PlanView<'a>,
    observation: &'a Observation,
    invocation_cwd: &'a str,
    git_config_credentials: &BTreeMap<String, Option<bool>>,
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
                        &entry_path(destination, entry),
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
            if let Some(descendants) = observed.and_then(|path| path.descendants()) {
                let unselected = observed
                    .map(|root| filtered_out(effect, root, descendants.paths()))
                    .unwrap_or_default();
                for path in descendants.paths() {
                    if observed.is_some_and(|root| excluded_below(effect, root, path))
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
                                followed_through_links(
                                    descendants.links(),
                                    path,
                                    view.authority().platform(),
                                )
                            })
                            .flatten();
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
                && !plan.effects.iter().any(|moved| {
                    moved.operation.as_str() == "filesystem.move"
                        && moved.execution == effect.execution
                        && moved.resource == effect.resource
                })
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
            && nah_proto::labels::git_config::is_git_config_path(path, platform)
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
                    && copy.selected_by(effect, platform)
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
                                        &entry_path(copy.destination, entry),
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
                    copies.push(CopiedContent {
                        written,
                        realm: &effect.realm,
                        destination: path,
                        entries: entries.clone(),
                        labels: carried.clone(),
                    });
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
                        observed_labels.add(owner, path, labels, &shared);
                    }
                    observed_labels.add_through_links(owner, path, &through_links);
                }
                selection @ effinterp_proto::ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { .. },
                } => observed_labels.add_selection(owner, selection, labels, &selected),
                selection if crate::observation_request::subtree_root(selection).is_some() => {
                    observed_labels.add_selection(owner, selection, labels, &selected)
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
    /// The names the content keeps when `destination` is a directory. Empty
    /// when the read names none, as a recursive one does not.
    entries: BTreeSet<String>,
    labels: Vec<nah_proto::labels::Sensitivity>,
}

impl CopiedContent<'_> {
    /// Whether `effect` selects the copy: one of its entries by path or by
    /// glob, or a tree that holds the destination. A read of the destination
    /// path itself is already tied to the write by the engine's own flow.
    fn selected_by(
        &self,
        effect: &effinterp_proto::Effect,
        platform: nah_proto::ctx::Platform,
    ) -> bool {
        let entries = || {
            self.entries
                .iter()
                .map(|entry| entry_path(self.destination, entry))
        };
        match &effect.resource {
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } => {
                entries()
                    .any(|entry| nah_proto::labels::lexical_path::same_path(&entry, path, platform))
                    || (effect.attributes.get("recursive")
                        == Some(&effinterp_proto::AttrValue::Bool(true))
                        || effect.operation.as_str() == "filesystem.move")
                        && nah_proto::labels::lexically_contains(path, self.destination, platform)
            }
            effinterp_proto::ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
            } => entries().any(|entry| effinterp_proto::glob_match(glob, &entry) == Ok(true)),
            selection => crate::observation_request::subtree_root(selection).is_some_and(|root| {
                nah_proto::labels::lexically_contains(root, self.destination, platform)
            }),
        }
    }
}

/// The path of `entry` inside the directory `destination`.
fn entry_path(destination: &str, entry: &str) -> String {
    format!("{}/{entry}", destination.trim_end_matches('/'))
}

/// The final component of a path.
fn entry_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Nah's labels for the host filesystem selections the plan's effects make,
/// answered from the observation this conversion binds: the path
/// annotations' sensitivity catalog, search reach and scope, the sensitivity
/// of a selection's observed descendants, and the kind of an observed path.
/// Each effect's selection carries the labels its own annotation resolved,
/// so an annotation on one effect never labels another effect on that path.
/// A selection no effect made with an observed label is unknown, never
/// unlabeled.
pub(super) struct ObservedLabels<'a> {
    pub(super) view: &'a crate::plan_view::PlanView<'a>,
    pub(super) observation: &'a Observation,
    /// The working directory the invocation runs in, from which Git
    /// discovers the repository a Git discard selects in.
    pub(super) invocation_cwd: &'a str,
    /// The concrete paths each effect selects, by the effect; a finite
    /// union's members under the effect that selects the union.
    pub(super) paths:
        BTreeMap<(effinterp_proto::EffectId, String), BTreeSet<effinterp_matcher::LabelId>>,
    /// Every labeled path, whichever effect selected it: a labeled directory
    /// lends its labels to what the observation shows it encloses.
    pub(super) directories: BTreeMap<String, BTreeSet<effinterp_matcher::LabelId>>,
    /// Pattern and subtree selections, labeled as the whole selection the
    /// annotation resolved; a finite union is labeled by its members' paths.
    pub(super) selections: Vec<(
        effinterp_proto::EffectId,
        effinterp_proto::ResourceExpr,
        BTreeSet<effinterp_matcher::LabelId>,
    )>,
}

impl ObservedLabels<'_> {
    /// Record the labels `effect` resolved for one concrete path it selects.
    pub(super) fn add(
        &mut self,
        effect: &effinterp_proto::EffectId,
        path: &str,
        labels: &effects::ResourceLabels,
        content: &[nah_proto::labels::Sensitivity],
    ) {
        let entry = Self::entry(labels, content);
        self.directories
            .entry(path.to_owned())
            .or_default()
            .extend(entry.iter().cloned());
        self.paths
            .entry((effect.clone(), path.to_owned()))
            .or_default()
            .extend(entry);
    }

    /// Record what `effect` alone reads through links below `path`. Unlike
    /// [`Self::add`], it labels no directory another effect's path inherits.
    pub(super) fn add_through_links(
        &mut self,
        effect: &effinterp_proto::EffectId,
        path: &str,
        content: &[nah_proto::labels::Sensitivity],
    ) {
        self.paths
            .entry((effect.clone(), path.to_owned()))
            .or_default()
            .extend(Self::content(content));
    }

    /// Record the labels `effect` resolved for a pattern or subtree selection.
    pub(super) fn add_selection(
        &mut self,
        effect: &effinterp_proto::EffectId,
        selection: &effinterp_proto::ResourceExpr,
        labels: &effects::ResourceLabels,
        content: &[nah_proto::labels::Sensitivity],
    ) {
        let entry = Self::entry(labels, content);
        match self
            .selections
            .iter_mut()
            .find(|(owner, recorded, _)| owner == effect && recorded == selection)
        {
            Some((_, _, recorded)) => recorded.extend(entry),
            None => self
                .selections
                .push((effect.clone(), selection.clone(), entry)),
        }
    }

    fn content(content: &[nah_proto::labels::Sensitivity]) -> BTreeSet<effinterp_matcher::LabelId> {
        content
            .iter()
            .filter(|sensitivity| **sensitivity != nah_proto::labels::Sensitivity::None)
            .map(|sensitivity| {
                effinterp_matcher::LabelId(
                    nah_proto::labels::NahLabel::Sensitivity(*sensitivity).label_id(),
                )
            })
            .collect()
    }

    fn entry(
        labels: &effects::ResourceLabels,
        content: &[nah_proto::labels::Sensitivity],
    ) -> BTreeSet<effinterp_matcher::LabelId> {
        use nah_proto::labels::NahLabel;
        let mut entry = Self::content(content);
        for (reach, label) in [
            (labels.selects_project, NahLabel::SelectsProject),
            (labels.selects_home, NahLabel::SelectsHome),
            (labels.selects_root, NahLabel::SelectsRoot),
        ] {
            if reach == effects::Reach::Yes {
                entry.insert(effinterp_matcher::LabelId(label.label_id()));
            }
        }
        match labels.scope {
            Known(nah_proto::labels::PathScope::System) => {
                entry.insert(effinterp_matcher::LabelId(NahLabel::SystemScope.label_id()));
            }
            Known(nah_proto::labels::PathScope::Home) => {
                entry.insert(effinterp_matcher::LabelId(NahLabel::HomeScope.label_id()));
            }
            _ => {}
        }
        entry
    }

    /// The labels of recorded directories the observation shows enclose
    /// `path`, and `path` itself when `inclusive`.
    fn ancestors(&self, path: &str, inclusive: bool) -> BTreeSet<effinterp_matcher::LabelId> {
        let platform = self.view.authority().platform();
        self.directories
            .iter()
            .filter(|(ancestor, _)| {
                (inclusive && ancestor.as_str() == path
                    || ancestor.as_str() != path
                        && nah_proto::labels::lexically_contains(ancestor, path, platform))
                    && self
                        .view
                        .observed_path(ancestor)
                        .is_some_and(|value| value.kind() == PathKind::Directory)
            })
            .flat_map(|(_, inherited)| inherited.iter().cloned())
            .collect()
    }

    fn path_labels(
        &self,
        effect: &effinterp_proto::EffectId,
        path: &str,
        selection: effinterp_matcher::LabelSelection,
    ) -> Option<BTreeSet<effinterp_matcher::LabelId>> {
        let mut labels = self.paths.get(&(effect.clone(), path.to_owned()))?.clone();
        if selection == effinterp_matcher::LabelSelection::ResourceOrAncestorDirectory {
            labels.extend(self.ancestors(path, false));
        }
        Some(labels)
    }
}

impl ObservedLabels<'_> {
    /// Which side of the observed Git root a Git discard's selection names:
    /// each path in its `selections` is the root or a named path, and the top
    /// `:/` names is the root. With no observed root every path is a named
    /// path, and the top is unknown. A selection the engine could not list
    /// is unknown.
    fn git_selection_labels(
        &self,
        effect: &effinterp_proto::EffectId,
    ) -> Option<BTreeSet<effinterp_matcher::LabelId>> {
        use nah_proto::labels::NahLabel;
        let effect = self
            .view
            .plan()
            .effects
            .iter()
            .find(|candidate| &candidate.id == effect)?;
        let Some(effinterp_proto::AttrValue::List(selections)) =
            effect.attributes.get("selections")
        else {
            return None;
        };
        let root = observed_git_root(self.view, self.observation, self.invocation_cwd, effect);
        let label = |label: NahLabel| effinterp_matcher::LabelId(label.label_id());
        let mut labels = BTreeSet::new();
        if effect.attributes.get("selects_top") == Some(&effinterp_proto::AttrValue::Bool(true)) {
            root.as_ref()?;
            labels.insert(label(NahLabel::GitSelectsRoot));
        }
        for selection in selections {
            let effinterp_proto::AttrValue::String(path) = selection else {
                return None;
            };
            labels.insert(label(if root.as_ref() == Some(path) {
                NahLabel::GitSelectsRoot
            } else {
                NahLabel::GitSelectsNamedPath
            }));
        }
        Some(labels)
    }
}

impl effinterp_matcher::LabelProvider for ObservedLabels<'_> {
    fn labels(
        &self,
        observation: &effinterp_matcher::ObservationBinding,
        resource: effinterp_matcher::LabelResource<'_>,
    ) -> effinterp_matcher::LabelStatus {
        use effinterp_matcher::LabelStatus;
        if observation.0 != nah_proto::labels::LABEL_OBSERVATION {
            return LabelStatus::Unknown;
        }
        let labels = match (resource.identity, resource.effect) {
            (effinterp_proto::ResourceIdentity::FsPath { path }, Some(effect))
                if resource.realm.is_host() =>
            {
                self.path_labels(effect, path, resource.selection)
            }
            (effinterp_proto::ResourceIdentity::GitRepository { .. }, Some(effect)) => {
                self.git_selection_labels(effect)
            }
            _ => None,
        };
        labels.map_or(LabelStatus::Unknown, |labels| {
            LabelStatus::Known(labels.into_iter().collect())
        })
    }

    fn path_kind(
        &self,
        observation: &effinterp_matcher::ObservationBinding,
        realm: &effinterp_proto::ExecutionRealm,
        path: &effinterp_proto::ResourceExpr,
    ) -> effinterp_matcher::PathKindStatus {
        use effinterp_matcher::{ObservedPathKind, PathKindStatus};
        if observation.0 != nah_proto::labels::LABEL_OBSERVATION || !realm.is_host() {
            return PathKindStatus::Unknown;
        }
        // A pattern is typed by the directory that bounds it.
        crate::observation_request::observation_bound(path)
            .and_then(|(path, _)| self.view.observed_path(&path))
            .map_or(PathKindStatus::Unknown, |value| {
                PathKindStatus::Known(match value.kind() {
                    PathKind::Directory => Some(ObservedPathKind::Directory),
                    PathKind::File => Some(ObservedPathKind::File),
                    PathKind::Missing => Some(ObservedPathKind::Missing),
                    PathKind::Symlink | PathKind::Fifo | PathKind::Other => None,
                })
            })
    }

    fn selection_labels(
        &self,
        observation: &effinterp_matcher::ObservationBinding,
        resource: effinterp_matcher::SelectionLabelResource<'_>,
    ) -> effinterp_matcher::LabelStatus {
        use effinterp_matcher::{LabelSelection, LabelStatus, SelectionTarget};
        if observation.0 != nah_proto::labels::LABEL_OBSERVATION {
            return LabelStatus::Unknown;
        }
        let labels = match resource.target {
            SelectionTarget::Filesystem(_) if !resource.realm.is_host() => None,
            SelectionTarget::Filesystem(_) if resource.effect.is_none() => None,
            SelectionTarget::Filesystem(selection) => {
                let effect = resource.effect.expect("an effect's own selection");
                if let Some((_, _, recorded)) = self
                    .selections
                    .iter()
                    .find(|(owner, recorded, _)| owner == effect && recorded == selection)
                {
                    // A pattern or subtree selects what lies within the
                    // directory that bounds it.
                    let mut labels = recorded.clone();
                    if resource.selection == LabelSelection::ResourceOrAncestorDirectory
                        && let Some((bound, _)) =
                            crate::observation_request::observation_bound(selection)
                    {
                        labels.extend(self.ancestors(&bound, true));
                    }
                    Some(labels)
                } else {
                    // A finite union selects exactly one member, so it
                    // carries every label a member might, and is known only
                    // when every member is.
                    crate::observation_request::finite_members(selection).and_then(|members| {
                        members
                            .iter()
                            .try_fold(BTreeSet::new(), |mut labels, member| {
                                let (path, _) =
                                    crate::observation_request::observation_bound(member)?;
                                labels.extend(self.path_labels(
                                    effect,
                                    &path,
                                    resource.selection,
                                )?);
                                Some(labels)
                            })
                    })
                }
            }
            // The catalog classifies the stated tree path without observing
            // a host file, as the bridge classifies a Git read's contents.
            SelectionTarget::GitTreePath {
                repository:
                    effinterp_proto::ResourceIdentity::GitRepository {
                        worktree: Some(worktree),
                        ..
                    },
                path,
            } if !path.is_empty() => {
                let platform = self.view.authority().platform();
                match worktree.as_ref() {
                    effinterp_proto::ResourceExpr::Literal { value: worktree }
                    | effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path: worktree },
                    } => nah_proto::ctx::AbsolutePath::new(platform, worktree.clone())
                        .ok()
                        .map(|worktree| {
                            let selected = nah_proto::ctx::AbsolutePath::new(
                                platform,
                                nah_proto::labels::join_lexical_path(
                                    worktree.as_str(),
                                    path,
                                    platform,
                                ),
                            )
                            .expect("tree path joined to an absolute worktree");
                            Self::content(&[nah_proto::labels::sensitivity::sensitivity(
                                path,
                                &selected,
                                self.view.authority().home(),
                                platform,
                                false,
                            )])
                        }),
                    _ => None,
                }
            }
            SelectionTarget::GitTreePath { .. } => None,
            // A disclosed whole environment holds an environment secret when
            // the observation found a catalogued credential name with a value,
            // and none when every credential probe found it empty or unset.
            SelectionTarget::EnvironmentAll => {
                let mut complete = true;
                let mut probed = false;
                let mut present = false;
                for fact in self.observation.facts() {
                    let (ObservationQuery::Env { name, .. }, ObservationValue::Env { observed }) =
                        (fact.query(), fact.value())
                    else {
                        continue;
                    };
                    if !nah_proto::labels::is_credential_name(name) {
                        continue;
                    }
                    match observed {
                        Observed::Ok {
                            value: EnvObservation::Value { text },
                        } => {
                            probed = true;
                            present |= !text.is_empty();
                        }
                        Observed::Ok {
                            value: EnvObservation::Unset,
                        } => probed = true,
                        Observed::Error { .. } => complete = false,
                    }
                }
                (present || probed && complete).then(|| {
                    Self::content(if present {
                        &[nah_proto::labels::Sensitivity::EnvironmentSecret]
                    } else {
                        &[]
                    })
                })
            }
        };
        labels.map_or(LabelStatus::Unknown, |labels| {
            LabelStatus::Known(labels.into_iter().collect())
        })
    }
}

/// Whether a recursive read whose model states `excluded_names`, a list of
/// whole names and `name*` prefixes (tar and rsync `--exclude`), skips
/// `path`: a component of it below the observed `root` is one of those names
/// or starts with one of those prefixes, so neither it nor anything below it
/// is read. An unreadable list skips nothing.
fn excluded_below(
    effect: &effinterp_proto::Effect,
    root: &nah_proto::observation::PathObservation,
    path: &nah_proto::ctx::AbsolutePath,
) -> bool {
    let Some(effinterp_proto::AttrValue::List(names)) = effect.attributes.get("excluded_names")
    else {
        return false;
    };
    let Some(names) = names
        .iter()
        .map(|name| match name {
            effinterp_proto::AttrValue::String(name) => Some(name.as_str()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let Some(below) = [root.realpath(), Some(root.resolved())]
        .into_iter()
        .flatten()
        .find_map(|base| {
            path.as_str()
                .strip_prefix(base.as_str().trim_end_matches('/'))
                .and_then(|rest| rest.strip_prefix('/'))
        })
    else {
        return false;
    };
    below.split('/').any(|component| {
        names.iter().any(|name| match name.strip_suffix('*') {
            Some(prefix) => component.starts_with(prefix),
            None => component == *name,
        })
    })
}

/// The observed descendants a recursive read skips under the path filters
/// its model states: `excluded_paths` (aws s3 `--exclude`) and
/// `included_paths` (az `--pattern`), JSON lists of fnmatch globs matched
/// against a file's path relative to the read's `root`, where `*` also
/// crosses `/`. A file is skipped when an exclusion matches it or no
/// inclusion does; a directory only when it and everything listed below it
/// are skipped. The tools join each glob under the root they were given, so
/// a root spelled with glob characters proves nothing.
fn filtered_out<'a>(
    effect: &effinterp_proto::Effect,
    root: &nah_proto::observation::PathObservation,
    paths: &'a [nah_proto::ctx::AbsolutePath],
) -> std::collections::BTreeSet<&'a nah_proto::ctx::AbsolutePath> {
    let globs = |name: &str| match effect.attributes.get(name) {
        Some(effinterp_proto::AttrValue::String(list)) => {
            serde_json::from_str::<Vec<String>>(list).ok()
        }
        _ => None,
    };
    let excluded = globs("excluded_paths").unwrap_or_default();
    let included = globs("included_paths");
    if (excluded.is_empty() && included.is_none())
        || root.resolved().as_str().contains(['*', '?', '['])
    {
        return Default::default();
    }
    // Whether the platform folds case is not known. An exclusion counts when
    // it matches as written. One holding a negated bracket class must also
    // match with case folded, where the class can stop matching and the file
    // would be kept. A range is read as written, though folding can shrink
    // one that spans both cases (`[A-z]`). An inclusion counts when it
    // matches either way.
    let folded = |glob: &str, relative: &str| {
        fnmatch(&glob.to_ascii_lowercase(), &relative.to_ascii_lowercase())
    };
    let selected = |relative: &str| {
        !excluded
            .iter()
            .any(|glob| fnmatch(glob, relative) && (!glob.contains("[!") || folded(glob, relative)))
            && included.as_ref().is_none_or(|included| {
                included
                    .iter()
                    .any(|glob| fnmatch(glob, relative) || folded(glob, relative))
            })
    };
    let relative = |path: &'a nah_proto::ctx::AbsolutePath| {
        [root.realpath(), Some(root.resolved())]
            .into_iter()
            .flatten()
            .find_map(|base| {
                path.as_str()
                    .strip_prefix(base.as_str().trim_end_matches('/'))
                    .and_then(|rest| rest.strip_prefix('/'))
            })
    };
    // Every directory above a file the filters keep.
    let mut kept_above = std::collections::BTreeSet::new();
    for relative in paths.iter().filter_map(relative) {
        if selected(relative) {
            kept_above.extend(relative.match_indices('/').map(|(at, _)| &relative[..at]));
        }
    }
    paths
        .iter()
        .filter(|path| {
            relative(path)
                .is_some_and(|relative| !selected(relative) && !kept_above.contains(relative))
        })
        .collect()
}

/// Python's fnmatch over `*` (any run, `/` included), `?` (one character),
/// bracket classes and literal characters.
fn fnmatch(glob: &str, text: &str) -> bool {
    let (glob, text) = (
        glob.chars().collect::<Vec<_>>(),
        text.chars().collect::<Vec<_>>(),
    );
    let (mut g, mut t) = (0, 0);
    // The last `*` seen and the text position it currently stops at.
    let mut star = None;
    while t < text.len() {
        // Where the glob continues once its element at `g` takes `text[t]`.
        let taken = match glob.get(g) {
            Some('*') => {
                star = Some((g, t));
                g += 1;
                continue;
            }
            Some('?') => Some(g + 1),
            Some('[') => match bracket_class(&glob, g, text[t]) {
                Some((holds, after)) => holds.then_some(after),
                None => (text[t] == '[').then_some(g + 1),
            },
            Some(&character) => (character == text[t]).then_some(g + 1),
            None => None,
        };
        match (taken, star) {
            (Some(next), _) => {
                g = next;
                t += 1;
            }
            (None, Some((star_at, stop))) => {
                g = star_at + 1;
                t = stop + 1;
                star = Some((star_at, stop + 1));
            }
            (None, None) => return false,
        }
    }
    glob[g..].iter().all(|character| *character == '*')
}

/// Whether the fnmatch bracket class opening at `glob[open]` holds
/// `character`, and the index after its closing `]`. A leading `!` negates
/// the class, a `]` placed first is a member, and `a-z` is a range. None when
/// no `]` closes the class: fnmatch then reads the `[` as itself.
fn bracket_class(glob: &[char], open: usize, character: char) -> Option<(bool, usize)> {
    let negated = glob.get(open + 1) == Some(&'!');
    let first = open + 1 + usize::from(negated);
    let close = (first + 1..glob.len()).find(|at| glob[*at] == ']')?;
    let members = &glob[first..close];
    let mut holds = false;
    let mut at = 0;
    while at < members.len() {
        if at + 2 < members.len() && members[at + 1] == '-' {
            holds |= (members[at]..=members[at + 2]).contains(&character);
            at += 3;
        } else {
            holds |= members[at] == character;
            at += 1;
        }
    }
    Some((holds != negated, close + 1))
}

/// The path a link-following listing's `path` names through the innermost
/// link above or at it, or None when it went through no link.
fn followed_through_links(
    links: &[(nah_proto::ctx::AbsolutePath, nah_proto::ctx::AbsolutePath)],
    path: &nah_proto::ctx::AbsolutePath,
    platform: nah_proto::ctx::Platform,
) -> Option<nah_proto::ctx::AbsolutePath> {
    let (visible, target) = links
        .iter()
        .filter(|(visible, _)| {
            path.as_str()
                .strip_prefix(visible.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .max_by_key(|(visible, _)| visible.as_str().len())?;
    nah_proto::ctx::AbsolutePath::new(
        platform,
        format!(
            "{}{}",
            target.as_str(),
            &path.as_str()[visible.as_str().len()..]
        ),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::fnmatch;

    #[test]
    fn fnmatch_reads_bracket_classes_as_python_does() {
        for (glob, text, matches) in [
            ("*.[kp]e[ym]", "certs/server.key", true),
            ("*.[kp]e[ym]", "certs/server.pem", true),
            ("*.[kp]e[ym]", "certs/server.crt", false),
            ("file[0-9].txt", "file7.txt", true),
            ("file[0-9].txt", "filex.txt", false),
            ("[!a-c]x", "dx", true),
            ("[!a-c]x", "bx", false),
            // A `]` placed first is a member, and an unclosed `[` is itself.
            ("[]a]", "]", true),
            ("a[b", "a[b", true),
            ("a[b", "ab", false),
            ("*[s]erver.key", "certs/server.key", true),
        ] {
            assert_eq!(fnmatch(glob, text), matches, "{glob} against {text}");
        }
    }
}
