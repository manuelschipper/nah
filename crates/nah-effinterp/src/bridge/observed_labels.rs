//! The labels the shipped guards read for each effect's selection: what
//! sensitivity propagation recorded, served to the matcher as its label
//! provider.

use nah_proto::effects;
use nah_proto::effects::Knowledge::Known;
use nah_proto::observation::{
    EnvObservation, Observation, ObservationQuery, ObservationValue, Observed, PathKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::git_content_selection::{change_leaves_add_candidates, stages_git_add_selection};
use super::guard_host_facts::observed_git_root;
use nah_proto::labels::lexical_path::{lexically_contains, same_path};

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
    /// The labels each write leaves in the file it names, from what flows
    /// into it, for a later Git staging selection that takes the file.
    pub(super) written: BTreeMap<effinterp_proto::EffectId, Vec<nah_proto::labels::Sensitivity>>,
}

impl ObservedLabels<'_> {
    fn git_tree_path_labels(
        &self,
        worktree: &effinterp_proto::ResourceExpr,
        path: &str,
    ) -> Option<BTreeSet<effinterp_matcher::LabelId>> {
        let platform = self.view.authority().platform();
        match worktree {
            effinterp_proto::ResourceExpr::Literal { value: worktree }
            | effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path: worktree },
            } => nah_proto::ctx::AbsolutePath::new(platform, worktree.clone())
                .ok()
                .map(|worktree| {
                    let selected = nah_proto::ctx::AbsolutePath::new(
                        platform,
                        nah_proto::labels::join_lexical_path(worktree.as_str(), path, platform),
                    )
                    .expect("tree path joined to an absolute worktree");
                    Self::sensitivity_label_ids(&[nah_proto::labels::sensitivity::sensitivity(
                        path,
                        &selected,
                        self.view.authority().home(),
                        platform,
                        false,
                    )])
                }),
            // An environment credential's basename is known even when a
            // conditional directory change left its repository unnamed.
            _ if nah_proto::labels::sensitivity::environment_file(path, platform) => {
                Some(Self::sensitivity_label_ids(&[
                    nah_proto::labels::Sensitivity::EnvironmentSecret,
                ]))
            }
            _ => None,
        }
    }

    /// Observations add inclusion to a broad Git read. Named paths keep their
    /// own labels even when an observation is empty or selects other files.
    fn git_content_labels(
        &self,
        id: &effinterp_proto::EffectId,
    ) -> Option<BTreeSet<effinterp_matcher::LabelId>> {
        let paths = self.git_content_paths(id)?;
        Some(Self::sensitivity_label_ids(
            &paths
                .iter()
                .flat_map(|(path, content)| {
                    let path = nah_proto::ctx::AbsolutePath::new(
                        self.view.authority().platform(),
                        path.clone(),
                    )
                    .expect("a Git selection's paths are absolute");
                    std::iter::once(nah_proto::labels::sensitivity::sensitivity(
                        path.as_str(),
                        &path,
                        self.view.authority().home(),
                        self.view.authority().platform(),
                        false,
                    ))
                    .chain(content.iter().copied())
                })
                .collect::<Vec<_>>(),
        ))
    }

    /// The files a broad Git read takes, each with the labels its content
    /// carries beyond its name. These filenames describe initial state.
    /// Possible filesystem or Git changes leave which files the invocation
    /// prints unestablished, except what a staging selection takes, which
    /// the observer answers for after the writes and deletes earlier calls
    /// make (`staging_changes`): a file one of them writes carries the labels
    /// of what was written into it last, and of every write that may have
    /// come after. Named-path evidence stands independently of this
    /// observation. A change in a call that starts after this one, such as
    /// the commit in `git add -A && git commit`, cannot alter what it
    /// selected.
    fn git_content_paths(
        &self,
        id: &effinterp_proto::EffectId,
    ) -> Option<BTreeMap<String, Vec<nah_proto::labels::Sensitivity>>> {
        use super::git_content_selection::{
            earlier_changes, may_precede, observed_paths, staging_changes,
        };
        let effect = self
            .view
            .plan()
            .effects
            .iter()
            .find(|effect| &effect.id == id)?;
        if !effect.attributes.contains_key("content_selection") {
            return None;
        }
        let unknown_pathspec = effect.attributes.get("content_pathspec_unknown")
            == Some(&effinterp_proto::AttrValue::Bool(true));
        let plan = self.view.plan();
        if plan.boundaries.iter().enumerate().any(|(index, boundary)| {
            if !may_precede(plan, effect, boundary_execution(plan, index)) {
                return false;
            }
            // Unknown pathspec magic, or pathspecs read from a file, widen this
            // read to repository candidates; its boundary must not erase the
            // positive inclusion they add.
            if unknown_pathspec
                && boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
                && boundary.domains == [effinterp_proto::Domain::new("git")]
                && boundary.affected_resource.as_ref() == Some(&effect.resource)
                && matches!(
                    boundary.detail.as_deref(),
                    Some(
                        "git pathspec magic is not observed"
                            | "git add pathspecs from a file are not observed"
                    )
                )
                && boundary
                    .provenance
                    .iter()
                    .any(|node| effect.provenance.contains(node))
            {
                return false;
            }
            boundary
                .domains
                .iter()
                .any(|domain| matches!(domain.0.as_str(), "filesystem" | "git" | "process"))
        }) {
            return None;
        }
        let (described, others) = if stages_git_add_selection(effect) {
            staging_changes(plan, effect)
        } else {
            (Vec::new(), earlier_changes(plan, effect))
        };
        let paths = observed_paths(plan, self.observation, effect)?;
        if !others
            .iter()
            .all(|change| change_leaves_add_candidates(plan, change, Some(paths)))
        {
            return None;
        }
        let platform = self.view.authority().platform();
        Some(
            paths
                .iter()
                .map(|path| {
                    let mut labels = Vec::new();
                    for (change, described) in &described {
                        let reaches = match described.operation {
                            nah_proto::observation::StagingOperation::Write { .. } => {
                                same_path(&described.path, path.as_str(), platform)
                            }
                            nah_proto::observation::StagingOperation::Delete { recursive } => {
                                same_path(&described.path, path.as_str(), platform)
                                    || recursive
                                        && lexically_contains(
                                            &described.path,
                                            path.as_str(),
                                            platform,
                                        )
                            }
                        };
                        if !reaches {
                            continue;
                        }
                        match described.operation {
                            nah_proto::observation::StagingOperation::Write { append, .. } => {
                                if described.certain && !append {
                                    labels.clear();
                                }
                                for label in self.written.get(&change.id).into_iter().flatten() {
                                    if !labels.contains(label) {
                                        labels.push(*label);
                                    }
                                }
                            }
                            // A delete that may not run leaves what was written.
                            nah_proto::observation::StagingOperation::Delete { .. }
                                if described.certain =>
                            {
                                labels.clear()
                            }
                            nah_proto::observation::StagingOperation::Delete { .. } => {}
                        }
                    }
                    (path.as_str().to_owned(), labels)
                })
                .collect(),
        )
    }

    /// Whether the file `path` that the `git add` read `effect` names is one
    /// the add leaves out: what its own selection takes, once the call's
    /// earlier changes have run, holds no secret file of that name. Git does not stage an ignored file it is
    /// not forced to, an excluded one or one that already matches the index,
    /// so the name alone stages no secret. Names are compared by file name,
    /// so a differently spelled root still counts as staged.
    fn staging_leaves_out(&self, effect: &effinterp_proto::EffectId, path: &str) -> bool {
        let (key, purpose) = nah_proto::observation::GIT_STAGING_PURPOSE;
        let plan = self.view.plan();
        let Some(read) = plan
            .effects
            .iter()
            .find(|candidate| &candidate.id == effect)
        else {
            return false;
        };
        if read.operation.as_str() != "filesystem.read"
            || read.attributes.get(key) != Some(&effinterp_proto::AttrValue::String(purpose.into()))
        {
            return false;
        }
        let name = |path: &str| path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned();
        let named = name(path);
        plan.effects
            .iter()
            .filter(|other| other.execution == read.execution && stages_git_add_selection(other))
            .any(|selection| {
                self.git_content_paths(&selection.id)
                    .is_some_and(|paths| paths.keys().all(|staged| name(staged) != named))
            })
    }

    /// Record the labels `effect` resolved for one concrete path it selects.
    pub(super) fn record_path_labels(
        &mut self,
        effect: &effinterp_proto::EffectId,
        path: &str,
        labels: &effects::ResourceLabels,
        content: &[nah_proto::labels::Sensitivity],
    ) {
        let entry = Self::resource_label_ids(labels, content);
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
    /// [`Self::record_path_labels`], it labels no directory another effect's path inherits.
    pub(super) fn record_labels_through_links(
        &mut self,
        effect: &effinterp_proto::EffectId,
        path: &str,
        content: &[nah_proto::labels::Sensitivity],
    ) {
        self.paths
            .entry((effect.clone(), path.to_owned()))
            .or_default()
            .extend(Self::sensitivity_label_ids(content));
    }

    /// Record that `effect`'s link-following read of `selection` leaves it
    /// and every project through a link (`NahLabel::LinkedOutsideTree`).
    /// Like [`Self::record_labels_through_links`], it labels only this
    /// effect's selection, after its other labels are recorded.
    pub(super) fn record_linked_outside_tree(
        &mut self,
        effect: &effinterp_proto::EffectId,
        selection: &effinterp_proto::ResourceExpr,
    ) {
        let label =
            effinterp_matcher::LabelId(nah_proto::labels::NahLabel::LinkedOutsideTree.label_id());
        if let effinterp_proto::ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } = selection
        {
            if let Some(labels) = self.paths.get_mut(&(effect.clone(), path.clone())) {
                labels.insert(label);
            }
        } else if let Some((_, _, labels)) = self
            .selections
            .iter_mut()
            .find(|(owner, recorded, _)| owner == effect && recorded == selection)
        {
            labels.insert(label);
        }
    }

    /// Record the labels `effect` resolved for a pattern or subtree selection.
    pub(super) fn record_selection_labels(
        &mut self,
        effect: &effinterp_proto::EffectId,
        selection: &effinterp_proto::ResourceExpr,
        labels: &effects::ResourceLabels,
        content: &[nah_proto::labels::Sensitivity],
    ) {
        let entry = Self::resource_label_ids(labels, content);
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

    /// The matcher label ids of the sensitivity labels a selection's content
    /// carries; `Sensitivity::None` is no label.
    fn sensitivity_label_ids(
        content: &[nah_proto::labels::Sensitivity],
    ) -> BTreeSet<effinterp_matcher::LabelId> {
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

    /// The matcher label ids one selection carries: its content's
    /// sensitivity, what it selects (project, home, root) and its system or
    /// home scope.
    fn resource_label_ids(
        labels: &effects::ResourceLabels,
        content: &[nah_proto::labels::Sensitivity],
    ) -> BTreeSet<effinterp_matcher::LabelId> {
        use nah_proto::labels::NahLabel;
        let mut entry = Self::sensitivity_label_ids(content);
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
    fn enclosing_directory_labels(
        &self,
        path: &str,
        inclusive: bool,
    ) -> BTreeSet<effinterp_matcher::LabelId> {
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

    /// The labels `effect` recorded for the concrete `path`, with those of
    /// the observed directories enclosing it when the query asks for
    /// ancestors. `None` when the effect recorded nothing for that path: its
    /// labels are unknown, not absent.
    fn path_labels(
        &self,
        effect: &effinterp_proto::EffectId,
        path: &str,
        selection: effinterp_matcher::LabelSelection,
    ) -> Option<BTreeSet<effinterp_matcher::LabelId>> {
        let mut labels = self.paths.get(&(effect.clone(), path.to_owned()))?.clone();
        if selection == effinterp_matcher::LabelSelection::ResourceOrAncestorDirectory {
            labels.extend(self.enclosing_directory_labels(path, false));
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
        if effect.operation.as_str() == "git.read" {
            let effinterp_proto::ResourceExpr::Concrete {
                identity:
                    effinterp_proto::ResourceIdentity::GitRepository {
                        worktree: Some(worktree),
                        ..
                    },
            } = &effect.resource
            else {
                return None;
            };
            if let Some(effinterp_proto::AttrValue::String(path)) = effect.attributes.get("path") {
                return self.git_tree_path_labels(worktree, path);
            }
            return None;
        }
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
                    .map(|mut labels| {
                        if self.staging_leaves_out(effect, path) {
                            labels.retain(|label| {
                                !Self::sensitivity_label_ids(&[
                                    nah_proto::labels::Sensitivity::EnvironmentSecret,
                                    nah_proto::labels::Sensitivity::CredentialSecret,
                                    nah_proto::labels::Sensitivity::KeyMaterial,
                                    nah_proto::labels::Sensitivity::OtherSensitive,
                                ])
                                .contains(label)
                            });
                        }
                        labels
                    })
            }
            (effinterp_proto::ResourceIdentity::GitRepository { .. }, Some(effect)) => {
                self.git_selection_labels(effect)
            }
            _ => None,
        };
        let added = resource
            .realm
            .is_host()
            .then(|| {
                resource
                    .effect
                    .and_then(|effect| self.git_content_labels(effect))
            })
            .flatten();
        let labels = match (labels, added) {
            (Some(mut named), Some(observed)) => {
                named.extend(observed);
                Some(named)
            }
            (named, observed) => named.or(observed),
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
                        labels.extend(self.enclosing_directory_labels(&bound, true));
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
            } if !path.is_empty() => self.git_tree_path_labels(worktree, path),
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
                    Self::sensitivity_label_ids(if present {
                        &[nah_proto::labels::Sensitivity::EnvironmentSecret]
                    } else {
                        &[]
                    })
                })
            }
        };
        let added = resource
            .realm
            .is_host()
            .then(|| {
                resource
                    .effect
                    .and_then(|effect| self.git_content_labels(effect))
            })
            .flatten();
        let labels = match (labels, added) {
            (Some(mut named), Some(observed)) => {
                named.extend(observed);
                Some(named)
            }
            (named, observed) => named.or(observed),
        };
        labels.map_or(LabelStatus::Unknown, |labels| {
            LabelStatus::Known(labels.into_iter().collect())
        })
    }
}

/// The call the boundary at `index` belongs to: the execution that records
/// it, such as an unobserved hook, or else the nearest execution its
/// provenance crosses. `None` when neither names one.
fn boundary_execution(plan: &effinterp_proto::Plan, index: usize) -> Option<u32> {
    if let Some(node) = plan.execution_graph.nodes.iter().position(|node| {
        node.boundary
            .is_some_and(|boundary| boundary.0 as usize == index)
    }) {
        return Some(node as u32);
    }
    let mut seen = BTreeSet::new();
    let mut queue = plan.boundaries[index]
        .provenance
        .iter()
        .copied()
        .collect::<std::collections::VecDeque<_>>();
    while let Some(reference) = queue.pop_front() {
        if !seen.insert(reference.0) {
            continue;
        }
        let node = plan.provenance.get(reference.0 as usize)?;
        if let effinterp_proto::ProvenanceKind::Execution { node } = node.kind {
            return Some(node);
        }
        queue.extend(node.antecedents.iter().copied());
    }
    None
}
