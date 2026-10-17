//! What one conversion tells the shipped guards about the host: the paths each
//! plan effect physically reaches, and the observed facts the guards' host
//! predicates read.

use nah_proto::effects;
use nah_proto::guard_host::{GuardHostFacts, ReachedHostPath};
use nah_proto::observation::{Observation, ObservationValue, Observed};
use std::collections::BTreeMap;

/// One host path an effect reaches, before the path catalogs read its labels.
pub(super) struct ReachedResource {
    pub(super) resource: effects::ResourceId,
    pub(super) recursive: bool,
    pub(super) device: Option<nah_proto::ctx::AbsolutePath>,
}

/// What one plan effect physically reaches on the host. `own` is the effect's
/// own selection `target`, withdrawn when the engine's move does not land in a
/// directory; `selected` adds the members of a finite selection and the paths
/// a Git discard replaces or removes; `destination` is where a move's single
/// certified transfer lands.
pub(super) struct HostReach {
    pub(super) target: effects::ResourceId,
    pub(super) own: Option<ReachedResource>,
    pub(super) selected: Vec<ReachedResource>,
    pub(super) destination: Option<ReachedResource>,
}

/// The bridge's host facts for one conversion's shipped guard evaluation: the
/// reach and graph facts it projected for each plan effect.
pub(super) struct ConversionHostFacts<'a, 'v> {
    pub(super) view: &'a crate::plan_view::PlanView<'v>,
    pub(super) observation: &'a Observation,
    pub(super) effect_facts: &'a [effects::FactId],
    pub(super) reach: &'a [HostReach],
    pub(super) graph: &'a effects::EffectGraph,
}

impl<'a> ConversionHostFacts<'a, '_> {
    fn reached_host_path(&self, reached: &'a ReachedResource) -> ReachedHostPath<'a> {
        ReachedHostPath {
            resource: &self.graph.resources[reached.resource.0 as usize],
            recursive: reached.recursive,
            device: reached.device.as_ref().map(|device| device.as_str()),
        }
    }
}

impl GuardHostFacts for ConversionHostFacts<'_, '_> {
    fn matcher_bindings(
        &self,
    ) -> BTreeMap<effinterp_proto::ExecutionNodeRef, effinterp_proto::Bindings> {
        self.view.matcher_bindings()
    }

    fn platform(&self) -> nah_proto::ctx::Platform {
        self.view.authority().platform()
    }

    fn condition_reach(&self, effect: usize) -> effects::Reach {
        match &self.graph.facts[self.effect_facts[effect].0 as usize].condition {
            Some(condition) => self
                .graph
                .conditions_compatible(std::slice::from_ref(condition)),
            None => effects::Reach::Yes,
        }
    }

    /// Content flow publishes the causal node at position `i` as occurrence
    /// `i` and the edge at position `j` as relation `j`, each with its
    /// converted condition.
    fn causal_route_reach(&self, nodes: &[usize], edges: &[usize]) -> effects::Reach {
        let conditions = nodes
            .iter()
            .filter_map(|&node| self.graph.occurrences[node].condition.clone())
            .chain(
                edges
                    .iter()
                    .filter_map(|&edge| self.graph.relations[edge].condition.clone()),
            )
            .collect::<Vec<_>>();
        self.graph.conditions_compatible(&conditions)
    }

    fn target_identified(&self, effect: usize) -> bool {
        self.graph.resources[self.reach[effect].target.0 as usize]
            .identity
            .kind
            != effects::ResourceKind::Unknown
    }

    fn model_identity_established(&self, effect: usize) -> bool {
        let call = effects::CallId(self.view.plan().effects[effect].execution.0);
        !self
            .graph
            .gaps
            .iter()
            .any(|gap| gap.call == call && gap.code == super::fact_projection::MODEL_IDENTITY_GAP)
    }

    fn selects_recursively(&self, effect: usize) -> bool {
        let plan = self.view.plan();
        let effect = &plan.effects[effect];
        effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true))
            || crate::observation_request::subtree_reached_whole(plan, effect)
    }

    fn selected_host_paths(&self, effect: usize) -> Vec<ReachedHostPath<'_>> {
        let reach = &self.reach[effect];
        reach
            .own
            .iter()
            .chain(&reach.selected)
            .map(|reached| self.reached_host_path(reached))
            .collect()
    }

    fn move_destination(&self, effect: usize) -> Option<ReachedHostPath<'_>> {
        self.reach[effect]
            .destination
            .as_ref()
            .map(|reached| self.reached_host_path(reached))
    }

    fn observed_path_spellings(&self, resource: &effinterp_proto::ResourceExpr) -> Vec<String> {
        resource_observed_path_spellings(self.view, resource)
    }

    fn command_has_hidden_characters(&self) -> bool {
        self.graph.calls.iter().any(|call| call.hidden_characters)
    }

    fn git_discard_loses_nothing(&self, effect: usize) -> bool {
        git_discard_loses_nothing(self.view, self.observation, effect)
    }

    fn permission_change_keeps_owner_access(&self, effect: usize) -> bool {
        use effinterp_proto::AttrValue;
        use nah_proto::labels::permission_mode::{chmod_keeps_owner_access, chown_user};
        let effect = &self.view.plan().effects[effect];
        let text = |name| match effect.attributes.get(name) {
            Some(AttrValue::String(value)) => Some(value.as_str()),
            _ => None,
        };
        if effect.operation.as_str() != "filesystem.metadata" {
            return false;
        }
        match (text("action"), text("spec")) {
            (Some("chmod"), Some(spec)) => {
                chmod_keeps_owner_access(spec, may_select_directory(self.view, effect))
            }
            // Taking ownership of one's own files changes nothing a later
            // command needs; the invoking user is the one `USER` names.
            (Some("chown"), Some(spec)) => chown_user(spec).is_some_and(|user| {
                self.observation.facts().iter().any(|fact| {
                    matches!(
                        (fact.query(), fact.value()),
                        (
                            nah_proto::observation::ObservationQuery::Env { name, .. },
                            ObservationValue::Env {
                                observed: Observed::Ok {
                                    value: nah_proto::observation::EnvObservation::Value { text },
                                },
                            },
                        ) if name == INVOKING_USER_VARIABLE && text == user
                    )
                })
            }),
            _ => false,
        }
    }
}

/// The environment variable that names the invoking user. The plan asks for
/// it wherever a chown names an owner (`bridge/mod.rs`).
pub(super) const INVOKING_USER_VARIABLE: &str = "USER";

/// Whether a permission change may be applied to a directory: it recurses,
/// or what it names is not established to be something else. A named path is
/// a file only when the host observed it as one, and a narrowed selection
/// leaves directories out only when its entry kinds do, a link included,
/// since chmod changes what a link leads to.
fn may_select_directory(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
) -> bool {
    use effinterp_proto::{FsEntryKind, ResourceExpr, ResourceIdentity};
    use nah_proto::observation::PathKind;
    if effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true)) {
        return true;
    }
    match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => view.observed_path(path).is_none_or(|observed| {
            observed.kind() != PathKind::File && observed.target_kind() != Some(PathKind::File)
        }),
        resource => {
            crate::observation_request::selection_narrowing(resource).is_none_or(|narrowing| {
                narrowing.kinds.is_empty()
                    || narrowing
                        .kinds
                        .iter()
                        .any(|kind| matches!(kind, FsEntryKind::Directory | FsEntryKind::Symlink))
            })
        }
    }
}

/// What decides whether a Git discard request loses anything: the
/// directories whose repositories it discards from, and whether their
/// untracked and ignored entries decide beside their tracked changes. `None`
/// for any other effect, and for a request whose repository is not the one
/// Git finds from a named host directory.
fn discard_state_paths(effect: &effinterp_proto::Effect) -> Option<(Vec<&str>, bool)> {
    use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                git_dir: None,
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: worktree },
    } = worktree.as_ref()
    else {
        return None;
    };
    if !effect.realm.is_host() {
        return None;
    }
    let text = |name| match effect.attributes.get(name) {
        Some(AttrValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let flag = |name| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    let own = || Some((vec![worktree.as_str()], false));
    match effect.operation.as_str() {
        "git.reset_request" if text("reset_mode") == Some("hard") => own(),
        "git.recovery_destroy_request" if flag("stash") => own(),
        "git.clean_request" => Some((vec![worktree.as_str()], true)),
        "git.worktree_discard_request" => match text("discard_mode")? {
            "checkout" | "restore" | "switch" => own(),
            // The worktrees the request removes, not the one it runs in.
            "worktree_remove" if flag("selection_complete") => {
                let Some(AttrValue::List(selections)) = effect.attributes.get("selections") else {
                    return None;
                };
                let removed = selections
                    .iter()
                    .map(|selection| match selection {
                        AttrValue::String(path) => Some(path.as_str()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                (!removed.is_empty()).then_some((removed, true))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The Git state each discard request of `plan` is judged by: one query per
/// directory, listing untracked entries when any request there needs them.
pub(super) fn git_state_queries(
    plan: &effinterp_proto::Plan,
) -> Vec<nah_proto::observation::ObservationQuery> {
    let mut directories = BTreeMap::<&str, bool>::new();
    for (paths, untracked) in plan.effects.iter().filter_map(discard_state_paths) {
        for path in paths {
            *directories.entry(path).or_default() |= untracked;
        }
    }
    directories
        .into_iter()
        .enumerate()
        .map(|(index, (requested, inspect_untracked))| {
            nah_proto::observation::ObservationQuery::GitState {
                key: format!("effinterp-git-state-{index:04}"),
                requested: requested.to_owned(),
                cwd_key: crate::observation_request::CWD_KEY.into(),
                inspect_untracked,
            }
        })
        .collect()
}

/// Whether the observation establishes that the Git discard the effect
/// requests has nothing to lose.
///
/// The observation is the state before the invocation runs, so it answers
/// only when nothing else the invocation does can put work where the discard
/// takes it: every other effect leaves the discarded repositories as they
/// were observed, and no boundary leaves filesystem or Git effects unknown.
/// Order is not read, so a write after the discard refuses the answer too.
fn git_discard_loses_nothing(
    view: &crate::plan_view::PlanView<'_>,
    observation: &Observation,
    effect_index: usize,
) -> bool {
    use effinterp_proto::AttrValue;
    use nah_proto::observation::ObservationQuery;
    let plan = view.plan();
    let effect = &plan.effects[effect_index];
    let Some((paths, _)) = discard_state_paths(effect) else {
        return false;
    };
    let platform = view.authority().platform();
    let flag = |name| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    let states = paths
        .iter()
        .map(|path| {
            observation
                .facts()
                .iter()
                .find_map(|fact| match (fact.query(), fact.value()) {
                    (
                        ObservationQuery::GitState { requested, .. },
                        ObservationValue::GitState {
                            observed: Observed::Ok { value },
                        },
                    ) if requested == path => Some((*path, value)),
                    _ => None,
                })
        })
        .collect::<Option<Vec<_>>>();
    let Some(states) = states else {
        return false;
    };
    let discards = plan
        .effects
        .iter()
        .filter(|other| discard_state_paths(other).is_some())
        .map(|other| other.execution)
        .collect::<std::collections::BTreeSet<_>>();
    // A discard acts on the whole tree its repository's top level starts,
    // wherever inside it Git was pointed.
    let top_levels = states
        .iter()
        .map(|(_, state)| state.top_level().as_str())
        .collect::<Vec<_>>();
    let nothing_observed = states.iter().all(|(directory, state)| {
        let build_output = |entry: &String| {
            entry
                .strip_suffix('/')
                .is_some_and(nah_proto::labels::build_output_directory)
        };
        // Only what a tool regenerates is expendable among the ignored: a
        // file named as a by-product that is no secret, or a directory named
        // as build output. A directory ignored as a whole hides what it
        // holds, and any other ignored file may be local state.
        let ignored_expendable = |entry: &String| {
            if entry.ends_with('/') {
                return build_output(entry);
            }
            let Ok(target) = nah_proto::ctx::AbsolutePath::new(
                platform,
                nah_proto::labels::join_lexical_path(state.top_level().as_str(), entry, platform),
            ) else {
                return false;
            };
            nah_proto::labels::build_output_file(entry)
                && nah_proto::labels::sensitivity::sensitivity(
                    target.as_str(),
                    &target,
                    view.authority().home(),
                    platform,
                    false,
                ) == nah_proto::labels::Sensitivity::None
        };
        match effect.operation.as_str() {
            "git.recovery_destroy_request" => !state.stash_entries(),
            "git.clean_request" => state.untracked().is_some_and(|entries| {
                (flag("ignored_only") || entries.untracked().is_empty())
                    && (!flag("ignored") || entries.ignored().iter().all(ignored_expendable))
            }),
            // A forced removal deletes the whole worktree: its tracked
            // changes, its untracked entries and its ignored ones. The state
            // answers for it only when the named path is that worktree's top
            // level, not a directory inside another tree.
            "git.worktree_discard_request"
                if effect.attributes.get("discard_mode")
                    == Some(&AttrValue::String("worktree_remove".into())) =>
            {
                let top_level = state.top_level().as_str();
                let names_top_level =
                    nah_proto::labels::lexical_path::same_path(directory, top_level, platform)
                        || view
                            .observed_path(directory)
                            .and_then(|observed| observed.realpath())
                            .is_some_and(|real| real.as_str() == top_level);
                names_top_level
                    && !state.tracked_changes()
                    && state.untracked().is_some_and(|entries| {
                        entries.untracked().iter().all(build_output)
                            && entries.ignored().iter().all(ignored_expendable)
                    })
            }
            _ => !state.tracked_changes(),
        }
    });
    nothing_observed
        && plan.boundaries.iter().all(|boundary| {
            !boundary
                .domains
                .iter()
                .any(|domain| matches!(domain.0.as_str(), "filesystem" | "git" | "process"))
        })
        && plan
            .effects
            .iter()
            // A discard's own command states more than its request (the
            // files a restore rewrites); none of it adds work.
            .filter(|other| !discards.contains(&other.execution))
            .all(|other| leaves_repositories_unchanged(view, other, &top_levels))
}

/// Whether `effect` cannot add uncommitted work or a stash entry to the
/// working trees that start at `top_levels`: it reads, runs a program (whose
/// own effects are stated beside it or left behind a boundary), fetches,
/// removes, or changes a path the host observed to lie outside every one of
/// them. A path's spelling does not say where it lies (a link, a `..`), and
/// one that does not exist yet has no observed place, so only an existing
/// path's real location counts as outside.
fn leaves_repositories_unchanged(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
    top_levels: &[&str],
) -> bool {
    let platform = view.authority().platform();
    use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};
    match effect.operation.as_str() {
        // A removal adds nothing a discard could take: a tracked file it
        // deletes is one the discard puts back.
        "process.exec"
        | "process.code_execution"
        | "environment.read"
        | "filesystem.read"
        | "filesystem.delete"
        | "git.read" => true,
        "git.remote_sync" => effect.attributes.get("fetch") == Some(&AttrValue::Bool(true)),
        // Moving or deleting a ref touches no working tree; the stash ref is
        // the one that holds work.
        "git.ref_update" | "git.ref_delete_request" => {
            effect.attributes.get("stash") != Some(&AttrValue::Bool(true))
                && effect.attributes.get("ref") != Some(&AttrValue::String("refs/stash".into()))
        }
        operation if operation.starts_with("network.") => true,
        operation if operation.starts_with("filesystem.") => match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => view
                .observed_path(path)
                .and_then(|observed| observed.realpath())
                .is_some_and(|real| {
                    top_levels.iter().all(|top_level| {
                        !nah_proto::labels::lexically_contains(top_level, real.as_str(), platform)
                            && !nah_proto::labels::lexically_contains(
                                real.as_str(),
                                top_level,
                                platform,
                            )
                    })
                }),
            _ => false,
        },
        _ => false,
    }
}

/// The observed project root a Git effect's worktree spells: the worktree
/// itself when it names an observed project root (`git -C <root>`), or, when
/// the repository was found from the invocation's working directory, however
/// the request spells it, the root that directory lies in.
///
/// No `GuardHostFacts` method reads it: the Git selection labels
/// (`observed_labels.rs`) and the Git discard reach (`fact_projection.rs`)
/// share it.
pub(super) fn observed_git_root(
    view: &crate::plan_view::PlanView<'_>,
    observation: &Observation,
    invocation_cwd: &str,
    effect: &effinterp_proto::Effect,
) -> Option<String> {
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
    let effinterp_proto::ResourceExpr::Concrete {
        identity: effinterp_proto::ResourceIdentity::FsPath { path: worktree },
    } = worktree.as_ref()
    else {
        return None;
    };
    if !effect.realm.is_host() {
        return None;
    }
    let separators: &[char] = if view.authority().platform() == nah_proto::ctx::Platform::Windows {
        &['/', '\\']
    } else {
        &['/']
    };
    let observed_cwd = observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Cwd {
                observed: Observed::Ok { value },
            } => Some(value.as_str()),
            _ => None,
        });
    let spells_invocation_cwd = effect.attributes.get("root_uses_invocation_cwd")
        == Some(&effinterp_proto::AttrValue::Bool(true))
        // The engine spells a Windows cwd with `/`, the host with `\`.
        && nah_proto::labels::lexical_path::same_path(
            worktree,
            invocation_cwd,
            view.authority().platform(),
        );
    // A start directory spelled another way, such as through a symlink, is
    // still the invocation's own directory when its observed real path is
    // the observed working directory.
    let observed_as_invocation_cwd = effect.attributes.get("discovers_from_worktree")
        == Some(&effinterp_proto::AttrValue::Bool(true))
        && view
            .observed_path(worktree)
            .and_then(|path| path.realpath())
            .zip(observed_cwd)
            .is_some_and(|(real, cwd)| real.as_str() == cwd);
    if !spells_invocation_cwd && !observed_as_invocation_cwd {
        // Git discovers the repository upward from the named directory; only
        // a directory that is itself an observed project root, by spelling or
        // by observed real path, is known to be that repository's root, not a
        // nested repository inside one.
        let named = worktree.trim_end_matches(separators);
        let real = view
            .observed_path(worktree)
            .and_then(|path| path.realpath())
            .map(|path| path.as_str().trim_end_matches(separators));
        return view
            .authority()
            .observed_roots()
            .iter()
            .any(|root| {
                let root_path = root.path().as_str().trim_end_matches(separators);
                root.kind() == nah_proto::observation::RootKind::Project
                    && (root_path == named || real == Some(root_path))
            })
            .then(|| nah_proto::ctx::AbsolutePath::new(view.authority().platform(), named).ok())
            .flatten()
            .map(|path| path.as_str().to_owned());
    }
    let observed_cwd = observed_cwd?;
    let root = view
        .authority()
        .observed_roots()
        .iter()
        .filter(|root| {
            root.kind() == nah_proto::observation::RootKind::Project
                && nah_proto::labels::lexically_contains(
                    root.path().as_str(),
                    observed_cwd,
                    view.authority().platform(),
                )
        })
        .max_by_key(|root| root.path().as_str().len())?;
    let depth = observed_cwd
        .trim_end_matches(separators)
        .strip_prefix(root.path().as_str().trim_end_matches(separators))
        .map_or(0, |suffix| {
            suffix
                .split(separators)
                .filter(|component| !component.is_empty())
                .count()
        });
    let mut spelled = worktree.trim_end_matches(separators);
    for _ in 0..depth {
        spelled = spelled
            .rsplit_once(separators)
            .map_or(spelled, |(parent, _)| parent);
    }
    nah_proto::ctx::AbsolutePath::new(view.authority().platform(), spelled)
        .ok()
        .map(|path| path.as_str().to_owned())
}

/// A resource's path as requested, resolved and real, sorted and deduplicated.
fn resource_observed_path_spellings(
    view: &crate::plan_view::PlanView<'_>,
    resource: &effinterp_proto::ResourceExpr,
) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some((requested, _)) = crate::observation_request::observation_bound(resource) {
        if let Some(observed) = view.observed_path(&requested) {
            paths.push(observed.resolved().as_str().to_owned());
            if let Some(realpath) = observed.realpath() {
                paths.push(realpath.as_str().to_owned());
            }
        }
        paths.push(requested.into_owned());
    }
    paths.sort();
    paths.dedup();
    paths
}
