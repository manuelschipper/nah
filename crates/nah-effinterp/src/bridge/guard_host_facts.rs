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
        let effect = &self.view.plan().effects[effect];
        effect.attributes.get("recursive") == Some(&effinterp_proto::AttrValue::Bool(true))
            || crate::observation_request::subtree_root(&effect.resource).is_some()
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
        resource_paths(self.view, resource)
    }

    fn command_has_hidden_characters(&self) -> bool {
        self.graph.calls.iter().any(|call| call.hidden_characters)
    }
}

/// The observed project root a Git effect's worktree spells: the worktree
/// itself when it names an observed project root (`git -C <root>`), or, when
/// the repository was found from the invocation's working directory, however
/// the request spells it, the root that directory lies in.
///
/// No `GuardHostFacts` method reads it: the Git selection labels
/// (`label_propagation.rs`) and the Git discard reach (`fact_projection.rs`)
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
                && nah_proto::labels::contains(
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
fn resource_paths(
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
