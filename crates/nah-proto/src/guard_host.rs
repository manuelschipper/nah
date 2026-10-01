//! The contract between the bridge and shipped guard evaluation: the bridge's
//! per-effect host facts that `nah_policy`'s guard evaluation reads, and the
//! typed shipped guard matches it returns to the reducer.

use std::collections::BTreeMap;

use crate::ctx::Platform;
use crate::effects::{CallId, Domain, EffectResource, Reach};
use effinterp_proto::{Bindings, ExecutionNodeRef};

/// One host path a plan effect reaches, as the bridge labeled it.
pub struct ReachedHostPath<'a> {
    pub resource: &'a EffectResource,
    /// The effect selects the path recursively: a subtree selection or an
    /// explicit recursive request.
    pub recursive: bool,
    /// The path of a typed block device, which carries no path labels.
    pub device: Option<&'a str>,
}

/// The bridge's per-effect host facts for shipped guard evaluation, read from
/// the observation the conversion binds. `effect` is a plan effect index.
pub trait GuardHostFacts {
    /// The engine's execution bindings the matcher evaluates effects under.
    fn matcher_bindings(&self) -> BTreeMap<ExecutionNodeRef, Bindings>;
    fn platform(&self) -> Platform;
    /// Whether the effect's condition can hold within the invocation: `No`
    /// only when it is proven impossible, `Unknown` when the condition is
    /// incomplete or too large to decide.
    fn condition_reach(&self, effect: usize) -> Reach;
    /// Whether the conditions of the plan causal nodes and edges at these
    /// positions (in `plan.causality.graph`) can all hold in one run: `No`
    /// only when they are proven mutually impossible.
    fn causal_route_reach(&self, nodes: &[usize], edges: &[usize]) -> Reach;
    /// The effect's target has an identified resource kind.
    fn target_identified(&self, effect: usize) -> bool;
    /// The model that planned the effect is trusted to be the program its
    /// call runs. The bridge records a refusal as a coverage gap on the call.
    fn model_identity_established(&self, effect: usize) -> bool;
    /// What the effect selects: its own selection, each member of a finite
    /// selection, and the paths a Git discard replaces or removes.
    fn selected_host_paths(&self, effect: usize) -> Vec<ReachedHostPath<'_>>;
    /// The effect selects its resource recursively: a subtree selection or an
    /// explicit recursive request.
    fn selects_recursively(&self, effect: usize) -> bool;
    /// Where a move's single certified transfer lands.
    fn move_destination(&self, effect: usize) -> Option<ReachedHostPath<'_>>;
    /// The spellings the observation gives a requested path: the path as
    /// requested, resolved, and its real path, sorted and deduplicated. Empty
    /// for a resource that names no observable path.
    fn observed_path_spellings(&self, resource: &effinterp_proto::ResourceExpr) -> Vec<String>;
    /// The root call's command text holds characters that make the operator's
    /// display of it differ from what runs (`EffectCall::hidden_characters`).
    fn command_has_hidden_characters(&self) -> bool;
}

/// A coverage gap a shipped guard names for a call whose query was
/// indeterminate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShippedGuardGap {
    pub call: CallId,
    pub domain: Domain,
    pub code: &'static str,
}

/// The shipped guard matches of one conversion: the guards that matched, in
/// evaluation order, and the gaps indeterminate guards named.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShippedGuardMatches {
    pub matched: Vec<&'static str>,
    pub gaps: Vec<ShippedGuardGap>,
}

impl ShippedGuardMatches {
    /// Whether the shipped guard `id` matched.
    pub fn matched(&self, id: &str) -> bool {
        self.matched.contains(&id)
    }
}
