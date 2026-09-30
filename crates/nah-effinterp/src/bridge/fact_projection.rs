//! Which typed fact each plan effect is: its operation projected onto a
//! `FactPayload`, with the certainty the engine's assurance supports.

use effinterp_proto as p;
use nah_proto::effects as e;
use nah_proto::effects::Knowledge::{Known, Unknown};
use std::collections::{BTreeMap, BTreeSet};

use super::ShippedGuardPolicy;
use super::guard_host_facts::{HostReach, ReachedResource, observed_git_root};
use super::input_selection::native_access_purpose;
use super::invocation_calls::{add_gap, add_untranslated_effect_gap};
use super::resource_projection::{
    add_structural_path_resource, convert_condition, convert_modality, convert_realm,
    effect_target_resource, identify_package_target, label_effect_target_path, whole_environment,
};

/// A boolean effect attribute; any other value or none is unknown.
pub(super) fn effect_attr_bool(effect: &p::Effect, key: &str) -> e::Knowledge<bool> {
    match effect.attributes.get(key) {
        Some(p::AttrValue::Bool(value)) => Known(*value),
        _ => Unknown,
    }
}

/// A string effect attribute; any other value or none is unknown.
pub(super) fn effect_attr_text(effect: &p::Effect, key: &str) -> e::Knowledge<String> {
    match effect.attributes.get(key) {
        Some(p::AttrValue::String(value)) => Known(value.clone()),
        _ => Unknown,
    }
}

/// Operations whose public certainty is the owning model's request
/// assurance. The artifact requests (`artifact.publish_request`,
/// `artifact.remove_request`, `artifact.yank_request`) are deliberately
/// absent: their certainty comes from the general rules for the resource they
/// name, and custom exec/v2 guards read that certainty, so certifying them
/// here would change which of those guards block.
const MODEL_CERTIFIED_OPERATIONS: &[&str] = &[
    "git.push_request",
    "git.history_rewrite_request",
    "git.recovery_destroy_request",
    "git.ref_delete_request",
    "network.delete_request",
    "git.clean_request",
    "git.reset_request",
    "git.worktree_discard_request",
    "credential.read_request",
    "credential.delete_request",
    "process.stream_transform",
];

/// Whether the effect is a Git request whose registered outcome discards
/// worktree contents: a clean, reset or worktree discard.
fn requests_worktree_discard(effect: &p::Effect) -> bool {
    effect
        .operation
        .spec()
        .is_some_and(|spec| spec.outcomes.contains(&"git.worktree_discard"))
}

/// Text typed into another terminal and not submitted: an input that runs
/// the program the text names once someone submits it there.
fn terminal_input_fact(effect: &p::Effect, target: e::ResourceId) -> e::FactPayload {
    use e::*;
    FactPayload::ControlInput {
        target,
        action: ControlAction::Deliver,
        transport: ControlTransport::Input,
        payload_certainty: Certainty::Conservative,
        candidate_identity: Unknown,
        tier: crate::annotate::terminal_input_tier(effect).map_or(Unknown, Known),
    }
}

/// What projecting the plan's effects leaves for the passes after it. Indices
/// run over the plan's effects and then the finite selections' members.
pub(super) struct EffectProjection {
    /// Each finite selection's members, by the index of the effect selecting them.
    pub(super) member_effects: Vec<(usize, p::Effect)>,
    pub(super) condition_atoms: BTreeMap<String, u32>,
    /// Each effect's public target resource.
    pub(super) effect_resources: Vec<e::ResourceId>,
    /// What each plan effect physically reaches on the host, for the path
    /// catalogs of the declarative filesystem guards.
    pub(super) reach: Vec<HostReach>,
    /// Each effect's own fact.
    pub(super) effect_facts: Vec<e::FactId>,
    /// Reads the engine says were written to the command's own output.
    pub(super) disclosed_to_output: Vec<e::FactId>,
    /// Accesses whose semantics the engine states as reaching something other
    /// than the object's contents.
    pub(super) stated_non_content_access: BTreeSet<e::FactId>,
    /// Content-filter reads, told again as the search they answer.
    pub(super) content_searches: Vec<(e::FactId, e::FactPayload)>,
}

/// The gap on a call whose program the filesystem models are not trusted to
/// describe: it runs by an absolute path outside the standard executable
/// directories (`nah_proto::labels::standard_executable_directory`).
pub(super) const MODEL_IDENTITY_GAP: &str = "model-identity-unestablished";

/// Project every plan effect, and each member of a finite selection, into
/// its target resource and typed fact.
pub(super) fn project_effect_facts(
    view: &crate::plan_view::PlanView<'_>,
    observation: &nah_proto::observation::Observation,
    invocation_cwd: &str,
    graph: &mut e::EffectGraph,
    guards: &ShippedGuardPolicy<'_>,
) -> EffectProjection {
    use e::*;
    let plan = view.plan();
    let member_effects = view
        .effects()
        .flat_map(|(index, effect)| {
            crate::observe::finite_members(&effect.resource)
                .into_iter()
                .flatten()
                .map(move |member| {
                    let mut selected = effect.clone();
                    selected.resource = member.clone();
                    (index, selected)
                })
        })
        .collect::<Vec<_>>();
    let mut condition_atoms = BTreeMap::new();
    let mut effect_resources = Vec::<ResourceId>::new();
    // What each plan effect physically reaches on the host, for the path
    // catalogs of the declarative filesystem guards.
    let mut reach = Vec::<HostReach>::new();
    let mut effect_facts = Vec::new();
    let mut disclosed_to_output = Vec::new();
    // Accesses whose semantics the engine states as reaching something other
    // than the object's contents. They carry no disclosure purpose because
    // none applies, so the access-semantics gap below must not read their
    // empty purpose as evidence the bridge failed to find.
    let mut stated_non_content_access = BTreeSet::new();
    let mut content_searches = Vec::new();
    for (effect_index, (effect, annotation)) in (0..plan.effects.len())
        .map(|index| (&plan.effects[index], view.annotation(index).clone()))
        .chain(
            member_effects
                .iter()
                .map(|(_, effect)| (effect, view.annotate_synthetic(effect))),
        )
        .enumerate()
    {
        let call = CallId(effect.execution.0);
        let realm = convert_realm(&effect.realm);
        let (target, aliased_remote) = effect_target_resource(
            view,
            graph,
            effect,
            effect_index,
            &member_effects,
            &effect_resources,
        );
        effect_resources.push(target);
        let reached = ReachedResource {
            resource: target,
            // A pattern ending in `**` selects every entry at every depth
            // below its bound, as a recursive operation does.
            recursive: crate::observe::subtree_root(&effect.resource).is_some()
                || effect.attributes.get("recursive") == Some(&p::AttrValue::Bool(true))
                || matches!(
                    &effect.resource,
                    p::ResourceExpr::Pattern {
                        pattern: p::ResourcePattern::FsPath { glob },
                    } if glob.ends_with("/**")
                ),
            device: match &effect.resource {
                p::ResourceExpr::Concrete {
                    identity: p::ResourceIdentity::BlockDevice { device },
                } => nah_proto::ctx::AbsolutePath::new(view.authority().platform(), device).ok(),
                _ => None,
            },
        };
        if effect_index < plan.effects.len() {
            reach.push(HostReach {
                target,
                own: Some(reached),
                selected: vec![],
                destination: None,
            });
        } else {
            // A finite selection reaches each of its members.
            reach[member_effects[effect_index - plan.effects.len()].0]
                .selected
                .push(reached);
        }
        label_effect_target_path(view, graph, effect, target, annotation);
        let attr_bool = |key: &str| effect_attr_bool(effect, key);
        let attr_text = |key: &str| effect_attr_text(effect, key);
        let control_tier = if effect.realm.is_host() && effect.operation.as_str() == "process.exec"
        {
            crate::annotate::process_protection_tier(view, effect)
        } else {
            Known(None)
        };
        // Nah control arguments to a program the engine could not locate:
        // whether it is nah's installed binary stays open.
        if control_tier == Unknown {
            add_gap(
                graph,
                call,
                Some(Domain::Process),
                GapPhase::Translation,
                "nah-process-identity-unresolved",
            );
        }
        let control_tier = match control_tier {
            Known(tier) => tier,
            Unknown => None,
        };
        // A package client states which package it publishes, yanks or hands
        // over, on its request and on that request's registered outcome; an
        // image or release push names no client and keeps its own typed
        // identity.
        let package_request = effect.operation.as_str() == "artifact.owner_change"
            || effect.operation.domain() == "artifact"
                && effect
                    .operation
                    .spec()
                    .is_some_and(|spec| !spec.outcomes.is_empty());
        let package_outcome = p::OPERATIONS.iter().any(|request| {
            request.domain == "artifact" && request.outcomes.contains(&effect.operation.as_str())
        });
        if (package_request || package_outcome) && matches!(attr_text("package_manager"), Known(_))
        {
            identify_package_target(
                graph,
                target,
                attr_text("package"),
                attr_text("version"),
                attr_text("registry"),
                attr_text("scope"),
            );
            if package_request {
                graph.resources[target.0 as usize].identity.provider = match attr_text("ecosystem")
                {
                    Known(value) if value == "rubygems" => Known("gem".into()),
                    Known(value) => Known(value),
                    Unknown => attr_text("package_manager"),
                };
            }
        }
        let discard_filesystem_operation = match attr_text("discard_mode") {
            Known(mode)
                if matches!(
                    mode.as_str(),
                    "clean" | "worktree_remove" | "worktree_prune" | "submodule_deinit"
                ) =>
            {
                Some(FilesystemOperation::Delete)
            }
            Known(mode) if matches!(mode.as_str(), "reset" | "restore" | "checkout" | "switch") => {
                Some(FilesystemOperation::Write)
            }
            _ => None,
        };
        // A clean selects everything untracked beneath the path it is given;
        // every other discard replaces the path itself.
        let subtree_selection = attr_text("discard_mode") == Known("clean".into());
        let git_selection = |path: nah_proto::ctx::AbsolutePath, graph: &EffectGraph| {
            if subtree_selection
                || matches!(
                    &graph.resources[target.0 as usize].identity.details,
                    Known(ResourceDetails::Git { worktree: Known(root), .. }) if root == &path
                )
            {
                Selection::Subtree { root: Known(path) }
            } else {
                Selection::NamedSet {
                    identities: vec![ResourceIdentity {
                        kind: ResourceKind::HostPath,
                        provider: Unknown,
                        name: Known(path.as_str().into()),
                        details: Unknown,
                    }],
                    bound: Bound::Finite(1),
                }
            }
        };
        // The plain discard states the one path it selects, once per path,
        // where the audited request beside it numbers the whole selection.
        let mut git_selections = if effect.operation.as_str() == "git.worktree_discard" {
            match attr_text("selection_path") {
                Known(path) => nah_proto::ctx::AbsolutePath::new(view.authority().platform(), path)
                    .ok()
                    .map(|path| git_selection(path, graph))
                    .into_iter()
                    .collect(),
                Unknown => vec![],
            }
        } else if requests_worktree_discard(effect)
            // A path-limited reset rewrites index entries, never the worktree,
            // so its selection is not a discard.
            && effect.operation.as_str() != "git.reset_request"
            && attr_bool("selection_complete") == Known(true)
        {
            match effect.attributes.get("selections") {
                Some(p::AttrValue::List(selections)) => selections
                    .iter()
                    .map(|selection| match selection {
                        p::AttrValue::String(path) => {
                            nah_proto::ctx::AbsolutePath::new(view.authority().platform(), path)
                                .ok()
                                .map(|path| git_selection(path, graph))
                        }
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                    .unwrap_or_default(),
                _ => vec![],
            }
        } else {
            vec![]
        };
        // `:/` also selects the top Git discovers, which is the observed root.
        if attr_bool("selects_top") == Known(true)
            && let Some(top) = observed_git_root(view, observation, invocation_cwd, effect)
            && let Ok(top) = nah_proto::ctx::AbsolutePath::new(view.authority().platform(), top)
        {
            let top = git_selection(top, graph);
            if !git_selections.contains(&top) {
                git_selections.push(top);
            }
        }
        let payload = effect_fact_payload(view, graph, effect, call, target, control_tier, guards);
        // A model selected by basename does not establish that an arbitrary
        // absolute-path executable, or one PATH left unresolved, implements
        // that basename's filesystem API. The refusal is a gap on the call, so
        // coverage says the effect was not understood and the host rules of
        // the filesystem guards read it back instead of matching.
        let filesystem_model_path_untrusted = nah_proto::labels::filesystem_model_untrusted(
            view.plan(),
            effect,
            view.authority().platform(),
        ) || (effect.operation.domain() == "filesystem"
            && crate::annotate::model_identity_unresolved(view.plan(), effect));
        if filesystem_model_path_untrusted
            && !graph
                .gaps
                .iter()
                .any(|gap| gap.call == call && gap.code == MODEL_IDENTITY_GAP)
        {
            add_gap(
                graph,
                call,
                Some(Domain::Filesystem),
                GapPhase::Translation,
                MODEL_IDENTITY_GAP,
            );
        }
        let condition = convert_condition(effect.condition.as_ref(), graph, &mut condition_atoms);
        effect_facts.push(FactId(graph.facts.len() as u32));
        // `metadata` and `partition_table` are the engine's statements that an
        // access reaches a path's entry or a device's partition table rather
        // than the bytes the object holds. Nah's filesystem payload has no
        // operation for a metadata read, so the access keeps the object it
        // names; what it must not keep is a disclosure purpose, because the
        // engine has said the contents are not what is touched.
        if matches!(payload, FactPayload::FilesystemAccess { .. })
            && (attr_bool("metadata") == Known(true) || attr_bool("partition_table") == Known(true))
        {
            stated_non_content_access.insert(FactId(graph.facts.len() as u32));
        }
        graph.facts.push(EffectFact {
            id: FactId(graph.facts.len() as u32),
            call,
            realm,
            certainty: if effect_index >= plan.effects.len() {
                // Membership does not strengthen the request: a union may
                // describe alternatives, rather than execution of every member.
                let owner = member_effects[effect_index - plan.effects.len()].0;
                graph.facts[effect_facts[owner].0 as usize].certainty
            } else if filesystem_model_path_untrusted {
                Certainty::Conservative
            } else if matches!(payload, FactPayload::ExecutionInput { .. })
                || MODEL_CERTIFIED_OPERATIONS.contains(&effect.operation.as_str())
            {
                // Accepted input mode and physical interpreter identity are
                // independent. Only the owning model can certify the request.
                match effect.request_assurance {
                    p::RequestAssurance::Exact => Certainty::Exact,
                    p::RequestAssurance::Conservative => Certainty::Conservative,
                }
            } else if (matches!(payload, FactPayload::FilesystemAccess { .. })
                && effect.request_assurance == p::RequestAssurance::Exact
                // An exact request says what was asked for, not what it acts
                // on. A resource of known family and unknown identity leaves
                // the target open, and a destructive fact whose target is
                // unidentified reads to the filesystem guards as reaching
                // every root.
                && !matches!(effect.resource, p::ResourceExpr::Unresolved { .. })
                && graph.resources[target.0 as usize].identity.kind != ResourceKind::Unknown)
                // A pattern names no single member, but for these payloads it
                // selects at least what any member would: a read of a pattern
                // discloses whatever the pattern's own labels say it covers,
                // and a write the engine states is a raw-device write reaches raw storage whichever device the
                // selector matches — the engine certifies that kind on the
                // pattern itself, and `fs-raw-device` decides on the kind
                // rather than on which device it is. An ordinary write or a
                // deletion is not in that set, because there the identity
                // decides what is written over or lost.
                || (matches!(effect.resource, p::ResourceExpr::Pattern { .. })
                    && (matches!(
                        payload,
                        FactPayload::FilesystemAccess {
                            operation: FilesystemOperation::Read,
                            ..
                        }
                            // The environment pattern that reads everything
                            // leaves no member unnamed: the selection is the
                            // whole environment, however many variables it
                            // holds.
                            | FactPayload::EnvironmentAccess {
                                names: EnvironmentSelection::Whole,
                                operation: EnvironmentOperation::Read,
                                ..
                            }
                    ) || matches!(
                        payload,
                        FactPayload::FilesystemAccess {
                            operation: FilesystemOperation::Write,
                            ..
                        }
                    ) && attr_bool("raw_device") == Known(true))
                    && view.execution(effect.execution).assurance
                        == p::ExecutionAssurance::Exact)
                || (matches!(effect.resource, p::ResourceExpr::Concrete { .. })
                    && view.execution(effect.execution).assurance
                        == p::ExecutionAssurance::Exact)
                // What leaves the host is supplied locally, so an outbound
                // transfer is established by the invocation that performs it
                // even when the peer is not named: a listener has no peer yet
                // and a dynamic address names none. What arrives is the peer's,
                // and an unnamed peer leaves that content open, so an inbound
                // transfer keeps the engine's assurance. A sync that carries
                // only a configured alias is excluded: what it actually sends —
                // a dry run sends nothing — is stated by git's own facts.
                || (matches!(
                    payload,
                    FactPayload::NetworkAccess {
                        direction: Known(TransferDirection::Outbound),
                        ..
                    }
                ) && !aliased_remote
                    && view.execution(effect.execution).assurance
                        == p::ExecutionAssurance::Exact)
            {
                Certainty::Exact
            } else {
                Certainty::Conservative
            },
            modality: convert_modality(effect.modality),
            condition,
            occurrences: None,
            payload,
        });
        if matches!(effect.operation.as_str(), "environment.read" | "git.read")
            && attr_text("output") == Known("stdout".into())
        {
            disclosed_to_output.push(graph.facts.last().expect("inserted fact").id);
        }
        // A content filter reads its subject to answer a query. The read alone
        // says the bytes were consumed; the query and what the program prints
        // are what a credential search is recognized by, so they are published
        // beside it rather than folded into the access.
        if effect.operation.as_str() == "filesystem.read"
            && attr_bool("content_filter") == Known(true)
        {
            content_searches.push((
                graph.facts.last().expect("inserted fact").id,
                FactPayload::FilesystemSearch {
                    target,
                    selection: graph.resources[target.0 as usize].selection.clone(),
                    query: attr_text("query"),
                    kind: SearchKind::Content,
                    recursive: attr_bool("recursive"),
                    output: match attr_text("output_mode") {
                        Known(mode) if mode == "content" => SearchOutput::Content,
                        Known(mode) if mode == "filenames" => SearchOutput::Names,
                        Known(mode) if mode == "count" => SearchOutput::None,
                        _ => SearchOutput::Unknown,
                    },
                },
            ));
        }
        if requests_worktree_discard(effect)
            && effect.request_assurance == p::RequestAssurance::Exact
            && attr_bool("active") == Known(true)
            && attr_bool("dry_run") == Known(false)
        {
            let Some(operation) = discard_filesystem_operation else {
                continue;
            };
            let paths = git_selections
                .iter()
                .flat_map(|selection| match selection {
                    Selection::Subtree { root: Known(root) } => vec![root.clone()],
                    Selection::NamedSet { identities, .. } => identities
                        .iter()
                        .filter_map(|identity| match (&identity.kind, &identity.name) {
                            (ResourceKind::HostPath, Known(path)) => {
                                nah_proto::ctx::AbsolutePath::new(view.authority().platform(), path)
                                    .ok()
                            }
                            _ => None,
                        })
                        .collect(),
                    _ => vec![],
                })
                .collect::<Vec<_>>();
            for path in paths {
                let target = add_structural_path_resource(graph, path, operation, view.authority());
                if effect_index < plan.effects.len() {
                    reach[effect_index].selected.push(ReachedResource {
                        resource: target,
                        recursive: false,
                        device: None,
                    });
                }
                graph.facts.push(EffectFact {
                    id: FactId(graph.facts.len() as u32),
                    call,
                    realm: Realm::Host,
                    certainty: Certainty::Exact,
                    // This summarizes the discard selection's filesystem
                    // reach; Git, not a direct path operation, performs it.
                    modality: Modality::May,
                    // The shipped producer conservatively protects every
                    // concrete path a reachable Git discard names.
                    condition: None,
                    occurrences: None,
                    payload: FactPayload::FilesystemAccess {
                        operation,
                        target,
                        destination: None,
                        recursive: Known(false),
                        truncate: Unknown,
                        permissions: PermissionGrants {
                            world_write: Unknown,
                            setuid: Unknown,
                            setgid: Unknown,
                        },
                        purpose: AccessPurpose::Explicit,
                    },
                });
            }
        }
    }
    // A write that only adds the entries the plan lists as writes of their
    // own does not write the directory it adds them to.
    for (index, effect) in view.effects() {
        if effect_attr_bool(effect, "entries_only") == Known(true) {
            reach[index].own = None;
            graph.resources[effect_resources[index].0 as usize].labels = None;
        }
    }
    EffectProjection {
        member_effects,
        condition_atoms,
        effect_resources,
        reach,
        effect_facts,
        disclosed_to_output,
        stated_non_content_access,
        content_searches,
    }
}

/// The typed payload an effect's operation projects onto, read from the
/// attributes the engine states beside it.
#[allow(clippy::too_many_arguments)]
fn effect_fact_payload(
    view: &crate::plan_view::PlanView<'_>,
    graph: &mut e::EffectGraph,
    effect: &p::Effect,
    call: e::CallId,
    target: e::ResourceId,
    control_tier: Option<nah_proto::labels::NahProtectionTier>,
    guards: &ShippedGuardPolicy<'_>,
) -> e::FactPayload {
    use e::*;
    let plan = view.plan();
    let attr_bool = |key: &str| effect_attr_bool(effect, key);
    let attr_text = |key: &str| effect_attr_text(effect, key);
    match effect.operation.as_str() {
        // A resource read has no destructive qualifiers for Nah to
        // translate. Its typed target and operation are the complete fact;
        // the API and live inventory remain environmental boundaries.
        "container.resource.read"
            if effect.attributes.is_empty()
                && matches!(
                    &effect.resource,
                    p::ResourceExpr::Concrete {
                        identity: p::ResourceIdentity::KubernetesResource { .. },
                    }
                ) =>
        {
            FactPayload::Other {
                operation: effect.operation.as_str().into(),
                domain: effect.operation.domain().into(),
                resource_kind: "modeled".into(),
                resources: vec![target],
            }
        }
        // A repository read names the repository it reads, and — for an
        // object read — the object and the revision it reads it at. The
        // engine states an object only when the invocation spells one, so
        // a status, a log or a dry-run prune leaves both unknown rather
        // than selecting the repository's contents.
        "git.read" => FactPayload::GitRead {
            repository: target,
            object: attr_text("object"),
            revision: attr_text("revision"),
            content_sensitivity: match (
                attr_text("disclosure"),
                attr_text("path"),
                &graph.resources[target.0 as usize].identity.details,
            ) {
                (
                    Known(disclosure),
                    Known(path),
                    Known(ResourceDetails::Git {
                        worktree: Known(worktree),
                        ..
                    }),
                ) if disclosure == "contents" && !path.is_empty() => {
                    // Classify the stated Git selection without observing
                    // a host file. Both an object read and a worktree diff
                    // disclose the selected path's contents.
                    let selected = nah_proto::ctx::AbsolutePath::new(
                        view.authority().platform(),
                        nah_proto::labels::join(
                            worktree.as_str(),
                            &path,
                            view.authority().platform(),
                        ),
                    )
                    .expect("tree path joined to an absolute worktree");
                    Known(nah_proto::labels::sensitivity::sensitivity(
                        &path,
                        &selected,
                        view.authority().home(),
                        view.authority().platform(),
                        false,
                    ))
                }
                _ => Unknown,
            },
            // Occurrences are numbered after every fact, so the port the
            // read's content reaches is bound below.
            output: None,
        },
        // A stash moves uncommitted work between the working tree and the
        // stash. The engine states that the invocation is a stash
        // operation and identifies its repository; it does not name the
        // entry or say which way the work moves, so neither is claimed.
        "git.worktree_write" if attr_bool("stash") == Known(true) => FactPayload::GitStash {
            repository: target,
            selection: Selection::Unknown,
            worktree_rewritten: Unknown,
        },
        // Git's own working-tree write states no semantic fields because
        // there are none to state: the tree is rewritten from what the
        // invocation already named, and Git refuses to overwrite
        // uncommitted work. A write that does lose work is stated as a
        // `git.worktree_discard` beside this one. Nothing here is a
        // translation the bridge is missing, so the effect is published
        // without a gap.
        "git.worktree_write" if effect.attributes.is_empty() => FactPayload::Other {
            operation: effect.operation.as_str().into(),
            domain: effect.operation.domain().into(),
            resource_kind: "modeled".into(),
            resources: vec![target],
        },
        // Updating the index is ordinary staging work. The repository is
        // the whole identity the engine states, and there are no guard
        // controls to translate from this bare effect.
        "git.index_write" if effect.attributes.is_empty() => FactPayload::Other {
            operation: effect.operation.as_str().into(),
            domain: effect.operation.domain().into(),
            resource_kind: "modeled".into(),
            resources: vec![target],
        },
        // Deletion requests reach the secret-store guards as queries;
        // a read stays typed because custom guards receive it.
        "credential.read_request" if matches!(attr_text("mode"), Known(ref mode) if mode == "value" || mode == "metadata") => {
            FactPayload::CredentialAccess {
                target,
                operation: if attr_text("mode") == Known("value".into()) {
                    CredentialOperation::ReadValue
                } else {
                    CredentialOperation::ReadMetadata
                },
                deletion: DeletionMode::Unknown,
                workflow: match attr_text("workflow") {
                    Known(mode) if mode == "ordinary" => CredentialWorkflow::Ordinary,
                    Known(mode) if mode == "run" => CredentialWorkflow::Run,
                    Known(mode) if mode == "inject" => CredentialWorkflow::Inject,
                    _ => CredentialWorkflow::Unknown,
                },
                purpose: match attr_text("purpose") {
                    Known(mode) if mode == "explicit" => AccessPurpose::Explicit,
                    Known(mode) if mode == "program_input" => AccessPurpose::ProgramInput,
                    _ => AccessPurpose::Unknown,
                },
            }
        }
        "process.exec" if control_tier.is_some() => FactPayload::ControlMutation {
            target,
            action: ControlAction::Other,
            candidate_identity: Unknown,
            tier: control_tier.map_or(Unknown, Known),
        },
        // A launch establishes the program started, the arguments it was
        // given and where its analysis continues. It does not establish
        // what the started program then does to anything it controls: a
        // terminal multiplexer's session or another agent's pane stay
        // outside this fact, and the engine claims no effect on them.
        "process.exec" => {
            // An execution whose program the engine could not name carries
            // no path and no argument vector to publish either.
            let (path, argv) = match &effect.resource {
                p::ResourceExpr::Concrete {
                    identity: p::ResourceIdentity::Process { path, argv, .. },
                } => (path.as_deref(), Some(argv)),
                _ => (None, None),
            };
            FactPayload::ProcessExecution {
                target,
                path: path
                    .and_then(|path| {
                        nah_proto::ctx::AbsolutePath::new(view.authority().platform(), path).ok()
                    })
                    .map_or(Unknown, Known),
                arguments: argv.map_or(Unknown, |argv| {
                    Known(
                        argv.iter()
                            .map(|argument| match argument {
                                p::ResourceExpr::Literal { value } => Known(value.clone()),
                                _ => Unknown,
                            })
                            .collect(),
                    )
                }),
                // The plan holds one execution effect per execution node,
                // so every node this one launched continues this
                // execution: a nested shell, an interpreter, a startup
                // file. Their own effects arrive as their own facts.
                nested_subjects: plan
                    .execution_graph
                    .edges
                    .iter()
                    .filter(|edge| edge.from.0 == effect.execution.0 && !edge.cycle)
                    .map(|edge| CallId(edge.to.0))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            }
        }
        "process.code_execution" if attr_text("source") == Known("terminal_input".into()) => {
            terminal_input_fact(effect, target)
        }
        "process.code_execution" if matches!(attr_text("source"), Known(ref source) if matches!(source.as_str(), "stdin" | "file" | "argument" | "interactive")) => {
            FactPayload::ExecutionInput {
                resource: Some(target),
                port: None,
                source: match attr_text("source") {
                    Known(source) if source == "stdin" => ExecutionSource::Stdin,
                    Known(source) if source == "file" => ExecutionSource::File,
                    Known(source) if source == "argument" => ExecutionSource::Argument,
                    _ => ExecutionSource::Interactive,
                },
                derivation: if attr_text("encoding") == Known("base64".into()) {
                    ExecutionDerivation::Encoded
                } else if attr_text("derivation") == Known("unresolved_command".into()) {
                    ExecutionDerivation::UnresolvedCommand
                } else {
                    ExecutionDerivation::Plain
                },
                visible_payload: VisiblePayload::Absent,
            }
        }
        "filesystem.read"
        | "filesystem.move"
        | "filesystem.write"
        | "filesystem.create"
        | "filesystem.delete"
        | "filesystem.metadata" => FactPayload::FilesystemAccess {
            operation: match effect.operation.as_str() {
                "filesystem.read" => FilesystemOperation::Read,
                "filesystem.move" => FilesystemOperation::Move,
                "filesystem.create" => FilesystemOperation::Create,
                "filesystem.delete" => FilesystemOperation::Delete,
                "filesystem.metadata" if matches!(attr_text("action"), Known(ref action) if matches!(action.as_str(), "chmod" | "chown" | "chgrp")) => {
                    FilesystemOperation::PermissionChange
                }
                "filesystem.metadata" => FilesystemOperation::MetadataMutation,
                _ if attr_bool("metadata") == Known(true) => FilesystemOperation::MetadataMutation,
                _ => FilesystemOperation::Write,
            },
            target,
            destination: None,
            recursive: if crate::observe::subtree_root(&effect.resource).is_some() {
                Known(true)
            } else {
                attr_bool("recursive")
            },
            truncate: attr_bool("truncate"),
            permissions: PermissionGrants {
                world_write: attr_bool("world_write"),
                setuid: attr_bool("setuid"),
                setgid: attr_bool("setgid"),
            },
            purpose: match native_access_purpose(&view.execution(effect.execution).subject) {
                AccessPurpose::Explicit => AccessPurpose::Explicit,
                // A disclosed read is asked for by name: the invocation
                // selects the object and the model states that its
                // contents are what leaves. That is the same purpose a
                // native file read carries, whichever store holds the
                // bytes.
                _ if attr_text("disclosure") == Known("contents".into()) => AccessPurpose::Explicit,
                _ if attr_text("access_purpose") == Known("program_input".into())
                    && !view.effects_exact("filesystem.move").any(|move_effect| {
                        move_effect.execution == effect.execution
                            && move_effect.realm == effect.realm
                            && move_effect.condition == effect.condition
                            && move_effect.operation.as_str() == "filesystem.move"
                            && move_effect.resource == effect.resource
                    }) =>
                {
                    AccessPurpose::ProgramInput
                }
                _ if attr_text("access_purpose") == Known("implicit_authentication".into()) => {
                    AccessPurpose::ImplicitAuthentication
                }
                _ => AccessPurpose::Unknown,
            },
        },
        "network.delete_request"
            if attr_text("method") == Known("DELETE".into())
                && attr_bool("delete") == Known(true)
                && matches!(attr_text("hosted_target_kind"), Known(ref kind) if kind == "repository" || kind == "resource") =>
        {
            let repository = attr_text("hosted_target_kind") == Known("repository".into());
            let resource = &mut graph.resources[target.0 as usize];
            resource.identity.kind = if repository {
                ResourceKind::HostedRepository
            } else {
                ResourceKind::HostedResource
            };
            resource.identity.provider = attr_text("hosted_provider");
            // A CLI selector does not identify the remote repository or object.
            resource.selection = Selection::Unknown;
            FactPayload::HostedDeletion {
                target,
                kind: if repository {
                    HostedTarget::Repository
                } else {
                    HostedTarget::Resource
                },
                provider: attr_text("hosted_provider"),
                object_kind: attr_text("hosted_object_kind"),
                selection: Selection::Unknown,
                delete: Known(true),
            }
        }
        "network.connect"
        | "network.listen"
        | "network.request"
        | "network.upload"
        | "network.download"
        | "network.delete_request" => {
            if attr_bool("delete") == Known(true) || attr_text("method") == Known("DELETE".into()) {
                add_gap(
                    graph,
                    call,
                    Some(Domain::Network),
                    GapPhase::Translation,
                    "network-delete-resource-kind-unavailable",
                );
            }
            FactPayload::NetworkAccess {
                operation: match effect.operation.as_str() {
                    "network.connect" => NetworkOperation::Connect,
                    "network.listen" => NetworkOperation::Listen,
                    "network.upload" => NetworkOperation::Upload,
                    "network.download" => NetworkOperation::Download,
                    _ => NetworkOperation::Request,
                },
                target,
                direction: match effect.operation.as_str() {
                    "network.upload" => Known(TransferDirection::Outbound),
                    "network.download" => Known(TransferDirection::Inbound),
                    _ => Unknown,
                },
                ports: vec![],
                attached_execution: Unknown,
            }
        }
        "artifact.delete"
            if graph.resources.iter().any(|resource| {
                resource.id == target && resource.identity.kind == ResourceKind::HostedResource
            }) =>
        {
            FactPayload::HostedDeletion {
                target,
                kind: HostedTarget::Resource,
                provider: Known("github".into()),
                object_kind: Known("release".into()),
                selection: graph
                    .resources
                    .iter()
                    .find(|resource| resource.id == target)
                    .expect("converted resource")
                    .selection
                    .clone(),
                delete: Known(true),
            }
        }
        "environment.read" | "environment.write" => FactPayload::EnvironmentAccess {
            names: match &effect.resource {
                p::ResourceExpr::Concrete {
                    identity: p::ResourceIdentity::EnvironmentVariable { name },
                } => EnvironmentSelection::Names(vec![name.clone()]),
                resource if whole_environment(resource) => EnvironmentSelection::Whole,
                _ => EnvironmentSelection::Unknown,
            },
            operation: if effect.operation.as_str() == "environment.read" {
                EnvironmentOperation::Read
            } else {
                EnvironmentOperation::Write
            },
            // A named read or an explicitly disclosed whole environment
            // identifies its selection. Other patterns leave it open.
            purpose: match &effect.resource {
                p::ResourceExpr::Concrete {
                    identity: p::ResourceIdentity::EnvironmentVariable { .. },
                } => AccessPurpose::Explicit,
                p::ResourceExpr::Pattern {
                    pattern: p::ResourcePattern::EnvironmentVariable { name_glob },
                } if name_glob == "*" && attr_text("output") == Known("stdout".into()) => {
                    AccessPurpose::Explicit
                }
                _ => AccessPurpose::Unknown,
            },
            // Occurrences are numbered after every fact, so the port the
            // disclosed value reaches is bound below.
            output: None,
        },
        _ => {
            add_untranslated_effect_gap(view, graph, effect, call, guards);
            FactPayload::Other {
                operation: effect.operation.as_str().into(),
                domain: effect.operation.domain().into(),
                resource_kind: "modeled".into(),
                resources: vec![target],
            }
        }
    }
}
