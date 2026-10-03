//! Where content flows between the facts: the engine's causality as public
//! occurrences and relations, the purposes and directions that flow proves,
//! and the output ports a disclosed read reaches.

use nah_proto::effects;
use nah_proto::effects::Knowledge::{Known, Unknown};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationQuery, ObservationValue, Observed, PathKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::fact_projection::EffectProjection;
use super::guard_host_facts::ReachedResource;
use super::invocation_calls::add_gap;
use super::resource_projection::{add_resource, convert_condition, convert_port, convert_realm};

/// Bind the engine's causality graph to the projected facts, and derive the
/// access purposes, move destinations and disclosure ports it establishes.
pub(super) fn project_content_flow(
    view: &crate::plan_view::PlanView<'_>,
    graph: &mut effects::EffectGraph,
    effects: &mut EffectProjection,
) {
    use effects::{
        AccessPurpose, CallId, Certainty, Domain, EffectOccurrence, EffectRelation, EffectResource,
        ExecutionSource, FactId, FactPayload, FilesystemOperation, GapPhase, NetworkOperation,
        OccurrenceId, PortKind, Reach, RelationKind, ResourceId, ResourceIdentity, ResourceKind,
        ResourceLabels, Selection, TransferDirection,
    };
    let plan = view.plan();
    let EffectProjection {
        member_effects,
        condition_atoms,
        effect_resources,
        reach,
        effect_facts,
        disclosed_to_output,
        stated_non_content_access,
        ..
    } = effects;
    if let Some(causality) = &plan.causality.graph {
        let mut bound_effects = BTreeSet::new();
        let ids = causality
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id.clone(), OccurrenceId(index as u32)))
            .collect::<BTreeMap<_, _>>();
        for node in &causality.nodes {
            let mut owning_fact = None;
            let (port, resource) = match &node.occurrence {
                effinterp_proto::OccurrenceKind::Port { port } => (convert_port(port), None),
                effinterp_proto::OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    attributes,
                } => {
                    let matches = view
                        .effect_indices_exact(operation.as_str())
                        .filter(|index| {
                            let effect = &plan.effects[*index];
                            effect.operation == *operation
                                && effect.resource == *resource
                                && effect.attributes == *attributes
                                && effect.realm == node.realm
                                && Some(effect.execution) == node.execution
                                && effect.condition == node.condition
                                && effect.modality == node.modality
                                && effect.provenance == node.provenance
                        })
                        .filter(|index| !bound_effects.contains(index))
                        .collect::<Vec<_>>();
                    let target = if let Some(index) = matches.first() {
                        bound_effects.insert(*index);
                        owning_fact = Some(effect_facts[*index]);
                        effect_resources[*index]
                    } else {
                        add_gap(
                            graph,
                            CallId(node.execution.map_or(0, |id| id.0)),
                            Some(Domain::Causal),
                            GapPhase::Translation,
                            "effect-occurrence-binding-unavailable",
                        );
                        let indexed = view
                            .occurrence_resource_id(&node.id)
                            .map(|id| view.resource(id));
                        add_resource(
                            graph,
                            indexed.map_or(resource, |resource| resource.expression),
                            indexed.map_or(&node.realm, |resource| resource.realm),
                            view.authority().platform(),
                            true,
                        )
                    };
                    (PortKind::Interaction, Some(target))
                }
                effinterp_proto::OccurrenceKind::Value { value } => (
                    PortKind::Value,
                    Some({
                        let indexed = view
                            .occurrence_resource_id(&node.id)
                            .map(|id| view.resource(id));
                        add_resource(
                            graph,
                            indexed.map_or(value, |resource| resource.expression),
                            indexed.map_or(&node.realm, |resource| resource.realm),
                            view.authority().platform(),
                            false,
                        )
                    }),
                ),
                effinterp_proto::OccurrenceKind::Boundary { .. } => (PortKind::Interaction, None),
            };
            let condition = convert_condition(node.condition.as_ref(), graph, condition_atoms);
            graph.occurrences.push(EffectOccurrence {
                condition,
                id: ids[&node.id],
                call: CallId(node.execution.map_or(0, |id| id.0)),
                fact: owning_fact,
                resource,
                port,
            });
        }
        for edge in &causality.edges {
            let condition = convert_condition(edge.condition.as_ref(), graph, condition_atoms);
            let kind = match edge.reason {
                effinterp_proto::CausalReason::ValueDependency => RelationKind::ValueDependence,
                effinterp_proto::CausalReason::ControlDependency => RelationKind::Control,
                effinterp_proto::CausalReason::Launch => RelationKind::Launch,
                effinterp_proto::CausalReason::ResourceTransition => RelationKind::StateTransition,
                effinterp_proto::CausalReason::ResourceTransfer => {
                    RelationKind::ContentPreservingTransfer
                }
                effinterp_proto::CausalReason::Alias => RelationKind::Alias,
                effinterp_proto::CausalReason::Containment => RelationKind::Containment,
            };
            graph.relations.push(EffectRelation {
                from: ids[&edge.from],
                to: ids[&edge.to],
                kind,
                condition,
                certainty: match edge.assurance {
                    effinterp_proto::CausalAssurance::Exact => Certainty::Exact,
                    effinterp_proto::CausalAssurance::Conservative => Certainty::Conservative,
                },
            });
        }
        // Move and its source-side deletion share the engine's provenance.
        // Only the modeled transfer edge identifies their destination; argv
        // order and other writes in the same invocation do not.
        for index in view.effect_indices_exact("filesystem.move") {
            let effect = &plan.effects[index];
            let destinations = view
                .occurrences_for_execution(effect.execution)
                .filter(|node| {
                    node.realm == effect.realm
                        && node.condition == effect.condition
                        && node.modality == effect.modality
                        && node.provenance == effect.provenance
                        && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction {
                        resource, ..
                    } if resource == &effect.resource)
                })
                .flat_map(|node| {
                    view.outgoing_edges(&node.id)
                        .filter(move |edge| {
                            edge.from == node.id
                                && edge.reason == effinterp_proto::CausalReason::ResourceTransfer
                                && edge.condition == effect.condition
                        })
                        .collect::<Vec<_>>()
                })
                .filter_map(|edge| {
                    let destination_node = view.causal_node(&edge.to)?;
                    let effinterp_proto::OccurrenceKind::ResourceInteraction {
                        resource: destination_resource,
                        ..
                    } = &destination_node.occurrence
                    else {
                        return None;
                    };
                    let destination = &graph.occurrences[ids[&edge.to].0 as usize];
                    let destination_established =
                        if matches!(effect.resource, effinterp_proto::ResourceExpr::Pattern { .. }) {
                            match (
                                crate::observation_request::observation_bound(&effect.resource),
                                crate::observation_request::observation_bound(destination_resource),
                            ) {
                                (Some((source, _)), Some((destination, _)))
                                    if source == destination =>
                                {
                                    false
                                }
                                (_, Some((destination, _))) => view
                                    .observed_path(&destination)
                                    .map(|value| {
                                        value.kind() == PathKind::Directory
                                            || value.kind() == PathKind::Symlink
                                                && value.target_kind() == Some(PathKind::Directory)
                                    })
                                    .unwrap_or(true),
                                _ => true,
                            }
                        } else {
                            true
                        };
                    (destination.condition == graph.facts[effect_facts[index].0 as usize].condition)
                        .then_some((
                            destination.resource?,
                            edge.assurance,
                            destination_established,
                        ))
                })
                .collect::<Vec<_>>();
            let fact_id = effect_facts[index].0 as usize;
            if !matches!(
                graph.facts[fact_id].payload,
                FactPayload::FilesystemAccess {
                    operation: FilesystemOperation::Move,
                    ..
                }
            ) {
                continue;
            }
            // A transfer edge is the engine's content-preserving claim: the
            // bytes selected here are the bytes that arrive at the other end.
            // That is the same access a declared content destination states,
            // and it holds however precisely the endpoint itself is known.
            if !destinations.is_empty()
                && let FactPayload::FilesystemAccess { purpose, .. } =
                    &mut graph.facts[fact_id].payload
            {
                *purpose = AccessPurpose::Explicit;
            }
            // An exact recursive move with one established modeled
            // destination removes its complete source selection. Destination
            // identity can remain conservative: the paired exact deletion is
            // the physical source reach the declarative filesystem queries
            // classify through their path catalogs. Renaming an observed
            // directory takes its whole tree off that path, so a system-scope
            // directory, a catalogued system tree and the home root each lose
            // their tree. Renaming a link to a directory, as macOS spells
            // `/etc`, `/tmp` and `/var`, takes the tree off its path the same way.
            let complete_source_selection = {
                let resource = &graph.resources[effect_resources[index].0 as usize];
                resource.labels.as_ref().is_some_and(|labels| {
                    let observed_system_tree = resource.selection == Selection::Exact
                        && matches!(&labels.lexical, Known(path)
                        if (labels.scope == Known(nah_proto::labels::PathScope::System)
                            || labels.selects_home == Reach::Yes
                            || nah_proto::labels::system_tree::selects_root_or_system_tree(
                                path.as_str(),
                            ))
                            && view.observed_path(path.as_str()).is_some_and(|value| {
                                value.kind() == PathKind::Directory
                                    || value.kind() == PathKind::Symlink
                                        && value.target_kind() == Some(PathKind::Directory)
                            }));
                    let home_pattern = format!(
                        "{}/*",
                        view.authority().home().as_str().trim_end_matches('/')
                    );
                    let complete_home_selection = matches!(
                        &resource.selection,
                        Selection::Pattern { pattern, .. } if pattern == &home_pattern
                    ) && labels.selects_home == Reach::Yes
                        && labels.scope == Known(nah_proto::labels::PathScope::Home);
                    observed_system_tree || complete_home_selection
                })
            };
            let exact_source_deletion = if complete_source_selection
                && matches!(destinations.as_slice(), [(_, _, true)])
                && plan
                    .coverage
                    .0
                    .get(&effinterp_proto::Domain::new("filesystem"))
                    .is_some_and(|claim| {
                        claim.level == effinterp_proto::CoverageLevel::Full && claim.gaps.is_empty()
                    })
                && graph.facts[fact_id].certainty == Certainty::Exact
                && effect.attributes.get("recursive")
                    == Some(&effinterp_proto::AttrValue::Bool(true))
            {
                plan.effects
                    .iter()
                    .enumerate()
                    .find(|(deletion_index, deletion)| {
                        deletion.operation.as_str() == "filesystem.delete"
                            && graph.facts[effect_facts[*deletion_index].0 as usize].certainty
                                == Certainty::Exact
                            && deletion.resource == effect.resource
                            && deletion.execution == effect.execution
                            && deletion.realm == effect.realm
                            && deletion.condition == effect.condition
                            && effect
                                .provenance
                                .iter()
                                .all(|reference| deletion.provenance.contains(reference))
                    })
            } else {
                None
            };
            if let Some((deletion_index, _)) = exact_source_deletion
                && let Some(source) = &mut reach[deletion_index].own
            {
                source.recursive = true;
            }
            if !matches!(destinations.as_slice(), [(_, assurance, _)]
                if *assurance == effinterp_proto::CausalAssurance::Exact || graph.facts[fact_id].certainty == Certainty::Conservative)
            {
                // Move requires an endpoint in the evidence contract. An
                // uncertified endpoint stays unknown on the exact source
                // fact; the modeled candidate is retained separately below.
                let unknown = ResourceId(graph.resources.len() as u32);
                graph.resources.push(EffectResource {
                    id: unknown,
                    realm: convert_realm(&effect.realm),
                    identity: ResourceIdentity {
                        kind: ResourceKind::HostPath,
                        name: Unknown,
                        provider: Unknown,
                        details: Unknown,
                    },
                    selection: Selection::Unknown,
                    labels: None,
                });
                if let FactPayload::FilesystemAccess { destination, .. } =
                    &mut graph.facts[fact_id].payload
                {
                    *destination = Some(unknown);
                }
            }
            if let [(resource, assurance, established)] = destinations.as_slice() {
                let own = &mut reach[index].own;
                if !established {
                    *own = None;
                } else if *assurance == effinterp_proto::CausalAssurance::Exact {
                    reach[index].destination = own.as_ref().map(|own| ReachedResource {
                        resource: *resource,
                        recursive: own.recursive,
                        device: None,
                    });
                }
            }
            // A multi-source move only reaches its source selection when its
            // destination is a different directory. A proven file, missing
            // path or the source directory itself makes the modeled move a
            // candidate rather than an established destructive request.
            if let [(_, _, false)] = destinations.as_slice() {
                graph.facts[fact_id].certainty = Certainty::Conservative;
            }
            if let [(resource, assurance, _)] = destinations.as_slice() {
                let fact = &graph.facts[fact_id];
                let mut transfer = fact.clone();
                if let FactPayload::FilesystemAccess { destination, .. } = &mut transfer.payload {
                    *destination = Some(*resource);
                    if *assurance == effinterp_proto::CausalAssurance::Conservative {
                        transfer.certainty = Certainty::Conservative;
                    }
                    if transfer.certainty != fact.certainty {
                        // The destination's uncertainty does not weaken the
                        // independently established source selection.
                        transfer.id = FactId(graph.facts.len() as u32);
                        graph.facts.push(transfer);
                    } else {
                        graph.facts[fact_id] = transfer;
                    }
                }
            } else {
                add_gap(
                    graph,
                    CallId(effect.execution.0),
                    Some(Domain::Filesystem),
                    GapPhase::Translation,
                    "move-destination-unavailable",
                );
            }
        }
        for (member_index, (owner, _)) in member_effects.iter().enumerate() {
            let member_index = plan.effects.len() + member_index;
            clone_fact_occurrences(
                graph,
                effect_facts[*owner],
                effect_facts[member_index],
                Some(effect_resources[member_index]),
            );
        }
        // A resource-transfer edge states that the source was read for its
        // contents and the destination received them, even when the engine
        // conservatively identifies which endpoint participated. Preserve
        // those access purposes separately from the edge's endpoint certainty.
        for relation in &graph.relations {
            if relation.kind != RelationKind::ContentPreservingTransfer {
                continue;
            }
            if let Some(fact) = graph.occurrences[relation.from.0 as usize].fact
                && let FactPayload::FilesystemAccess {
                    operation: FilesystemOperation::Read,
                    purpose,
                    ..
                } = &mut graph.facts[fact.0 as usize].payload
            {
                *purpose = AccessPurpose::ProgramInput;
            }
            if let Some(fact) = graph.occurrences[relation.to.0 as usize].fact
                && let FactPayload::FilesystemAccess {
                    operation: FilesystemOperation::Write,
                    purpose,
                    ..
                } = &mut graph.facts[fact.0 as usize].payload
            {
                *purpose = AccessPurpose::Explicit;
            }
        }
        // A hard link gives the source's inode a new name, so writing through
        // the created entry changes the source. An exact transfer from a
        // metadata read of a path into a create by the same call, under one
        // condition, therefore gives the created entry the tier a write to the
        // source carries. A copy writes new content and a conservative pairing
        // proves no link, so neither labels its destination.
        let hard_link_tiers = graph
            .relations
            .iter()
            .filter(|relation| {
                relation.kind == RelationKind::ContentPreservingTransfer
                    && relation.certainty == Certainty::Exact
            })
            .filter_map(|relation| {
                let source =
                    &graph.facts[graph.occurrences[relation.from.0 as usize].fact?.0 as usize];
                let created =
                    &graph.facts[graph.occurrences[relation.to.0 as usize].fact?.0 as usize];
                let (
                    FactPayload::FilesystemAccess {
                        operation: FilesystemOperation::Read,
                        target: source_target,
                        ..
                    },
                    FactPayload::FilesystemAccess {
                        operation: FilesystemOperation::Create,
                        target: created_target,
                        ..
                    },
                ) = (&source.payload, &created.payload)
                else {
                    return None;
                };
                if !stated_non_content_access.contains(&source.id)
                    || source.call != created.call
                    || source.realm != created.realm
                    || source.condition != created.condition
                    || relation.condition != created.condition
                {
                    return None;
                }
                let source_resource = &graph.resources[source_target.0 as usize];
                let Some(ResourceLabels {
                    lexical: Known(path),
                    canonical,
                    ..
                }) = &source_resource.labels
                else {
                    return None;
                };
                if source_resource.selection != Selection::Exact {
                    return None;
                }
                let authority = view.authority();
                nah_proto::labels::tier::nah_protection_tier(
                    nah_proto::action::FilesystemOperation::Write,
                    path,
                    match canonical {
                        Known(canonical) => canonical,
                        Unknown => path,
                    },
                    authority.observed_roots(),
                    authority.trusted_roots(),
                    authority.home(),
                    authority.critical_paths(),
                    authority.platform(),
                    false,
                    false,
                )
                .map(|tier| (*created_target, tier))
            })
            .collect::<Vec<_>>();
        for (created, tier) in hard_link_tiers {
            if let Some(labels) = &mut graph.resources[created.0 as usize].labels
                && !matches!(labels.protection, Known(Some(_)))
            {
                labels.protection = Known(Some(tier));
            }
        }
        // An audited response-body binding establishes the direction of a
        // request without claiming that its response contains any bytes.
        for relation in &graph.relations {
            let from = &graph.occurrences[relation.from.0 as usize];
            let to = &graph.occurrences[relation.to.0 as usize];
            if relation.kind == RelationKind::ValueDependence
                && relation.certainty == Certainty::Exact
                && relation.condition.is_none()
                && from.condition.is_none()
                && to.condition.is_none()
                && from.call == to.call
                && to.port == PortKind::NetworkResponse
                && let Some(fact) = from.fact
                && let FactPayload::NetworkAccess {
                    operation: NetworkOperation::Request,
                    direction,
                    ..
                } = &mut graph.facts[fact.0 as usize].payload
            {
                *direction = Known(TransferDirection::Inbound);
            }
        }
        // Follow audited consumption, not merely an open stdin descriptor: a
        // command such as chmod does not consume its redirected input bytes.
        let mut inputs = vec![Vec::new(); graph.occurrences.len()];
        for relation in &graph.relations {
            if relation.certainty == Certainty::Exact
                && matches!(
                    relation.kind,
                    RelationKind::ValueDependence | RelationKind::ContentPreservingTransfer
                )
                && relation.condition.is_none()
                && graph.occurrences[relation.from.0 as usize]
                    .condition
                    .is_none()
                && graph.occurrences[relation.to.0 as usize]
                    .condition
                    .is_none()
            {
                inputs[relation.to.0 as usize].push(relation.from);
            }
        }
        let mut pending = graph
            .occurrences
            .iter()
            .filter_map(|occurrence| {
                (occurrence.condition.is_none()
                    && (matches!(
                        occurrence.port,
                        PortKind::Stdout | PortKind::Code | PortKind::NetworkRequest
                    ) || occurrence.port == PortKind::Stdin
                        && graph.facts.iter().any(|fact| {
                            fact.call == occurrence.call
                                && matches!(
                                    fact.payload,
                                    FactPayload::ExecutionInput {
                                        source: ExecutionSource::Stdin,
                                        ..
                                    }
                                )
                        })
                        || occurrence.fact.is_some_and(|id| {
                            matches!(
                                graph.facts[id.0 as usize].payload,
                                FactPayload::ExecutionInput { .. }
                                    | FactPayload::NetworkAccess {
                                        operation: NetworkOperation::Upload,
                                        ..
                                    }
                                    // A destination the engine declares to carry
                                    // contents consumes them the same way a port
                                    // does: whatever it was written from was read
                                    // for its bytes, not merely opened.
                                    | FactPayload::FilesystemAccess {
                                        operation: FilesystemOperation::Write,
                                        purpose: AccessPurpose::Explicit,
                                        ..
                                    }
                            )
                        })))
                .then_some(occurrence.id)
            })
            .collect::<Vec<_>>();
        let mut consumed = BTreeSet::new();
        let mut content_reads = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !consumed.insert(id) {
                continue;
            }
            if let Some(fact) = graph.occurrences[id.0 as usize].fact {
                content_reads.insert(fact);
            }
            pending.extend(inputs[id.0 as usize].iter().copied());
        }
        for id in content_reads {
            if let FactPayload::FilesystemAccess {
                operation: FilesystemOperation::Read,
                purpose,
                ..
            } = &mut graph.facts[id.0 as usize].payload
            {
                *purpose = AccessPurpose::ProgramInput;
            }
        }
        // The engine said what was read was written to the command's own
        // output. Name that port, so a credential read or a read of a stored
        // object is a disclosure and not merely a lookup.
        //
        // A shell call carries one output port per builtin that writes to it,
        // so position does not identify the one the value reached. Follow the
        // engine's own dataflow from the read instead; a call whose output the
        // causality leaves unnamed keeps its single stdout.
        for id in disclosed_to_output.iter() {
            let call = graph.facts[id.0 as usize].call;
            let mut pending = graph
                .occurrences
                .iter()
                .filter(|occurrence| occurrence.fact == Some(*id))
                .map(|occurrence| occurrence.id)
                .collect::<Vec<_>>();
            let mut visited = BTreeSet::new();
            let mut reached = None;
            while let Some(occurrence) = pending.pop() {
                if !visited.insert(occurrence) {
                    continue;
                }
                let port = &graph.occurrences[occurrence.0 as usize];
                if port.call == call && port.port == PortKind::Stdout && port.condition.is_none() {
                    reached = Some(occurrence);
                    break;
                }
                pending.extend(
                    graph
                        .relations
                        .iter()
                        .filter(|edge| {
                            edge.from == occurrence
                                && matches!(
                                    edge.kind,
                                    RelationKind::ValueDependence
                                        | RelationKind::ContentPreservingTransfer
                                )
                        })
                        .map(|edge| edge.to),
                );
            }
            let Some(port) = reached.or_else(|| {
                graph
                    .occurrences
                    .iter()
                    .find(|occurrence| {
                        occurrence.call == call
                            && occurrence.port == PortKind::Stdout
                            && occurrence.condition.is_none()
                    })
                    .map(|occurrence| occurrence.id)
            }) else {
                continue;
            };
            match &mut graph.facts[id.0 as usize].payload {
                FactPayload::EnvironmentAccess { output, .. }
                | FactPayload::GitRead { output, .. } => *output = Some(port),
                _ => {}
            }
        }
    } else {
        add_gap(
            graph,
            CallId(0),
            Some(Domain::Causal),
            GapPhase::Translation,
            "causal-detail-unavailable",
        );
    }
}

/// Name the catalogued credentials a disclosed whole environment holds.
pub(super) fn name_disclosed_credentials(
    observation: &Observation,
    graph: &mut effects::EffectGraph,
) {
    use effects::{EnvironmentOperation, EnvironmentSelection, FactId, FactPayload};
    // A disclosed whole environment names no variable, but it discloses every
    // catalogued credential the observation found holding a value. Name those
    // beside it; an empty one discloses nothing.
    let present_credentials = observation
        .facts()
        .iter()
        .filter_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::Env { name, .. },
                ObservationValue::Env {
                    observed:
                        Observed::Ok {
                            value: EnvObservation::Value { text },
                        },
                },
            ) if !text.is_empty() && nah_proto::labels::is_credential_name(name) => {
                Some(name.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if !present_credentials.is_empty() {
        for index in 0..graph.facts.len() {
            if let FactPayload::EnvironmentAccess {
                names: EnvironmentSelection::Whole,
                operation: EnvironmentOperation::Read,
                output: Some(_),
                ..
            } = graph.facts[index].payload
            {
                let mut fact = graph.facts[index].clone();
                fact.id = FactId(graph.facts.len() as u32);
                if let FactPayload::EnvironmentAccess { names, .. } = &mut fact.payload {
                    *names =
                        EnvironmentSelection::Names(present_credentials.iter().cloned().collect());
                }
                graph.facts.push(fact);
            }
        }
    }
}

/// Publish each content-filter read again as the search it answers.
pub(super) fn add_content_searches(
    graph: &mut effects::EffectGraph,
    content_searches: Vec<(effects::FactId, effects::FactPayload)>,
) {
    use effects::FactId;
    // The search shares the read's occurrences: it is the same access, told as
    // the query it answers, so whatever the read reached the search reaches.
    for (read, payload) in content_searches {
        let mut fact = graph.facts[read.0 as usize].clone();
        fact.id = FactId(graph.facts.len() as u32);
        fact.payload = payload;
        clone_fact_occurrences(graph, read, fact.id, None);
        graph.facts.push(fact);
    }
}

/// Give fact `to` a copy of each occurrence of fact `from`, with the
/// relations incident to that occurrence rebound to the copy. `resource`
/// replaces each copy's resource; `None` keeps the original's.
///
/// Each copy reads the relations as they stand when it is made, so an edge
/// between two copied occurrences is copied again for the second one.
/// Occurrence IDs are appended; the caller creates and pushes `to` itself.
pub(super) fn clone_fact_occurrences(
    graph: &mut effects::EffectGraph,
    from: effects::FactId,
    to: effects::FactId,
    resource: Option<effects::ResourceId>,
) {
    let occurrences = graph
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.fact == Some(from))
        .cloned()
        .collect::<Vec<_>>();
    for mut occurrence in occurrences {
        let source = occurrence.id;
        occurrence.id = effects::OccurrenceId(graph.occurrences.len() as u32);
        occurrence.fact = Some(to);
        if let Some(resource) = resource {
            occurrence.resource = Some(resource);
        }
        let relations = graph
            .relations
            .iter()
            .filter(|edge| edge.from == source || edge.to == source)
            .cloned()
            .map(|mut edge| {
                if edge.from == source {
                    edge.from = occurrence.id;
                }
                if edge.to == source {
                    edge.to = occurrence.id;
                }
                edge
            })
            .collect::<Vec<_>>();
        graph.occurrences.push(occurrence);
        graph.relations.extend(relations);
    }
}
