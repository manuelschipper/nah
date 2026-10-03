//! Evidence graph validation: the rules an `EffectGraph` and its
//! `PublicSelection` must meet before `GuardEvidence::new` accepts them.
//! Every broken rule is reported as an `EvidenceError`.

use super::*;

fn unique<T: Ord>(ids: impl Iterator<Item = T>) -> Result<BTreeSet<T>, EvidenceError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(EvidenceError::DuplicateId);
        }
    }
    Ok(seen)
}
/// Each item by its id, refusing a repeated id. Validation looks references
/// up here, so its work stays near-linear in the graph's size.
fn index<K: Ord, V>(items: &[V], id: impl Fn(&V) -> K) -> Result<BTreeMap<K, &V>, EvidenceError> {
    let mut indexed = BTreeMap::new();
    for item in items {
        if indexed.insert(id(item), item).is_some() {
            return Err(EvidenceError::DuplicateId);
        }
    }
    Ok(indexed)
}
pub(super) fn require_evidence(value: bool, error: EvidenceError) -> Result<(), EvidenceError> {
    if value { Ok(()) } else { Err(error) }
}

pub(super) fn validate_effect_graph(graph: &EffectGraph) -> Result<(), EvidenceError> {
    // Conditions count like any other item: a relation between two
    // conditional occurrences carries its own conjunction, so their number
    // grows with the relations rather than with the command.
    require_evidence(
        graph.calls.len()
            + graph.resources.len()
            + graph.facts.len()
            + graph.occurrences.len()
            + graph.relations.len()
            + graph.gaps.len()
            + graph.conditions.len()
            <= 65536,
        EvidenceError::ExceedsLimit,
    )?;
    let calls = index(&graph.calls, |v| v.id)?;
    let resources = index(&graph.resources, |v| v.id)?;
    let facts = index(&graph.facts, |v| v.id)?;
    let occurrences = unique(graph.occurrences.iter().map(|v| v.id))?;
    let conditions = index(&graph.conditions, |v| v.id)?;
    let gaps = unique(graph.gaps.iter().map(|v| v.id))?;
    let condition = |v: &Option<ConditionUse>| {
        require_evidence(
            v.as_ref().is_none_or(|c| conditions.contains_key(&c.id)),
            EvidenceError::DanglingReference,
        )
    };
    for call in &graph.calls {
        require_evidence(
            call.parent.is_none_or(|id| calls.contains_key(&id)),
            EvidenceError::DanglingReference,
        )?;
        if let Some(input) = &call.input {
            require_evidence(
                serde_json::to_vec(input.invocation_input())
                    .map_err(|_| EvidenceError::InvalidPayload)?
                    .len()
                    <= 1024 * 1024,
                EvidenceError::ExceedsLimit,
            )?;
        }
        let mut seen = BTreeSet::new();
        let mut parent = Some(call.id);
        while let Some(id) = parent {
            require_evidence(seen.insert(id), EvidenceError::Cycle)?;
            parent = calls.get(&id).and_then(|c| c.parent);
        }
    }
    for c in &graph.conditions {
        let mut pending = vec![(c.id, BTreeSet::new())];
        let mut work = 0;
        while let Some((id, mut ancestors)) = pending.pop() {
            work += 1;
            require_evidence(work <= 4096, EvidenceError::ExceedsLimit)?;
            require_evidence(ancestors.insert(id), EvidenceError::Cycle)?;
            let node = conditions
                .get(&id)
                .ok_or(EvidenceError::DanglingReference)?;
            let children = match &node.expression {
                ConditionExpr::Literal { .. } => vec![],
                ConditionExpr::All(ids) | ConditionExpr::Any(ids) => ids.clone(),
                ConditionExpr::Not(id) => vec![*id],
            };
            pending.extend(children.into_iter().map(|id| (id, ancestors.clone())));
        }
    }
    for resource in &graph.resources {
        if let Some(labels) = &resource.labels {
            require_evidence(
                resource.realm == Realm::Host && resource.identity.kind == ResourceKind::HostPath,
                EvidenceError::InvalidLabelRealm,
            )?;
            for path in [&labels.lexical, &labels.canonical, &labels.link_target] {
                if let Knowledge::Known(path) = path {
                    require_evidence(
                        is_lexically_normalized_path(path.as_str()),
                        EvidenceError::InvalidLabel,
                    )?;
                }
            }
            if let Knowledge::Known(PathScope::Project { root }) = &labels.scope {
                require_evidence(
                    is_lexically_normalized_path(root.as_str()),
                    EvidenceError::InvalidLabel,
                )?;
                let inside = [&labels.lexical, &labels.canonical]
                    .iter()
                    .any(|path| match path {
                        Knowledge::Known(path) => {
                            path == root
                                || crate::action::is_path_descendant(path.as_str(), root.as_str())
                        }
                        Knowledge::Unknown => false,
                    });
                require_evidence(inside, EvidenceError::InvalidLabel)?;
            }
            // Every observed descendant of a selected tree is an identity here,
            // so the bound follows the observation bound.
            require_evidence(
                labels.reach.len() <= crate::observation::MAX_DESCENDANT_PATHS + 4096,
                EvidenceError::ExceedsLimit,
            )?;
            unique(labels.reach.iter().map(|reach| &reach.identity))?;
            require_evidence(
                labels
                    .reach
                    .iter()
                    .all(|reach| is_lexically_normalized_path(reach.identity.as_str())),
                EvidenceError::InvalidLabel,
            )?;
            require_evidence(
                labels.is_symlink != Knowledge::Known(false)
                    || matches!(labels.link_target, Knowledge::Unknown),
                EvidenceError::InvalidLabel,
            )?;
        }
    }
    for fact in &graph.facts {
        require_evidence(
            calls.contains_key(&fact.call),
            EvidenceError::DanglingReference,
        )?;
        condition(&fact.condition)?;
        let allowed_kinds: Option<&[ResourceKind]> = match &fact.payload {
            FactPayload::FilesystemAccess { .. } | FactPayload::FilesystemSearch { .. } => {
                Some(&[ResourceKind::HostPath])
            }
            FactPayload::GitRead { .. } | FactPayload::GitStash { .. } => Some(&[
                ResourceKind::GitRepository,
                ResourceKind::GitWorktree,
                ResourceKind::GitRef,
            ]),
            FactPayload::HostedDeletion {
                kind: HostedTarget::Repository,
                ..
            } => Some(&[ResourceKind::HostedRepository]),
            FactPayload::HostedDeletion {
                kind: HostedTarget::Resource,
                ..
            } => Some(&[ResourceKind::HostedResource]),
            FactPayload::ProcessExecution { .. } => Some(&[ResourceKind::Process]),
            FactPayload::NetworkAccess { .. } => Some(&[ResourceKind::Endpoint]),
            FactPayload::CredentialAccess { .. } => Some(&[
                ResourceKind::CredentialStore,
                ResourceKind::CredentialObject,
            ]),
            _ => None,
        };
        for id in fact.payload.resource_ids() {
            let resource = resources.get(&id).ok_or(EvidenceError::DanglingReference)?;
            require_evidence(
                resource.realm == fact.realm,
                EvidenceError::InvalidLabelRealm,
            )?;
            require_evidence(
                allowed_kinds.is_none_or(|allowed| {
                    resource.identity.kind == ResourceKind::Unknown
                        || allowed.contains(&resource.identity.kind)
                }),
                EvidenceError::InvalidPayload,
            )?;
        }
        require_evidence(
            fact.payload
                .occurrence_ids()
                .iter()
                .all(|id| occurrences.contains(id)),
            EvidenceError::DanglingReference,
        )?;
        if let Some(bounds) = &fact.occurrences {
            require_evidence(
                bounds.lower > 0 && !matches!(bounds.upper, Bound::Finite(n) if n < bounds.lower),
                EvidenceError::InvalidBounds,
            )?;
        }
        if let FactPayload::FilesystemAccess {
            operation,
            target,
            destination,
            ..
        } = &fact.payload
        {
            require_evidence(
                if *operation == FilesystemOperation::Move {
                    destination.is_some_and(|id| id != *target)
                } else {
                    destination.is_none()
                },
                EvidenceError::InvalidPayload,
            )?;
        }
        if let FactPayload::ProcessExecution {
            nested_subjects, ..
        } = &fact.payload
        {
            require_evidence(
                nested_subjects.iter().all(|id| calls.contains_key(id)),
                EvidenceError::DanglingReference,
            )?;
        }
        if let FactPayload::Other {
            operation,
            domain,
            resource_kind,
            ..
        } = &fact.payload
        {
            require_evidence(
                [operation, domain, resource_kind]
                    .iter()
                    .all(|v| stable_code(v)),
                EvidenceError::InvalidPayload,
            )?;
        }
        if let FactPayload::FilesystemSearch {
            query: Knowledge::Known(query),
            ..
        } = &fact.payload
        {
            require_evidence(query.len() <= 4096, EvidenceError::ExceedsLimit)?;
        }
    }
    for occurrence in &graph.occurrences {
        condition(&occurrence.condition)?;
        if let Some(id) = occurrence.fact {
            let fact = facts.get(&id).ok_or(EvidenceError::DanglingReference)?;
            require_evidence(fact.call == occurrence.call, EvidenceError::InvalidPayload)?;
        }
        require_evidence(
            calls.contains_key(&occurrence.call)
                && occurrence.fact.is_none_or(|id| facts.contains_key(&id))
                && occurrence
                    .resource
                    .is_none_or(|id| resources.contains_key(&id)),
            EvidenceError::DanglingReference,
        )?;
    }
    for relation in &graph.relations {
        require_evidence(
            occurrences.contains(&relation.from) && occurrences.contains(&relation.to),
            EvidenceError::DanglingReference,
        )?;
        condition(&relation.condition)?;
        require_evidence(
            !matches!(relation.kind, RelationKind::ConservativeDataflow { .. })
                || relation.certainty == Certainty::Conservative,
            EvidenceError::InvalidPayload,
        )?;
    }
    for gap in &graph.gaps {
        require_evidence(
            calls.contains_key(&gap.call),
            EvidenceError::DanglingReference,
        )?;
        require_evidence(stable_code(&gap.code), EvidenceError::InvalidGap)?;
    }
    let mut claims = BTreeSet::new();
    for claim in &graph.coverage {
        require_evidence(
            claims.insert((claim.call, format!("{:?}", claim.domain))),
            EvidenceError::InvalidCoverage,
        )?;
        require_evidence(
            calls.contains_key(&claim.call) && claim.gaps.iter().all(|id| gaps.contains(id)),
            EvidenceError::DanglingReference,
        )?;
        require_evidence(
            claim.level != ClaimLevel::Full || claim.gaps.is_empty(),
            EvidenceError::InvalidCoverage,
        )?;
    }
    Ok(())
}
fn stable_code(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.' | b'_')
        })
}

pub(super) fn validate_public_selection(
    graph: &EffectGraph,
    public: &PublicSelection,
) -> Result<(), EvidenceError> {
    let calls = graph.calls.iter().map(|c| c.id).collect::<BTreeSet<_>>();
    let facts = graph.facts.iter().map(|f| f.id).collect::<BTreeSet<_>>();
    let resources = graph
        .resources
        .iter()
        .map(|r| r.id)
        .collect::<BTreeSet<_>>();
    let occurrences = graph
        .occurrences
        .iter()
        .map(|o| o.id)
        .collect::<BTreeSet<_>>();
    require_evidence(
        public.calls.is_subset(&calls)
            && public.facts.is_subset(&facts)
            && public.resources.is_subset(&resources)
            && public.occurrences.is_subset(&occurrences)
            && public
                .relations
                .iter()
                .all(|id| *id < graph.relations.len()),
        EvidenceError::DanglingReference,
    )?;
    let mut groups = BTreeMap::new();
    for call in graph.calls.iter().filter(|c| public.calls.contains(&c.id)) {
        let (Knowledge::Known(group), Knowledge::Known(ordinal)) =
            (&call.payload_group, &call.visibility_ordinal)
        else {
            return Err(EvidenceError::InvalidProjection);
        };
        let ordinals = groups.entry(*group).or_insert_with(BTreeSet::new);
        require_evidence(
            ordinals.insert(*ordinal) && ordinals.len() <= 64,
            EvidenceError::InvalidProjection,
        )?;
        require_evidence(
            call.parent.is_none_or(|id| public.calls.contains(&id)),
            EvidenceError::InvalidProjection,
        )?;
    }
    for fact in graph.facts.iter().filter(|f| public.facts.contains(&f.id)) {
        require_evidence(
            public.calls.contains(&fact.call)
                && fact
                    .payload
                    .resource_ids()
                    .iter()
                    .all(|id| public.resources.contains(id))
                && fact
                    .payload
                    .occurrence_ids()
                    .iter()
                    .all(|id| public.occurrences.contains(id)),
            EvidenceError::InvalidProjection,
        )?;
    }
    for occurrence in graph
        .occurrences
        .iter()
        .filter(|o| public.occurrences.contains(&o.id))
    {
        require_evidence(
            public.calls.contains(&occurrence.call)
                && occurrence.fact.is_none_or(|id| public.facts.contains(&id))
                && occurrence
                    .resource
                    .is_none_or(|id| public.resources.contains(&id)),
            EvidenceError::InvalidProjection,
        )?;
    }
    for index in &public.relations {
        let relation = &graph.relations[*index];
        require_evidence(
            public.occurrences.contains(&relation.from)
                && public.occurrences.contains(&relation.to),
            EvidenceError::InvalidProjection,
        )?;
    }
    require_evidence(
        !public.complete || !graph.gaps.iter().any(|g| g.phase == GapPhase::Projection),
        EvidenceError::InvalidProjection,
    )
}
