use Knowledge::{Known, Unknown};
use nah_proto::action::Coverage;
use nah_proto::effects::*;

fn graph() -> EffectGraph {
    EffectGraph {
        calls: vec![EffectCall {
            id: CallId(0),
            parent: None,
            kind: InvocationKind::Native,
            identity: Known("Read".into()),
            input: None,
            cwd: Unknown,
            payload_group: Known(PayloadGroupId(0)),
            visibility_ordinal: Known(0),
            coverage: Coverage::Full,
        }],
        resources: vec![],
        facts: vec![],
        occurrences: vec![],
        relations: vec![],
        conditions: vec![],
        coverage: vec![],
        gaps: vec![],
        causality: CausalAvailability::Unavailable,
    }
}
fn public() -> PublicSelection {
    PublicSelection {
        calls: [CallId(0)].into(),
        facts: Default::default(),
        resources: Default::default(),
        occurrences: Default::default(),
        relations: Default::default(),
        complete: true,
    }
}

#[test]
fn graph_rejects_duplicate_dangling_and_cross_realm_evidence() {
    let mut draft = graph();
    draft.calls.push(draft.calls[0].clone());
    assert_eq!(
        GuardEvidence::new(draft, public()),
        Err(EvidenceError::DuplicateId)
    );
    let mut draft = graph();
    draft.calls[0].parent = Some(CallId(9));
    assert_eq!(
        GuardEvidence::new(draft, public()),
        Err(EvidenceError::DanglingReference)
    );
    let mut draft = graph();
    draft.resources.push(EffectResource {
        id: ResourceId(0),
        realm: Realm::Remote { identity: Unknown },
        identity: ResourceIdentity {
            details: Unknown,
            kind: ResourceKind::HostPath,
            provider: Unknown,
            name: Known("/etc/passwd".into()),
        },
        selection: Selection::Exact,
        labels: None,
    });
    draft.facts.push(EffectFact {
        id: FactId(0),
        call: CallId(0),
        realm: Realm::Host,
        certainty: Certainty::Conservative,
        modality: Modality::May,
        condition: None,
        occurrences: None,
        payload: FactPayload::TreeStateLoss {
            target: ResourceId(0),
            class: TreeClass::System,
        },
    });
    assert_eq!(
        GuardEvidence::new(draft.clone(), public()),
        Err(EvidenceError::InvalidLabelRealm)
    );
    draft.facts[0].realm = draft.resources[0].realm.clone();
    draft.resources[0].labels = Some(ResourceLabels {
        lexical: Unknown,
        canonical: Unknown,
        scope: Unknown,
        sensitivity: Unknown,
        protection: Unknown,
        host_integrity: Unknown,
        selects_project: Reach::Unknown,
        selects_home: Reach::Unknown,
        selects_root: Reach::Unknown,
        is_symlink: Unknown,
        link_target: Unknown,
        descendants_complete: Unknown,
        reach: vec![],
    });
    assert_eq!(
        GuardEvidence::new(draft.clone(), public()),
        Err(EvidenceError::InvalidLabelRealm)
    );
    draft.resources[0].labels = None;
    draft.facts[0].realm = Realm::Host;
    draft.resources[0].realm = Realm::Host;
    draft.resources[0].identity.kind = ResourceKind::Process;
    assert_eq!(
        GuardEvidence::new(draft, public()),
        Err(EvidenceError::InvalidPayload)
    );
}

#[test]
fn public_selection_is_closed_and_bounded_per_payload_without_truncating_safety() {
    let mut draft = graph();
    for id in 1..130 {
        let mut call = draft.calls[0].clone();
        call.id = CallId(id);
        call.payload_group = Known(PayloadGroupId(id / 64));
        call.visibility_ordinal = Known(id % 64);
        draft.calls.push(call);
    }
    let mut selection = public();
    selection.facts.insert(FactId(99));
    assert_eq!(
        GuardEvidence::new(draft.clone(), selection.clone()),
        Err(EvidenceError::DanglingReference)
    );
    selection.facts.clear();
    selection.calls = draft.calls.iter().map(|c| c.id).collect();
    assert_eq!(
        GuardEvidence::new(draft.clone(), selection.clone())
            .unwrap()
            .graph()
            .calls
            .len(),
        130
    );
    draft.calls[64].payload_group = Known(PayloadGroupId(0));
    draft.calls[64].visibility_ordinal = Known(64);
    assert_eq!(
        GuardEvidence::new(draft.clone(), selection.clone()),
        Err(EvidenceError::InvalidProjection)
    );
    selection.calls.remove(&CallId(64));
    selection.complete = false;
    let evidence = GuardEvidence::new(draft, selection).unwrap();
    assert_eq!(evidence.public_calls().count(), 129);
    assert_eq!(evidence.graph().calls.len(), 130);
}

#[test]
fn conditions_preserve_negation_and_exclusive_arms() {
    let mut draft = graph();
    draft.conditions = vec![
        EffectCondition {
            complete: true,
            id: ConditionId(0),
            expression: ConditionExpr::Literal { atom: 0 },
            alternative_group: Some(AlternativeGroupId(0)),
        },
        EffectCondition {
            complete: true,
            id: ConditionId(1),
            expression: ConditionExpr::Literal { atom: 1 },
            alternative_group: Some(AlternativeGroupId(0)),
        },
        EffectCondition {
            complete: true,
            id: ConditionId(2),
            expression: ConditionExpr::Not(ConditionId(0)),
            alternative_group: None,
        },
    ];
    let evidence = GuardEvidence::new(draft.clone(), public()).unwrap();
    let positive = |id| ConditionUse {
        id: ConditionId(id),
        positive: true,
    };
    assert_eq!(
        evidence.conditions_compatible(&[positive(0), positive(1)]),
        Reach::No
    );
    assert_eq!(
        evidence.conditions_compatible(&[positive(0), positive(2)]),
        Reach::No
    );
    assert_eq!(
        evidence.conditions_compatible(&[positive(1), positive(2)]),
        Reach::Yes
    );
    draft.conditions[2].expression = ConditionExpr::Not(ConditionId(2));
    assert_eq!(
        GuardEvidence::new(draft, public()),
        Err(EvidenceError::Cycle)
    );
}

#[test]
fn abstract_evidence_and_missing_coverage_do_not_invent_flows_or_growth() {
    let mut draft = graph();
    draft.facts.push(EffectFact {
        id: FactId(0),
        call: CallId(0),
        realm: Realm::Host,
        certainty: Certainty::Exact,
        modality: Modality::May,
        condition: None,
        occurrences: None,
        payload: FactPayload::ExecutionInput {
            resource: None,
            port: None,
            source: ExecutionSource::Unknown,
            derivation: ExecutionDerivation::Decoded,
            visible_payload: VisiblePayload::Absent,
        },
    });
    let evidence = GuardEvidence::new(draft, public()).unwrap();
    assert!(evidence.graph().resources.is_empty());
    assert!(evidence.graph().relations.is_empty());
    assert!(evidence.graph().coverage.is_empty());
    assert_eq!(evidence.graph().causality, CausalAvailability::Unavailable);
    assert_eq!(evidence.graph().facts[0].certainty, Certainty::Exact);
    assert_eq!(evidence.graph().facts[0].modality, Modality::May);
    assert_ne!(Unknown, Known(false));
    assert_ne!(Bound::Unknown, Bound::Unbounded);
}
