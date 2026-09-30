use effinterp_engine::Engine;
use effinterp_proto::{
    ExecutionAssurance, Modality, Plan, RequestAssurance, ResourceExpr, ResourceFamily, Subject,
    ValidationError, redact_plan, validate_plan, validate_redacted,
};

fn shell(source: &str) -> Plan {
    Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap()
}

#[test]
fn only_complete_sh_and_bash_stdin_requests_are_certified() {
    for command in ["sh", "bash", "sh -s", "sh -s extra", "bash -", "/bin/sh"] {
        let plan = shell(&format!("curl https://example.com/script | {command}"));
        let certified: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.request_assurance == RequestAssurance::Exact)
            .collect();
        assert_eq!(certified.len(), 1, "{command}");
        assert_eq!(certified[0].operation.as_str(), "process.code_execution");
        assert_eq!(certified[0].modality, Modality::May);
        assert_eq!(
            certified[0].attributes["source"],
            effinterp_proto::AttrValue::String("stdin".into())
        );
    }
    let standalone = shell("sh -s");
    assert!(
        standalone
            .effects
            .iter()
            .all(|effect| effect.request_assurance == RequestAssurance::Conservative)
    );
    for command in [
        "sh -n",
        "bash -n -s",
        "sh - extra",
        "sh --bad",
        "sh $OPTIONS",
        "sh$SUFFIX",
        "sh -c true",
        "sh -x /tmp/script",
        "dash",
        "zsh",
        "python",
        "node",
    ] {
        let plan = shell(&format!("curl https://example.com/script | {command}"));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.request_assurance == RequestAssurance::Conservative),
            "{command}"
        );
    }
    let plan = shell("printf 'rm /victim' | sh");
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete")
    );
    assert!(
        plan.effects
            .iter()
            .filter(|effect| !matches!(
                effect.operation.as_str(),
                "process.code_execution" | "filesystem.delete"
            ))
            .all(|effect| effect.request_assurance == RequestAssurance::Conservative)
    );
    let deletion = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "filesystem.delete")
        .unwrap();
    assert_eq!(deletion.request_assurance, RequestAssurance::Exact);
    assert_eq!(deletion.modality, Modality::May);
    let conditional = shell("test -e /flag && printf 'code' | sh -s");
    assert!(
        conditional
            .effects
            .iter()
            .any(|effect| effect.request_assurance == RequestAssurance::Exact
                && effect.condition.is_some()
                && effect.modality == Modality::May)
    );
}

#[test]
fn request_proof_is_required_and_survives_identity_and_redaction_without_a_target() {
    let mut plan = shell("printf 'code' | sh -s");
    plan.causality.graph = None;
    let index = plan
        .effects
        .iter()
        .position(|effect| effect.request_assurance == RequestAssurance::Exact)
        .unwrap();
    // An accepted input mode does not establish a physical interpreter identity.
    plan.effects[index].resource = ResourceExpr::Unresolved {
        family: ResourceFamily::new("process"),
    };
    plan.stamp_effect_ids().unwrap();
    validate_plan(&plan).unwrap();
    let encoded = serde_json::to_value(&plan).unwrap();
    let decoded: Plan = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded.effects[index], plan.effects[index]);
    let view = redact_plan(&plan);
    validate_redacted(&view).unwrap();
    assert_eq!(
        view.effects[index].request_assurance,
        RequestAssurance::Exact
    );
    assert_eq!(view.effects[index].id, plan.effects[index].id);
    let mut missing = encoded;
    missing["effects"][index]
        .as_object_mut()
        .unwrap()
        .remove("request_assurance");
    assert!(serde_json::from_value::<Plan>(missing).is_err());
    let exact_id = plan.effects[index].id.clone();
    plan.effects[index].request_assurance = RequestAssurance::Conservative;
    plan.stamp_effect_ids().unwrap();
    assert_ne!(plan.effects[index].id, exact_id);
}

#[test]
fn uncertain_selection_and_widening_cannot_transport_exact_request_proof() {
    let plan = shell("printf 'code' | sh -s");
    let index = plan
        .effects
        .iter()
        .position(|effect| effect.request_assurance == RequestAssurance::Exact)
        .unwrap();
    for assurance in [
        ExecutionAssurance::Alternatives,
        ExecutionAssurance::Heuristic,
        ExecutionAssurance::Widened,
    ] {
        let mut changed = plan.clone();
        // The owning node remains Exact: an uncertain ancestor must also revoke proof.
        changed.execution_graph.nodes[0].assurance = assurance;
        assert!(
            validate_plan(&changed)
                .unwrap_err()
                .contains(&ValidationError::InvalidRequestAssurance { effect: index })
        );
        assert!(validate_redacted(&redact_plan(&changed)).is_err());
    }
    let mut widened = plan.clone();
    widened.effects[index].condition = Some(effinterp_proto::Condition::Widened);
    widened.stamp_effect_ids().unwrap();
    assert!(
        validate_plan(&widened)
            .unwrap_err()
            .contains(&ValidationError::InvalidRequestAssurance { effect: index })
    );
    let mut unowned = plan;
    unowned.effects[index].provenance.clear();
    assert!(
        validate_plan(&unowned)
            .unwrap_err()
            .contains(&ValidationError::InvalidRequestAssurance { effect: index })
    );
}

#[test]
fn builder_revokes_request_proof_when_it_retracts_resource_or_condition() {
    use effinterp_engine::{AnalysisLimits, PlanBuilder};
    use effinterp_proto::{CoverageLevel, Domain, ProvenanceKind};
    let plan = shell("printf 'code' | sh -s");
    let effect = plan
        .effects
        .iter()
        .find(|effect| effect.request_assurance == RequestAssurance::Exact)
        .unwrap();
    for invalid_resource in [false, true] {
        let mut builder = PlanBuilder::new(
            plan.subject.clone(),
            "test".into(),
            "test".into(),
            AnalysisLimits::default(),
        );
        let model = builder.node(
            ProvenanceKind::ModelApplication {
                model: "test/request".into(),
            },
            &[],
        );
        let mut effect = effect.clone();
        effect.provenance = vec![model];
        if invalid_resource {
            effect.resource = ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath {
                    path: "/wrong-family".into(),
                },
            };
        } else {
            effect.condition = Some(effinterp_proto::Condition::Widened);
        }
        builder.effect(effect);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let result = builder.finish().unwrap();
        assert_eq!(result.effects.len(), 1);
        assert_eq!(
            result.effects[0].request_assurance,
            RequestAssurance::Conservative
        );
    }
}
