use std::collections::BTreeMap;

use effinterp_engine::{AnalysisLimits, PlanBuilder};
use effinterp_proto::{
    AttrValue, BoundaryClass, Condition, CoverageLevel, Domain, Effect, ExecutionNodeRef,
    ExecutionRealm, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceFamily, ResourceIdentity, Subject, ValidationError, validate_plan,
};

fn unresolved_family(expr: &ResourceExpr, family: &str) -> bool {
    match expr {
        ResourceExpr::Unresolved { family: actual } => actual.0 == family,
        ResourceExpr::Property { base, .. } => unresolved_family(base, family),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => parts.iter().any(|part| unresolved_family(part, family)),
        _ => false,
    }
}

fn test_builder() -> PlanBuilder {
    PlanBuilder::new(
        Subject::Exec {
            argv: vec!["x".into()],
            cwd: None,
            context: Default::default(),
        },
        "test".into(),
        "test".into(),
        AnalysisLimits::default(),
    )
}

#[test]
fn invalid_effect_resources_degrade_to_typed_boundaries() {
    let cases = [
        (
            "network.request",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: String::new(),
                    scheme: None,
                    port: None,
                    path: None,
                },
            },
        ),
        (
            "filesystem.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: "X".into() },
            },
        ),
        (
            "network.request",
            ResourceExpr::Unresolved {
                family: ResourceFamily::new("filesystem"),
            },
        ),
        (
            "filesystem.delete",
            ResourceExpr::Join {
                parts: vec![
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable {
                            name: "APP_ROOT".into(),
                        },
                    },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath {
                            path: "cache".into(),
                        },
                    },
                ],
            },
        ),
        (
            "git.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/srv/repo".into(),
                },
            },
        ),
    ];

    for (operation, resource) in cases {
        let mut builder = test_builder();
        let provenance = vec![builder.node(ProvenanceKind::SourceSpan { start: 1, end: 2 }, &[])];
        let effect = Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: BTreeMap::from([("recursive".into(), AttrValue::Bool(true))]),
            modality: Modality::May,
            condition: Some(Condition::from_source(
                "flag",
                effinterp_proto::ByteSpan { start: 0, end: 4 },
                effinterp_proto::ConditionKind::Branch,
                0,
                2,
                true,
                true,
            )),
            realm: ExecutionRealm::Host,
            execution: ExecutionNodeRef(0),
            provenance,
        };
        let expected = effect.clone();
        builder.effect(effect);

        builder.attest_closure(Domain::new(expected.operation.domain()));
        let plan = builder.finish().unwrap();
        assert_eq!(
            plan.coverage
                .gaps(&Domain::new(expected.operation.domain())),
            &[effinterp_proto::BoundaryRef(0)]
        );
        validate_plan(&plan).unwrap();
        assert_eq!(plan.effects.len(), 1);
        let actual = &plan.effects[0];
        assert_eq!(actual.operation, expected.operation);
        assert_eq!(actual.attributes, expected.attributes);
        assert_eq!(actual.modality, expected.modality);
        assert_eq!(actual.condition, expected.condition);
        assert_eq!(actual.realm, expected.realm);
        assert_eq!(actual.execution, expected.execution);
        assert_eq!(actual.provenance, expected.provenance);
        let replacement = ResourceExpr::Unresolved {
            family: ResourceFamily::new(expected.operation.domain()),
        };
        assert_eq!(actual.resource, replacement);
        assert_eq!(plan.boundaries.len(), 1);
        let boundary = &plan.boundaries[0];
        assert_eq!(boundary.reason.as_str(), "untyped_resource");
        assert_eq!(boundary.class, BoundaryClass::Unresolved);
        assert_eq!(boundary.domains, [Domain::new(expected.operation.domain())]);
        assert_eq!(boundary.provenance, expected.provenance);
        assert_eq!(boundary.affected_resource, Some(replacement));
        assert!(boundary.detail.is_some());
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new(expected.operation.domain()))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Partial)
        );
    }
}

#[test]
fn union_overflow_widens_to_the_operation_family() {
    let mut resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: "/z".into() },
    };
    for _ in 0..40 {
        resource = ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: "/a".into() },
                },
                resource,
            ],
        };
    }

    let mut builder = test_builder();
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("filesystem.read"),
        resource,
        attributes: BTreeMap::new(),
        modality: Modality::May,
        condition: None,
        realm: ExecutionRealm::Host,
        execution: ExecutionNodeRef(0),
        provenance: Vec::new(),
    });

    let plan = builder.finish().unwrap();
    validate_plan(&plan).unwrap();
    assert!(unresolved_family(&plan.effects[0].resource, "filesystem"));
    assert!(!unresolved_family(&plan.effects[0].resource, "unknown"));
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "untyped_resource")
    );
}

#[test]
fn finish_reports_residual_invariant_failures_as_errors() {
    let mut builder = test_builder();
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("filesystem.read"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: "/x".into() },
        },
        attributes: BTreeMap::new(),
        modality: Modality::May,
        condition: None,
        realm: ExecutionRealm::Host,
        execution: ExecutionNodeRef(0),
        provenance: vec![ProvenanceRef(7)],
    });

    let errors = builder.finish().unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::DanglingProvenanceRef { index: 7, .. }
    )));
}

#[test]
fn unregistered_operation_is_retracted_to_a_partial_boundary() {
    let mut builder = test_builder();
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("filesystem.future_delete"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/data".into(),
            },
        },
        attributes: BTreeMap::new(),
        modality: Modality::May,
        condition: None,
        realm: ExecutionRealm::Host,
        execution: ExecutionNodeRef(0),
        provenance: vec![],
    });
    builder.attest_closure(Domain::new("filesystem"));
    let plan = builder.finish().unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.is_empty());
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(plan.boundaries[0].reason.as_str(), "untyped_resource");
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Partial
    );
}
