//! Declarative definitions for the system guards: host power state and
//! service stops.

use effinterp_matcher::{
    Assertion, AttributePredicate, AttributeTest, Query, ResourcePredicate, ResourceVariant,
    SelectionShape,
};
use effinterp_proto::{AttrValue, ExecutionAssurance};
use nah_proto::effects::Domain;

use crate::registry::{GuardDefinition, GuardFamily, engine_only};
use crate::shared_queries::{
    bool_attr, present_attr, resource_family, resource_selection, resource_variant,
    success_path_effect,
};

pub(crate) fn sys_power() -> GuardDefinition {
    GuardDefinition {
        id: "sys-power",
        reason: "sys-power blocked a host power action; keep the host running and ask the operator to perform any intentional power action",
        family: GuardFamily::System,
        default_enabled: true,
        domain: Domain::System,
        gap_code: Some("system-action-controls-unavailable"),
        clauses: engine_only(Query::new(success_path_effect(
            "system.power",
            resource_variant(ResourceVariant::HostSystem),
            system_controls(),
            None,
            Some(ExecutionAssurance::Exact),
        ))),
    }
}

pub(crate) fn sys_service_stop() -> GuardDefinition {
    GuardDefinition {
        id: "sys-service-stop",
        reason: "sys-service-stop blocked a reviewed service or stop-all container shutdown; keep the service or containers running and ask the operator to perform any intentional stop",
        family: GuardFamily::System,
        default_enabled: false,
        domain: Domain::System,
        gap_code: Some("system-action-controls-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any {
            assertions: vec![
                success_path_effect(
                    "system.service_stop",
                    ResourcePredicate::AnyOf {
                        predicates: vec![
                            resource_variant(ResourceVariant::ServiceUnit),
                            ResourcePredicate::All {
                                predicates: vec![
                                    resource_family("system"),
                                    resource_selection(SelectionShape::Pattern),
                                ],
                            },
                        ],
                    },
                    system_controls(),
                    None,
                    Some(ExecutionAssurance::Exact),
                ),
                success_path_effect(
                    "container.stop",
                    ResourcePredicate::Any,
                    vec![
                        present_attr("all"),
                        bool_attr("all", true),
                        bool_attr("active", true),
                        bool_attr("dry_run", false),
                    ],
                    None,
                    None,
                ),
            ],
        })),
    }
}

fn system_controls() -> Vec<AttributePredicate> {
    vec![
        bool_attr("active", true),
        bool_attr("cancel", false),
        bool_attr("help", false),
        bool_one_of("runtime_only", &[true, false]),
        bool_one_of("persistent", &[true, false]),
    ]
}

fn bool_one_of(name: &str, values: &[bool]) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::OneOf(values.iter().copied().map(AttrValue::Bool).collect()),
    }
}
