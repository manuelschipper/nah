//! Predicate builders the shipped guard definitions share.

use effinterp_matcher::{
    Assertion, AttributePredicate, AttributeTest, ConditionPredicate, OperationMatch,
    ResourcePredicate, ResourceVariant, SelectionShape, Selector,
};
use effinterp_proto::{AttrValue, ExecutionAssurance, RequestAssurance};

pub(crate) fn resource_family(value: &str) -> ResourcePredicate {
    ResourcePredicate::Family {
        family: value.into(),
    }
}

pub(crate) fn resource_variant(value: ResourceVariant) -> ResourcePredicate {
    ResourcePredicate::Variant { variant: value }
}

pub(crate) fn resource_selection(shape: SelectionShape) -> ResourcePredicate {
    ResourcePredicate::Selection { shape }
}

pub(crate) fn bool_attr(name: &str, value: bool) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::Equals(AttrValue::Bool(value)),
    }
}

pub(crate) fn string_attr(name: &str, value: &str) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::Equals(AttrValue::String(value.into())),
    }
}

pub(crate) fn string_one_of(name: &str, values: &[&str]) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::OneOf(
            values
                .iter()
                .map(|value| AttrValue::String((*value).into()))
                .collect(),
        ),
    }
}

pub(crate) fn present_attr(name: &str) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::Present,
    }
}

/// An assertion that one effect of exactly `operation` holds on the success path.
pub(crate) fn success_path_effect(
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
    request_assurance: Option<RequestAssurance>,
    execution_assurance: Option<ExecutionAssurance>,
) -> Assertion {
    Assertion::Effect {
        selector: Selector {
            operation: OperationMatch::Exact(operation.into()),
            resource,
            attributes,
            request_assurance,
            condition: Some(ConditionPredicate::SuccessPath),
            modality: None,
            execution_assurance,
            realm: None,
        },
        closure: None,
    }
}
