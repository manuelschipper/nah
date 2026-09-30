//! Predicate builders the shipped guard definitions share.

use effinterp_matcher::{
    AttributePredicate, AttributeTest, ResourcePredicate, ResourceVariant, SelectionShape,
};
use effinterp_proto::AttrValue;

pub(crate) fn family(value: &str) -> ResourcePredicate {
    ResourcePredicate::Family {
        family: value.into(),
    }
}

pub(crate) fn variant(value: ResourceVariant) -> ResourcePredicate {
    ResourcePredicate::Variant { variant: value }
}

pub(crate) fn selection(shape: SelectionShape) -> ResourcePredicate {
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
