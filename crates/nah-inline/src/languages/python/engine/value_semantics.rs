//! Python abstract values, operators, truthiness, and display semantics.

use super::*;

pub(super) fn parse_integer(value: &str) -> Option<i64> {
    let value = value.replace('_', "");
    if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        i64::from_str_radix(value, 16).ok()
    } else if let Some(value) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        i64::from_str_radix(value, 8).ok()
    } else if let Some(value) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        i64::from_str_radix(value, 2).ok()
    } else {
        value.parse().ok()
    }
}

pub(super) fn binary_value(
    left: Value,
    right: Value,
    operator: &str,
    budget: &mut Budget,
) -> Value {
    let origins = producer_ordinals(&left)
        .chain(producer_ordinals(&right))
        .collect::<BTreeSet<_>>();
    if !origins.is_empty() {
        return Value::Produced(origins.into_iter().collect());
    }
    match (left, right, operator) {
        (Value::String(mut left), Value::String(right), "+") => {
            if bounded_push_str(&mut left, &right, budget) {
                Value::String(left)
            } else {
                Value::Unknown
            }
        }
        (Value::Bytes(mut left), Value::Bytes(right), "+") => {
            if budget.admit_value_bytes(left.len().checked_add(right.len())) {
                left.extend(right);
                Value::Bytes(left)
            } else {
                Value::Unknown
            }
        }
        (Value::Int(left), Value::Int(right), "+") => {
            left.checked_add(right).map_or(Value::Unknown, Value::Int)
        }
        (Value::Int(left), Value::Int(right), "-") => {
            left.checked_sub(right).map_or(Value::Unknown, Value::Int)
        }
        (Value::Int(left), Value::Int(right), "*") => {
            left.checked_mul(right).map_or(Value::Unknown, Value::Int)
        }
        (Value::Int(left), Value::Int(right), "|") => Value::Int(left | right),
        (Value::Path(left), Value::String(right), "/") => {
            join_path(left, &right, budget).map_or(Value::Unknown, Value::Path)
        }
        _ => Value::Unknown,
    }
}

pub(super) fn compare_values(left: &Value, right: &Value, operator: &str) -> Option<bool> {
    let equal = match (left, right) {
        (Value::None, Value::None) => Some(true),
        (Value::None, Value::Bool(_) | Value::Int(_) | Value::String(_) | Value::Bytes(_))
        | (Value::Bool(_) | Value::Int(_) | Value::String(_) | Value::Bytes(_), Value::None) => {
            Some(false)
        }
        (Value::Bool(left), Value::Bool(right)) => Some(left == right),
        (Value::Int(left), Value::Int(right)) => Some(left == right),
        (Value::Bool(left), Value::Int(right)) | (Value::Int(right), Value::Bool(left)) => {
            Some(i64::from(*left) == *right)
        }
        (Value::String(left), Value::String(right))
        | (Value::ImplicitString(left), Value::ImplicitString(right))
        | (Value::String(left), Value::ImplicitString(right))
        | (Value::ImplicitString(left), Value::String(right))
        | (Value::Path(left), Value::Path(right)) => Some(left == right),
        (Value::Bytes(left), Value::Bytes(right)) => Some(left == right),
        _ => None,
    };
    match operator {
        "==" => equal,
        "!=" => equal.map(|value| !value),
        "is" => match (left, right) {
            (Value::None, Value::None) => Some(true),
            (Value::None, _) | (_, Value::None) => Some(false),
            _ => None,
        },
        "is not" => match (left, right) {
            (Value::None, Value::None) => Some(false),
            (Value::None, _) | (_, Value::None) => Some(true),
            _ => None,
        },
        "<" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left < right),
            (Value::String(left), Value::String(right)) => Some(left < right),
            _ => None,
        },
        "<=" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left <= right),
            (Value::String(left), Value::String(right)) => Some(left <= right),
            _ => None,
        },
        ">" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left > right),
            (Value::String(left), Value::String(right)) => Some(left > right),
            _ => None,
        },
        ">=" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left >= right),
            (Value::String(left), Value::String(right)) => Some(left >= right),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn join_values(left: Value, right: Value) -> Value {
    if left == right {
        return left;
    }
    join_distinct_values(left, right)
}

pub(super) fn join_distinct_values(left: Value, right: Value) -> Value {
    let origins = producer_ordinals(&left)
        .chain(producer_ordinals(&right))
        .collect::<BTreeSet<_>>();
    if origins.is_empty() {
        Value::Unknown
    } else {
        Value::Produced(origins.into_iter().collect())
    }
}

pub(super) fn producer_ordinals(value: &Value) -> impl Iterator<Item = usize> + '_ {
    match value {
        Value::Produced(origins) => origins.as_slice(),
        Value::Decoded(value) => match value.as_ref() {
            Value::Produced(origins) => origins.as_slice(),
            _ => &[],
        },
        _ => &[],
    }
    .iter()
    .copied()
}

pub(super) fn truthy(value: &Value, state: &State) -> Option<bool> {
    match value {
        Value::None => Some(false),
        Value::Bool(value) => Some(*value),
        Value::Int(value) => Some(*value != 0),
        Value::String(value) | Value::ImplicitString(value) => Some(!value.is_empty()),
        Value::Bytes(value) => Some(!value.is_empty()),
        Value::EmptyDictionary => Some(false),
        Value::Cell(cell) => match state.cells.get(*cell) {
            Some(Cell::Sequence { values, .. }) => Some(!values.is_empty()),
            Some(Cell::Unknown) | None => None,
        },
        Value::Module(_) | Value::Known(_) | Value::LocalFunction(_) | Value::Path(_) => Some(true),
        _ => None,
    }
}

pub(super) fn display_value(value: &Value) -> Option<String> {
    match value {
        Value::None => Some("None".into()),
        Value::Bool(true) => Some("True".into()),
        Value::Bool(false) => Some("False".into()),
        Value::Int(value) => Some(value.to_string()),
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => {
            Some(value.clone())
        }
        _ => None,
    }
}

pub(super) fn value_text(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) | Value::ImplicitString(value) => Some(value),
        _ => None,
    }
}

pub(super) fn value_string(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => Some(value),
        Value::Decoded(value) => value_string(value),
        _ => None,
    }
}

pub(super) fn decoded(value: &Value) -> bool {
    matches!(value, Value::Decoded(_))
}
