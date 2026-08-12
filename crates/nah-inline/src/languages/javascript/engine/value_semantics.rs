//! JavaScript coercion, abrupt control, equality, truthiness, and state joins.

use super::*;

pub(super) fn string_coercion(value: &Value) -> Option<String> {
    match value {
        Value::Undefined => Some("undefined".to_owned()),
        Value::Null => Some("null".to_owned()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

pub(super) fn abrupt_value(value: &Value) -> bool {
    matches!(value, Value::SynchronousThrow | Value::Divergent)
}

pub(super) fn abrupt_control(value: &Value) -> Option<Control> {
    match value {
        Value::SynchronousThrow => Some(Control::Throw),
        Value::Divergent => Some(Control::Diverge),
        _ => None,
    }
}

pub(super) fn truthy(value: &Value) -> Option<bool> {
    match value {
        Value::Invalid
        | Value::NonCallablePrimitive
        | Value::Accessor
        | Value::AccessorGetter(_)
        | Value::SynchronousThrow
        | Value::Divergent
        | Value::Unknown
        | Value::DynamicEvalResult
        | Value::UnknownModuleMember(_)
        | Value::UnknownReceiver(_) => None,
        Value::Undefined | Value::Null => Some(false),
        Value::Bool(value) => Some(*value),
        Value::Number(value) => Some(*value != 0),
        Value::String(value) => Some(!value.is_empty()),
        Value::Promise
        | Value::RejectedPromise
        | Value::Array(_)
        | Value::Object(_)
        | Value::Module(_)
        | Value::Known(_)
        | Value::Function(_)
        | Value::Require
        | Value::Eval
        | Value::FunctionConstructor
        | Value::DynamicFunction(_)
        | Value::ObjectBuiltin
        | Value::Process
        | Value::Environment
        | Value::CommonJsModule
        | Value::InheritedNodeProperty(_)
        | Value::NodeModule
        | Value::LoadedModule(_)
        | Value::NodeModulePrototype
        | Value::NodeModuleMember(_)
        | Value::Deno
        | Value::DenoCommandConstructor
        | Value::DenoCommand(_)
        | Value::Bun
        | Value::BunFile(_)
        | Value::OpenClawTools => Some(true),
    }
}

pub(super) fn nullish(value: &Value) -> Option<bool> {
    match value {
        Value::Undefined | Value::Null => Some(true),
        value if unknown_value(value) || abrupt_value(value) => None,
        _ => Some(false),
    }
}

pub(super) fn strict_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Undefined, Value::Undefined) | (Value::Null, Value::Null) => Some(true),
        (Value::Bool(left), Value::Bool(right)) => Some(left == right),
        (Value::Number(left), Value::Number(right)) => Some(left == right),
        (Value::String(left), Value::String(right)) => Some(left == right),
        (left, right) if uncertain_identity(left) || uncertain_identity(right) => None,
        (left, right) if primitive_value(left) || primitive_value(right) => Some(false),
        _ => None,
    }
}

pub(super) fn primitive_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

pub(super) fn uncertain_identity(value: &Value) -> bool {
    matches!(
        value,
        Value::Unknown
            | Value::DynamicEvalResult
            | Value::Invalid
            | Value::SynchronousThrow
            | Value::Divergent
            | Value::UnknownModuleMember(_)
            | Value::UnknownReceiver(_)
    )
}

pub(super) fn loose_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Undefined, Value::Null) | (Value::Null, Value::Undefined) => Some(true),
        (Value::Undefined, Value::Undefined)
        | (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => strict_equal(left, right),
        (left, right) if unknown_value(left) || unknown_value(right) => None,
        _ => None,
    }
}

pub(super) fn join_values(left: Value, right: Value) -> Value {
    if left == right { left } else { Value::Unknown }
}

pub(super) fn join_node_property_state(
    left: NodePropertyState,
    right: NodePropertyState,
) -> NodePropertyState {
    NodePropertyState {
        value: join_values(left.value, right.value),
        own: if left.own == right.own {
            left.own
        } else {
            None
        },
        kind: if left.kind == right.kind {
            left.kind
        } else {
            NodePropertyKind::Unknown
        },
        enumerable: if left.enumerable == right.enumerable {
            left.enumerable
        } else {
            None
        },
        assignment: if left.assignment == right.assignment {
            left.assignment
        } else {
            NodeMutation::Unknown
        },
        deletion: if left.deletion == right.deletion {
            left.deletion
        } else {
            NodeMutation::Unknown
        },
    }
}

pub(super) fn join_states(mut left: State, right: State) -> State {
    if left.scopes.len() != right.scopes.len() || left.scope_chain != right.scope_chain {
        return State {
            scopes: left
                .scopes
                .into_iter()
                .map(|scope| Scope {
                    id: scope.id,
                    function: scope.function,
                    bindings: scope
                        .bindings
                        .into_keys()
                        .map(|name| (name, Value::Unknown))
                        .collect(),
                })
                .collect(),
            scope_chain: left.scope_chain,
            next_scope_id: left.next_scope_id.max(right.next_scope_id),
            owned_members: left
                .owned_members
                .intersection(&right.owned_members)
                .copied()
                .collect(),
            loaded_modules_intact: left
                .loaded_modules_intact
                .intersection(&right.loaded_modules_intact)
                .copied()
                .collect(),
            node_properties: left
                .node_properties
                .into_iter()
                .map(|(property, value)| {
                    let right = right
                        .node_properties
                        .get(&property)
                        .cloned()
                        .unwrap_or_else(unknown_node_property);
                    (property, join_node_property_state(value, right))
                })
                .collect(),
            cwd: if left.cwd == right.cwd {
                left.cwd
            } else {
                NestedExecutionCwd::Unknown
            },
            prototype_integrity_known: left.prototype_integrity_known
                && right.prototype_integrity_known,
            runtime_globals_intact: left.runtime_globals_intact && right.runtime_globals_intact,
        };
    }
    for (left_scope, right_scope) in left.scopes.iter_mut().zip(right.scopes) {
        let names = left_scope
            .bindings
            .keys()
            .chain(right_scope.bindings.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        left_scope.bindings = names
            .into_iter()
            .map(|name| {
                let left = left_scope
                    .bindings
                    .get(&name)
                    .cloned()
                    .unwrap_or(Value::Unknown);
                let right = right_scope
                    .bindings
                    .get(&name)
                    .cloned()
                    .unwrap_or(Value::Unknown);
                (name, join_values(left, right))
            })
            .collect();
    }
    left.owned_members = left
        .owned_members
        .intersection(&right.owned_members)
        .copied()
        .collect();
    left.loaded_modules_intact = left
        .loaded_modules_intact
        .intersection(&right.loaded_modules_intact)
        .copied()
        .collect();
    for (property, value) in &mut left.node_properties {
        let right = right
            .node_properties
            .get(property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        *value = join_node_property_state(value.clone(), right);
    }
    if left.cwd != right.cwd {
        left.cwd = NestedExecutionCwd::Unknown;
    }
    left.prototype_integrity_known &= right.prototype_integrity_known;
    left.runtime_globals_intact &= right.runtime_globals_intact;
    left.next_scope_id = left.next_scope_id.max(right.next_scope_id);
    left
}

pub(super) fn values_bytes(values: &[Value]) -> Option<usize> {
    values.iter().try_fold(0usize, |bytes, value| {
        bytes.checked_add(value_bytes(value)?)
    })
}

pub(super) fn properties_bytes(properties: &BTreeMap<String, Value>) -> Option<usize> {
    properties.iter().try_fold(0usize, |bytes, (name, value)| {
        bytes
            .checked_add(name.len())?
            .checked_add(value_bytes(value)?)
    })
}

pub(super) fn value_bytes(value: &Value) -> Option<usize> {
    match value {
        Value::String(value) => Some(value.len()),
        Value::Array(values) => values_bytes(values),
        Value::Object(properties) => properties_bytes(properties),
        _ => Some(0),
    }
}
