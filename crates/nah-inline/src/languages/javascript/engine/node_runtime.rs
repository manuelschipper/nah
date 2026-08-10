//! Node module loader ownership and mutable loader-property semantics.

use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum NodeModuleMember {
    Load,
    CreateRequire,
    Require,
    IsBuiltin,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum NodeProperty {
    ModuleLoad,
    ModuleCreateRequire,
    ModuleIsBuiltin,
    ModuleAlias,
    ModulePrototype,
    ModuleConstructor,
    PrototypeRequire,
    CommonJsRequire,
    CommonJsConstructor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NodeMutation {
    Applies,
    Ignored,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NodePropertyKind {
    Absent,
    Data,
    Accessor,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodePropertyState {
    pub(super) value: Value,
    pub(super) own: Option<bool>,
    pub(super) kind: NodePropertyKind,
    pub(super) enumerable: Option<bool>,
    pub(super) assignment: NodeMutation,
    pub(super) deletion: NodeMutation,
}

pub(super) fn commonjs_module_value() -> Value {
    Value::CommonJsModule
}

pub(super) fn default_node_properties() -> BTreeMap<NodeProperty, NodePropertyState> {
    BTreeMap::from([
        (
            NodeProperty::ModuleLoad,
            mutable_node_property(Value::NodeModuleMember(NodeModuleMember::Load), true, true),
        ),
        (
            NodeProperty::ModuleCreateRequire,
            mutable_node_property(
                Value::NodeModuleMember(NodeModuleMember::CreateRequire),
                true,
                true,
            ),
        ),
        (
            NodeProperty::ModuleIsBuiltin,
            mutable_node_property(
                Value::NodeModuleMember(NodeModuleMember::IsBuiltin),
                true,
                true,
            ),
        ),
        (
            NodeProperty::ModuleAlias,
            mutable_node_property(Value::NodeModule, true, true),
        ),
        (
            NodeProperty::ModulePrototype,
            mutable_node_property(Value::NodeModulePrototype, false, false),
        ),
        (
            NodeProperty::ModuleConstructor,
            inherited_node_property(
                Value::InheritedNodeProperty(NodeProperty::ModuleConstructor),
                NodeMutation::Applies,
                NodePropertyKind::Data,
                false,
            ),
        ),
        (
            NodeProperty::PrototypeRequire,
            mutable_node_property(
                Value::NodeModuleMember(NodeModuleMember::Require),
                true,
                true,
            ),
        ),
        (
            NodeProperty::CommonJsRequire,
            inherited_node_property(
                Value::InheritedNodeProperty(NodeProperty::CommonJsRequire),
                NodeMutation::Applies,
                NodePropertyKind::Data,
                true,
            ),
        ),
        (
            NodeProperty::CommonJsConstructor,
            inherited_node_property(
                Value::InheritedNodeProperty(NodeProperty::CommonJsConstructor),
                NodeMutation::Ignored,
                NodePropertyKind::Accessor,
                false,
            ),
        ),
    ])
}

pub(super) fn mutable_node_property(
    value: Value,
    configurable: bool,
    enumerable: bool,
) -> NodePropertyState {
    NodePropertyState {
        value,
        own: Some(true),
        kind: NodePropertyKind::Data,
        enumerable: Some(enumerable),
        assignment: NodeMutation::Applies,
        deletion: if configurable {
            NodeMutation::Applies
        } else {
            NodeMutation::Ignored
        },
    }
}

pub(super) fn inherited_node_property(
    value: Value,
    assignment: NodeMutation,
    kind: NodePropertyKind,
    enumerable: bool,
) -> NodePropertyState {
    NodePropertyState {
        value,
        own: Some(false),
        kind,
        enumerable: Some(enumerable),
        assignment,
        deletion: NodeMutation::Ignored,
    }
}

pub(super) fn absent_node_property(property: NodeProperty) -> NodePropertyState {
    match property {
        NodeProperty::ModuleConstructor
        | NodeProperty::CommonJsRequire
        | NodeProperty::CommonJsConstructor => default_node_properties()
            .remove(&property)
            .expect("reviewed Node property"),
        _ => NodePropertyState {
            value: Value::Undefined,
            own: Some(false),
            kind: NodePropertyKind::Absent,
            enumerable: None,
            assignment: NodeMutation::Applies,
            deletion: NodeMutation::Ignored,
        },
    }
}

pub(super) fn unknown_node_property() -> NodePropertyState {
    NodePropertyState {
        value: Value::Unknown,
        own: None,
        kind: NodePropertyKind::Unknown,
        enumerable: None,
        assignment: NodeMutation::Unknown,
        deletion: NodeMutation::Unknown,
    }
}

pub(super) fn defined_node_property(
    current: NodePropertyState,
    descriptor: Option<&Value>,
) -> (NodePropertyState, bool, bool) {
    let Some(Value::Object(properties)) = descriptor else {
        let replacement = descriptor
            .and_then(property_descriptor_replacement)
            .unwrap_or(Value::Unknown);
        return (
            NodePropertyState {
                value: join_values(current.value, replacement),
                own: None,
                kind: NodePropertyKind::Unknown,
                enumerable: None,
                assignment: NodeMutation::Unknown,
                deletion: NodeMutation::Unknown,
            },
            true,
            true,
        );
    };
    if current.own.is_none()
        || current.assignment == NodeMutation::Unknown
        || current.deletion == NodeMutation::Unknown
    {
        let replacement =
            property_descriptor_replacement(descriptor.expect("reviewed property descriptor"))
                .unwrap_or(Value::Unknown);
        return (
            NodePropertyState {
                value: join_values(current.value, replacement),
                own: None,
                kind: NodePropertyKind::Unknown,
                enumerable: None,
                assignment: NodeMutation::Unknown,
                deletion: NodeMutation::Unknown,
            },
            true,
            true,
        );
    }
    let creates_own = current.own == Some(false);
    let replacement =
        property_descriptor_replacement(descriptor.expect("reviewed property descriptor"));
    let accessor = properties.contains_key("get") || properties.contains_key("set");
    let data = properties.contains_key("value") || properties.contains_key("writable");
    let kind = if accessor {
        NodePropertyKind::Accessor
    } else if data || creates_own {
        NodePropertyKind::Data
    } else {
        current.kind
    };
    let changes_value = creates_own
        || kind != current.kind
        || replacement.as_ref().is_some_and(|replacement| {
            unknown_value(replacement)
                || unknown_value(&current.value)
                || replacement != &current.value
        });
    let value = replacement.unwrap_or_else(|| {
        if creates_own {
            Value::Undefined
        } else {
            current.value.clone()
        }
    });
    let assignment = match kind {
        NodePropertyKind::Accessor if accessor => {
            properties
                .get("set")
                .map_or(NodeMutation::Ignored, |setter| {
                    if *setter == Value::Undefined || exact_undefined_getter(setter) {
                        NodeMutation::Ignored
                    } else {
                        NodeMutation::Unknown
                    }
                })
        }
        NodePropertyKind::Accessor => current.assignment,
        NodePropertyKind::Data if data => properties.get("writable").map_or_else(
            || {
                if creates_own {
                    NodeMutation::Ignored
                } else {
                    current.assignment
                }
            },
            node_mutation,
        ),
        NodePropertyKind::Data if creates_own => NodeMutation::Ignored,
        NodePropertyKind::Data => current.assignment,
        NodePropertyKind::Absent | NodePropertyKind::Unknown => NodeMutation::Unknown,
    };
    let deletion = properties.get("configurable").map_or_else(
        || {
            if creates_own {
                NodeMutation::Ignored
            } else {
                current.deletion
            }
        },
        node_mutation,
    );
    let enumerable = properties.get("enumerable").map_or_else(
        || {
            if creates_own {
                Some(false)
            } else {
                current.enumerable
            }
        },
        truthy,
    );
    let uncertain = assignment == NodeMutation::Unknown || deletion == NodeMutation::Unknown;
    let defined = NodePropertyState {
        value,
        own: Some(true),
        kind,
        enumerable,
        assignment,
        deletion,
    };
    if node_property_redefinition_may_reject(&current, properties) {
        (
            join_node_property_state(current, defined),
            changes_value,
            true,
        )
    } else {
        (defined, changes_value, uncertain)
    }
}

pub(super) fn node_mutation(value: &Value) -> NodeMutation {
    match truthy(value) {
        Some(true) => NodeMutation::Applies,
        Some(false) => NodeMutation::Ignored,
        None => NodeMutation::Unknown,
    }
}

pub(super) fn node_define_property_target(arguments: &Arguments) -> Option<NodeProperty> {
    let property = arguments.values.get(1).and_then(value_string)?;
    match arguments.values.first()? {
        Value::NodeModule => node_module_property(property),
        Value::NodeModulePrototype if property == "require" => Some(NodeProperty::PrototypeRequire),
        Value::CommonJsModule => commonjs_module_property(property),
        _ => None,
    }
}

pub(super) fn invalid_node_prototype_constructor_definition(arguments: &Arguments) -> bool {
    if !matches!(arguments.values.first(), Some(Value::NodeModulePrototype))
        || arguments.values.get(1).and_then(value_string) != Some("constructor")
    {
        return false;
    }
    let Some(Value::Object(properties)) = arguments.values.get(2) else {
        return false;
    };
    properties.contains_key("value")
        || properties.contains_key("writable")
        || properties.get("configurable").and_then(truthy) == Some(true)
        || properties.get("enumerable").and_then(truthy) == Some(true)
        || properties
            .get("get")
            .is_some_and(|value| !unknown_value(value))
        || properties
            .get("set")
            .is_some_and(|value| *value != Value::Undefined)
}

pub(super) fn invalid_node_property_redefinition(
    current: &NodePropertyState,
    descriptor: &Value,
) -> bool {
    let Value::Object(properties) = descriptor else {
        return false;
    };
    if current.own != Some(true) || current.deletion != NodeMutation::Ignored {
        return false;
    }
    if properties.get("configurable").and_then(truthy) == Some(true) {
        return true;
    }
    if let Some(enumerable) = properties.get("enumerable").and_then(truthy)
        && current
            .enumerable
            .is_some_and(|current| current != enumerable)
    {
        return true;
    }
    if let Some(kind) = descriptor_property_kind(properties)
        && matches!(
            current.kind,
            NodePropertyKind::Data | NodePropertyKind::Accessor
        )
        && kind != current.kind
    {
        return true;
    }
    if current.kind != NodePropertyKind::Data || current.assignment != NodeMutation::Ignored {
        return false;
    }
    if properties.get("writable").and_then(truthy) == Some(true) {
        return true;
    }
    properties.get("value").is_some_and(|value| {
        value != &current.value && strict_equal(&current.value, value) == Some(false)
    })
}

pub(super) fn node_property_redefinition_may_reject(
    current: &NodePropertyState,
    properties: &BTreeMap<String, Value>,
) -> bool {
    if current.own != Some(true) || current.deletion != NodeMutation::Ignored {
        return false;
    }
    if properties.get("enumerable").is_some_and(|value| {
        truthy(value).is_none_or(|enumerable| current.enumerable != Some(enumerable))
    }) || properties
        .get("configurable")
        .is_some_and(|value| truthy(value) != Some(false))
    {
        return true;
    }
    if let Some(kind) = descriptor_property_kind(properties) {
        if current.kind == NodePropertyKind::Unknown {
            return true;
        }
        if kind != current.kind {
            return true;
        }
    }
    if current.kind == NodePropertyKind::Accessor {
        return properties.contains_key("get") || properties.contains_key("set");
    }
    current.kind == NodePropertyKind::Data
        && current.assignment == NodeMutation::Ignored
        && (properties
            .get("writable")
            .is_some_and(|value| truthy(value) != Some(false))
            || properties.get("value").is_some_and(|value| {
                value != &current.value && strict_equal(&current.value, value) != Some(true)
            }))
}

pub(super) fn descriptor_property_kind(
    properties: &BTreeMap<String, Value>,
) -> Option<NodePropertyKind> {
    if properties.contains_key("get") || properties.contains_key("set") {
        Some(NodePropertyKind::Accessor)
    } else if properties.contains_key("value") || properties.contains_key("writable") {
        Some(NodePropertyKind::Data)
    } else {
        None
    }
}

pub(super) fn node_module_property(property: &str) -> Option<NodeProperty> {
    match property {
        "_load" => Some(NodeProperty::ModuleLoad),
        "createRequire" => Some(NodeProperty::ModuleCreateRequire),
        "isBuiltin" => Some(NodeProperty::ModuleIsBuiltin),
        "Module" => Some(NodeProperty::ModuleAlias),
        "prototype" => Some(NodeProperty::ModulePrototype),
        "constructor" => Some(NodeProperty::ModuleConstructor),
        _ => None,
    }
}

pub(super) fn node_module_property_value(property: &str, state: &State) -> Option<Value> {
    node_module_property(property).map(|property| resolved_node_property(property, state))
}

pub(super) fn commonjs_module_property(property: &str) -> Option<NodeProperty> {
    match property {
        "require" => Some(NodeProperty::CommonJsRequire),
        "constructor" => Some(NodeProperty::CommonJsConstructor),
        _ => None,
    }
}

pub(super) fn resolved_node_property(property: NodeProperty, state: &State) -> Value {
    match state
        .node_properties
        .get(&property)
        .map(|property| &property.value)
    {
        Some(Value::InheritedNodeProperty(NodeProperty::CommonJsRequire)) => {
            resolved_node_property(NodeProperty::PrototypeRequire, state)
        }
        Some(Value::InheritedNodeProperty(NodeProperty::ModuleConstructor)) => {
            Value::FunctionConstructor
        }
        Some(Value::InheritedNodeProperty(NodeProperty::CommonJsConstructor)) => Value::NodeModule,
        Some(value) => value.clone(),
        None => Value::Unknown,
    }
}

pub(super) fn property_descriptor_replacement(descriptor: &Value) -> Option<Value> {
    match descriptor {
        Value::Object(properties) => {
            if let Some(value) = properties.get("value") {
                Some(if accessor_value(value) {
                    Value::Unknown
                } else {
                    value.clone()
                })
            } else if let Some(getter) = properties.get("get") {
                Some(if accessor_value(getter) {
                    Value::Unknown
                } else if *getter == Value::Undefined || exact_undefined_getter(getter) {
                    Value::Undefined
                } else {
                    Value::Unknown
                })
            } else if properties.contains_key("set") {
                Some(Value::Undefined)
            } else {
                None
            }
        }
        value if unknown_value(value) => Some(Value::Unknown),
        _ => None,
    }
}

pub(super) fn exact_undefined_getter(value: &Value) -> bool {
    matches!(
        value,
        Value::Function(function)
            if function.expression_body && function.body.kind() == HirKind::Undefined
    )
}

pub(super) fn invalid_define_property_target(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::NonCallablePrimitive
    )
}

pub(super) fn accessor_value(value: &Value) -> bool {
    matches!(value, Value::Accessor | Value::AccessorGetter(_))
}

pub(super) fn invalid_property_descriptor(value: &Value) -> bool {
    match value {
        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            true
        }
        Value::Object(properties) => {
            let accessor = properties.contains_key("get") || properties.contains_key("set");
            let data = properties.contains_key("value") || properties.contains_key("writable");
            accessor && data
                || ["get", "set"].into_iter().any(|property| {
                    properties.get(property).is_some_and(|value| {
                        *value != Value::Undefined && exact_non_callable(value)
                    })
                })
        }
        _ => false,
    }
}

pub(super) fn node_module_loader_hook(member: NodeModuleMember) -> bool {
    !matches!(member, NodeModuleMember::IsBuiltin)
}

pub(super) fn node_property_loader_hook(property: NodeProperty) -> bool {
    matches!(
        property,
        NodeProperty::ModuleLoad
            | NodeProperty::ModuleCreateRequire
            | NodeProperty::PrototypeRequire
            | NodeProperty::CommonJsRequire
    )
}

pub(super) fn node_loader_reference(member: &MemberReference) -> bool {
    match (&member.object, member.property.as_deref()) {
        (Value::NodeModule, Some(property)) => {
            node_module_property(property).is_some_and(node_property_loader_hook)
        }
        (Value::NodeModulePrototype, Some("require"))
        | (Value::CommonJsModule, Some("require")) => true,
        _ => false,
    }
}
