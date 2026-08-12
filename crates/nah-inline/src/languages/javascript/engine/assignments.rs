//! JavaScript assignments, destructuring, property mutation, and invalidation.

use super::*;

impl Interpreter<'_> {
    pub(super) fn assignment(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        let left = node.child(HirField::Left);
        let member = match left.and_then(member_assignment_target) {
            Some(target) => match self.member_reference(target, state, call_depth) {
                Ok(member) => Some(member),
                Err(value) => return value,
            },
            None => None,
        };
        let value = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, call_depth));
        if abrupt_value(&value) {
            return value;
        }
        if let Some(value) = self.store_assignment(member, left, value.clone(), state, call_depth) {
            return value;
        }
        value
    }

    pub(super) fn store_assignment(
        &mut self,
        member: Option<MemberReference>,
        left: Option<&HirNode>,
        value: Value,
        state: &mut State,
        call_depth: usize,
    ) -> Option<Value> {
        if let Some(member) = member {
            match self.assign_member(member, value.clone(), state) {
                NodeMutation::Ignored if self.strict => return Some(Value::SynchronousThrow),
                NodeMutation::Ignored => {}
                NodeMutation::Applies => state.invalidate_node_module_escape(&value),
                NodeMutation::Unknown => {
                    state.invalidate_node_module_escape(&value);
                    self.complete = false;
                    self.draft.set_partial();
                }
            }
        } else if let Some(left) = left
            && let Some(value) = self.assign_target(left, value, state, call_depth)
        {
            return Some(value);
        }
        None
    }

    pub(super) fn augmented_assignment(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        let left = node
            .child(HirField::Left)
            .or_else(|| named_children(node).next());
        let member = match left.and_then(member_assignment_target) {
            Some(target) => match self.member_reference(target, state, call_depth) {
                Ok(member) => Some(member),
                Err(value) => return value,
            },
            None => None,
        };
        let left_value = if let Some(member) = &member {
            self.read_member(member, state)
        } else {
            left.map_or(Value::Unknown, |left| self.eval(left, state, call_depth))
        };
        if abrupt_value(&left_value) {
            return left_value;
        }
        let operator = node
            .child(HirField::Operator)
            .map_or("", |operator| self.text(operator));
        if matches!(operator, "&&=" | "||=" | "??=") {
            let assign = match operator {
                "&&=" => truthy(&left_value),
                "||=" => truthy(&left_value).map(|truthy| !truthy),
                "??=" => nullish(&left_value),
                _ => unreachable!(),
            };
            if assign == Some(false) {
                return left_value;
            }
            let Some(right) = node.child(HirField::Right) else {
                return Value::Unknown;
            };
            if assign == Some(true) {
                let value = self.eval(right, state, call_depth);
                if abrupt_value(&value) {
                    return value;
                }
                if let Some(value) =
                    self.store_assignment(member, left, value.clone(), state, call_depth)
                {
                    return value;
                }
                return value;
            }
            self.complete = false;
            self.draft.set_partial();
            let no = state.clone();
            let mut yes = state.clone();
            let saved_dominators = self.execution_dominators.clone();
            self.conditional_depth += 1;
            let value = self.eval(right, &mut yes, call_depth);
            if !abrupt_value(&value)
                && self
                    .store_assignment(member, left, value.clone(), &mut yes, call_depth)
                    .is_none()
            {
                *state = join_states(no, yes);
                self.conditional_depth -= 1;
                self.execution_dominators = saved_dominators;
                return join_values(left_value, value);
            }
            *state = no;
            self.conditional_depth -= 1;
            self.execution_dominators = saved_dominators;
            return left_value;
        }
        let right = node
            .child(HirField::Right)
            .map(|right| self.eval(right, state, call_depth));
        if let Some(value) = &right
            && abrupt_value(value)
        {
            return value.clone();
        }
        let replacement = Value::NonCallablePrimitive;
        if !augmented_coercion_proven(&left_value, right.as_ref(), state) {
            self.complete = false;
            self.draft.set_partial();
            if self.catchable_depth > 0 && member.as_ref().is_some_and(node_loader_reference) {
                return replacement;
            }
        }
        if let Some(value) =
            self.store_assignment(member, left, replacement.clone(), state, call_depth)
        {
            value
        } else {
            replacement
        }
    }

    pub(super) fn assign_target(
        &mut self,
        node: &HirNode,
        value: Value,
        state: &mut State,
        call_depth: usize,
    ) -> Option<Value> {
        match node.kind() {
            HirKind::Identifier => state.assign(self.text(node), value),
            HirKind::ObjectPattern | HirKind::ArrayPattern => {
                return self.assign_pattern(node, value, state, BindingMode::Assign, call_depth);
            }
            HirKind::ParenthesizedExpression => {
                if let Some(target) = named_children(node).next() {
                    return self.assign_target(target, value, state, call_depth);
                }
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression => {
                let member = match self.member_reference(node, state, call_depth) {
                    Ok(member) => member,
                    Err(value) => return Some(value),
                };
                return self.store_assignment(Some(member), None, value, state, call_depth);
            }
            _ => {}
        }
        None
    }

    pub(super) fn member_reference(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Result<MemberReference, Value> {
        let object = node
            .child(HirField::Object)
            .map_or(Value::Unknown, |object| {
                self.eval(object, state, call_depth)
            });
        if abrupt_value(&object) {
            return Err(object);
        }
        let property = if let Some(property) = node.child(HirField::Property) {
            Some(self.text(property).to_owned())
        } else {
            let value = node
                .child(HirField::Index)
                .map_or(Value::Unknown, |index| self.eval(index, state, call_depth));
            if abrupt_value(&value) {
                return Err(value);
            }
            string_coercion(&value)
        };
        Ok(MemberReference {
            object,
            property,
            prototype_mutation: prototype_mutation_target(self.text(node)),
        })
    }

    pub(super) fn assign_node_property(
        &mut self,
        property: NodeProperty,
        replacement: Value,
        state: &mut State,
    ) -> NodeMutation {
        let current = state
            .node_properties
            .get(&property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        match current.assignment {
            NodeMutation::Ignored => NodeMutation::Ignored,
            NodeMutation::Applies => {
                let creates_own = current.own == Some(false);
                let property_state = state
                    .node_properties
                    .entry(property)
                    .or_insert_with(unknown_node_property);
                property_state.value = replacement;
                if creates_own {
                    property_state.own = Some(true);
                    property_state.kind = NodePropertyKind::Data;
                    property_state.enumerable = Some(true);
                    property_state.deletion = NodeMutation::Applies;
                }
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                NodeMutation::Applies
            }
            NodeMutation::Unknown => {
                let property_state = state
                    .node_properties
                    .entry(property)
                    .or_insert_with(unknown_node_property);
                property_state.value = join_values(current.value, replacement);
                property_state.own = None;
                property_state.kind = NodePropertyKind::Unknown;
                property_state.enumerable = None;
                property_state.assignment = NodeMutation::Unknown;
                property_state.deletion = NodeMutation::Unknown;
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                self.complete = false;
                self.draft.set_partial();
                NodeMutation::Unknown
            }
        }
    }

    pub(super) fn define_node_property(
        &mut self,
        property: NodeProperty,
        arguments: &Arguments,
        state: &mut State,
    ) {
        let current = state
            .node_properties
            .get(&property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        let (defined, changes_value, uncertain) =
            defined_node_property(current, arguments.values.get(2));
        state.node_properties.insert(property, defined);
        if changes_value && node_property_loader_hook(property) {
            state.invalidate_node_module_loader();
        }
        if uncertain {
            self.complete = false;
            self.draft.set_partial();
        }
    }

    pub(super) fn delete_node_property(
        &mut self,
        property: NodeProperty,
        state: &mut State,
    ) -> NodeMutation {
        let current = state
            .node_properties
            .get(&property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        if current.own == Some(false) {
            return NodeMutation::Applies;
        }
        match current.deletion {
            NodeMutation::Ignored => NodeMutation::Ignored,
            NodeMutation::Applies => {
                state
                    .node_properties
                    .insert(property, absent_node_property(property));
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                NodeMutation::Applies
            }
            NodeMutation::Unknown => {
                let absent = absent_node_property(property);
                state.node_properties.insert(
                    property,
                    NodePropertyState {
                        value: join_values(current.value, absent.value),
                        own: None,
                        kind: NodePropertyKind::Unknown,
                        enumerable: None,
                        assignment: NodeMutation::Unknown,
                        deletion: NodeMutation::Unknown,
                    },
                );
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                self.complete = false;
                self.draft.set_partial();
                NodeMutation::Unknown
            }
        }
    }

    pub(super) fn assign_member(
        &mut self,
        member: MemberReference,
        replacement: Value,
        state: &mut State,
    ) -> NodeMutation {
        if member.prototype_mutation {
            state.prototype_integrity_known = false;
            self.complete = false;
            self.draft.set_partial();
        }
        if matches!(
            (&member.object, member.property.as_deref()),
            (Value::Object(properties), Some(property))
                if properties.get(property).is_some_and(accessor_value)
        ) {
            self.complete = false;
        }
        match (&member.object, member.property.as_deref()) {
            (Value::NodeModule, Some(property)) => {
                if let Some(property) = node_module_property(property) {
                    self.assign_node_property(property, replacement.clone(), state)
                } else {
                    NodeMutation::Applies
                }
            }
            (Value::NodeModule, None) => {
                state.invalidate_node_module_properties();
                NodeMutation::Unknown
            }
            (Value::NodeModulePrototype, Some("require")) => self.assign_node_property(
                NodeProperty::PrototypeRequire,
                replacement.clone(),
                state,
            ),
            (Value::NodeModulePrototype, Some("constructor")) => NodeMutation::Ignored,
            (Value::NodeModulePrototype, None) => {
                state.invalidate_node_module_properties();
                NodeMutation::Unknown
            }
            (Value::NodeModulePrototype, Some(_)) => NodeMutation::Applies,
            (Value::CommonJsModule, Some(property @ ("constructor" | "require"))) => {
                let property =
                    commonjs_module_property(property).expect("reviewed CommonJS property");
                self.assign_node_property(property, replacement.clone(), state)
            }
            (Value::CommonJsModule, None) => {
                state.invalidate_node_module_properties();
                NodeMutation::Unknown
            }
            (Value::CommonJsModule, Some(_)) => NodeMutation::Applies,
            (Value::Object(properties), Some(property))
                if properties
                    .get(property)
                    .is_none_or(|value| !accessor_value(value)) =>
            {
                let mut properties = properties.clone();
                properties.insert(property.to_owned(), replacement);
                state.replace_mutated_container(&member.object, &Value::Object(properties));
                NodeMutation::Applies
            }
            (Value::Array(values), Some(property)) => {
                let Some(index) = property
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < MAX_COLLECTION_ITEMS && *index <= values.len())
                else {
                    state.forget_container(&member.object);
                    return NodeMutation::Unknown;
                };
                let mut values = values.clone();
                if index == values.len() {
                    values.push(replacement);
                } else {
                    values[index] = replacement;
                }
                state.replace_mutated_container(&member.object, &Value::Array(values));
                NodeMutation::Applies
            }
            (Value::LoadedModule(module), Some(_)) => {
                state.invalidate_loaded_module(*module);
                NodeMutation::Applies
            }
            (Value::Module(module), Some(property)) => {
                if *module == Module::Fs && property == "promises" {
                    state.invalidate_module(Module::FsPromises);
                } else if let Some(known) = module_member(*module, property) {
                    state.owned_members.remove(&(*module, known));
                    state.invalidate_loaded_module_cache(*module);
                } else {
                    state.invalidate_module(*module);
                }
                NodeMutation::Applies
            }
            _ => {
                state.invalidate_value(&member.object);
                NodeMutation::Unknown
            }
        }
    }

    pub(super) fn delete_member(
        &mut self,
        member: MemberReference,
        state: &mut State,
    ) -> NodeMutation {
        match (&member.object, member.property.as_deref()) {
            (Value::Object(properties), Some(property)) => {
                let mut properties = properties.clone();
                properties.remove(property);
                state.replace_mutated_container(&member.object, &Value::Object(properties));
                NodeMutation::Applies
            }
            (Value::Array(values), Some(property)) => {
                let Some(index) = property
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < values.len())
                else {
                    state.forget_container(&member.object);
                    return NodeMutation::Unknown;
                };
                let mut values = values.clone();
                values[index] = Value::Undefined;
                state.replace_mutated_container(&member.object, &Value::Array(values));
                NodeMutation::Applies
            }
            (Value::NodeModule, Some(property)) => {
                if let Some(property) = node_module_property(property) {
                    self.delete_node_property(property, state)
                } else {
                    NodeMutation::Unknown
                }
            }
            (Value::CommonJsModule, Some(property @ ("require" | "constructor"))) => {
                let property =
                    commonjs_module_property(property).expect("reviewed CommonJS property");
                self.delete_node_property(property, state)
            }
            (Value::NodeModulePrototype, Some("require")) => {
                self.delete_node_property(NodeProperty::PrototypeRequire, state)
            }
            (Value::NodeModulePrototype, Some("constructor")) => NodeMutation::Ignored,
            _ => {
                self.assign_member(member, Value::Unknown, state);
                NodeMutation::Unknown
            }
        }
    }

    pub(super) fn assign_pattern(
        &mut self,
        node: &HirNode,
        value: Value,
        state: &mut State,
        mode: BindingMode,
        call_depth: usize,
    ) -> Option<Value> {
        match node.kind() {
            HirKind::Identifier | HirKind::ShorthandPropertyIdentifier => match mode {
                BindingMode::Assign | BindingMode::Var => {
                    state.assign(self.text(node), value);
                }
                BindingMode::Lexical => state.declare(self.text(node), value),
            },
            HirKind::ObjectPattern => {
                if abrupt_value(&value) {
                    return Some(value);
                }
                if matches!(value, Value::Undefined | Value::Null) {
                    return Some(Value::SynchronousThrow);
                }
                for child in named_children(node) {
                    match child.kind() {
                        HirKind::ShorthandPropertyIdentifier => {
                            let property = self.text(child).to_owned();
                            let selected = self.read_property(&value, &property, state);
                            if let Some(value) =
                                self.assign_pattern(child, selected, state, mode, call_depth)
                            {
                                return Some(value);
                            }
                        }
                        HirKind::Pair => {
                            let property = match child.child(HirField::Key) {
                                Some(key) => {
                                    match self.object_property_name(key, state, call_depth) {
                                        Ok(property) => property,
                                        Err(value) => return Some(value),
                                    }
                                }
                                None => None,
                            };
                            let selected = property.as_deref().map_or(Value::Unknown, |property| {
                                self.read_property(&value, property, state)
                            });
                            if let Some(target) = child.child(HirField::Value)
                                && let Some(value) =
                                    self.assign_pattern(target, selected, state, mode, call_depth)
                            {
                                return Some(value);
                            }
                        }
                        HirKind::AssignmentPattern => {
                            let property = child
                                .child(HirField::Left)
                                .map(|target| self.text(target).to_owned());
                            let selected = property.as_deref().map_or(Value::Unknown, |property| {
                                self.read_property(&value, property, state)
                            });
                            if let Some(value) =
                                self.assign_pattern(child, selected, state, mode, call_depth)
                            {
                                return Some(value);
                            }
                        }
                        _ => {
                            self.predeclare_pattern(child, state, matches!(mode, BindingMode::Var))
                        }
                    }
                }
            }
            HirKind::ArrayPattern => {
                let values = match &value {
                    Value::Array(values) => Some(values.clone()),
                    Value::String(value) => Some(
                        value
                            .chars()
                            .map(|value| Value::String(value.to_string()))
                            .collect(),
                    ),
                    value if exact_non_iterable(value) => {
                        return Some(Value::SynchronousThrow);
                    }
                    Value::SynchronousThrow | Value::Divergent => return Some(value),
                    _ => None,
                };
                for (index, child) in named_children(node).enumerate() {
                    let selected = values.as_ref().map_or(Value::Unknown, |values| {
                        values.get(index).cloned().unwrap_or(Value::Undefined)
                    });
                    if let Some(value) =
                        self.assign_pattern(child, selected, state, mode, call_depth)
                    {
                        return Some(value);
                    }
                }
            }
            HirKind::AssignmentPattern => {
                if let Some(target) = node.child(HirField::Left) {
                    let value = if value == Value::Undefined {
                        node.child(HirField::Right)
                            .map_or(Value::Unknown, |right| self.eval(right, state, call_depth))
                    } else {
                        value
                    };
                    if abrupt_value(&value) {
                        return Some(value);
                    }
                    if let Some(value) = self.assign_pattern(target, value, state, mode, call_depth)
                    {
                        return Some(value);
                    }
                }
            }
            HirKind::RestPattern => {
                if let Some(target) = named_children(node).next()
                    && let Some(value) =
                        self.assign_pattern(target, Value::Unknown, state, mode, call_depth)
                {
                    return Some(value);
                }
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression
                if matches!(mode, BindingMode::Assign) =>
            {
                return self.assign_target(node, value, state, call_depth);
            }
            _ => {}
        }
        None
    }
}
