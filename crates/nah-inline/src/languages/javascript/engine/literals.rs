//! JavaScript functions, templates, arrays, objects, and property literals.

use super::*;

impl Interpreter<'_> {
    pub(super) fn function_value(&mut self, node: &HirNode, state: &State) -> Option<Value> {
        if !self.budget.add_function() {
            return None;
        }
        let parameters = self.parameters(node);
        let body = node.child(HirField::Body)?.clone();
        Some(Value::Function(Arc::new(LocalFunction {
            parameters,
            expression_body: body.kind() != HirKind::StatementBlock,
            asynchronous: asynchronous_function(node, self.source),
            strict: self.strict || strict_directive(&body, self.source),
            captured_scopes: state.scope_chain.clone(),
            source_identity: self.source.as_ptr() as usize,
            body,
        })))
    }

    pub(super) fn parameters(&self, node: &HirNode) -> Option<Vec<String>> {
        if let Some(parameter) = node.child(HirField::Parameter) {
            return self.parameter_name(parameter).map(|name| vec![name]);
        }
        let Some(parameters) = node.child(HirField::Parameters) else {
            return Some(Vec::new());
        };
        let mut names = Vec::new();
        for parameter in named_children(parameters) {
            names.push(self.parameter_name(parameter)?);
        }
        Some(names)
    }

    pub(super) fn parameter_name(&self, node: &HirNode) -> Option<String> {
        let identifier = match node.kind() {
            HirKind::Identifier => node,
            HirKind::RequiredParameter if node.child(HirField::Value).is_none() => node
                .child(HirField::Name)
                .or_else(|| node.child(HirField::Parameter))
                .or_else(|| {
                    named_children(node).find(|child| child.kind() == HirKind::Identifier)
                })?,
            _ => return None,
        };
        (identifier.kind() == HirKind::Identifier).then(|| self.text(identifier).to_owned())
    }

    pub(super) fn template(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        let mut value = String::new();
        let mut exact = true;
        let mut branches = Vec::new();
        for child in node.children() {
            let part = match child.kind() {
                HirKind::StringFragment => Some(self.text(child).to_owned()),
                HirKind::EscapeSequence => decode_escape(self.text(child)),
                HirKind::TemplateSubstitution => {
                    let value = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |expression| {
                            self.eval(expression, state, call_depth)
                        });
                    if abrupt_value(&value) {
                        return self.finish_assembly_branches(state, &mut branches, value);
                    }
                    match string_coercion(&value) {
                        Some(value) => Some(value),
                        None => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                            continue;
                        }
                    }
                }
                HirKind::Token | HirKind::Comment => continue,
                _ => None,
            };
            let Some(part) = part else {
                self.complete = false;
                self.draft.set_partial();
                exact = false;
                continue;
            };
            if !exact {
                continue;
            }
            let Some(bytes) = value.len().checked_add(part.len()) else {
                self.budget.refuse();
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            };
            if !self.budget.admit_bytes(Some(bytes)) {
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            }
            value.push_str(&part);
        }
        let value = if exact {
            Value::String(value)
        } else {
            Value::Unknown
        };
        self.finish_assembly_branches(state, &mut branches, value)
    }

    pub(super) fn array(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut values = Vec::new();
        let mut exact = true;
        let mut branches = Vec::new();
        let mut cursor = node.span().start().saturating_add(1);
        let mut has_element = false;
        for child in named_children(node) {
            let holes = delimited_holes(self.source, cursor, child.span().start(), has_element);
            match holes {
                Some(holes) => values.extend((0..holes).map(|_| Value::Undefined)),
                None => {
                    self.complete = false;
                    self.draft.set_partial();
                    exact = false;
                }
            }
            if child.kind() == HirKind::SpreadElement {
                let spread = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                if abrupt_value(&spread) {
                    return self.finish_assembly_branches(state, &mut branches, spread);
                }
                if exact_non_iterable(&spread) {
                    return self.finish_assembly_branches(
                        state,
                        &mut branches,
                        Value::SynchronousThrow,
                    );
                }
                match spread {
                    Value::Array(spread) => values.extend(spread),
                    Value::String(spread) => {
                        values.extend(spread.chars().map(|value| Value::String(value.to_string())));
                    }
                    _ => {
                        exact = false;
                        self.start_assembly_branch(state, &mut branches);
                    }
                }
            } else {
                let value = self.eval(child, state, call_depth);
                if abrupt_value(&value) {
                    return self.finish_assembly_branches(state, &mut branches, value);
                }
                values.push(value);
            }
            has_element = true;
            cursor = child.span().end();
            if values.len() > MAX_COLLECTION_ITEMS
                || !self.budget.admit_bytes(values_bytes(&values))
            {
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            }
        }
        let trailing_end = node.span().end().saturating_sub(1);
        match delimited_holes(self.source, cursor, trailing_end, has_element) {
            Some(holes) => values.extend((0..holes).map(|_| Value::Undefined)),
            None => {
                self.complete = false;
                self.draft.set_partial();
                exact = false;
            }
        }
        let value = if values.len() > MAX_COLLECTION_ITEMS
            || !self.budget.admit_bytes(values_bytes(&values))
        {
            Value::Unknown
        } else if exact {
            Value::Array(values)
        } else {
            Value::Unknown
        };
        self.finish_assembly_branches(state, &mut branches, value)
    }

    pub(super) fn object(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut properties = BTreeMap::new();
        let mut prototype_unknown = false;
        let mut exact = true;
        let mut branches = Vec::new();
        for child in named_children(node) {
            let (name, value) = match child.kind() {
                HirKind::Pair => {
                    let key = child.child(HirField::Key);
                    let name = key.map_or(Ok(None), |key| {
                        self.object_property_name(key, state, call_depth)
                    });
                    let name = match name {
                        Err(value) => {
                            return self.finish_assembly_branches(state, &mut branches, value);
                        }
                        Ok(Some(name)) => name,
                        Ok(None) => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                            if let Some(value) = child.child(HirField::Value) {
                                let value = self.eval(value, state, call_depth);
                                if abrupt_value(&value) {
                                    return self.finish_assembly_branches(
                                        state,
                                        &mut branches,
                                        value,
                                    );
                                }
                            }
                            continue;
                        }
                    };
                    let value = child
                        .child(HirField::Value)
                        .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                    if abrupt_value(&value) {
                        return self.finish_assembly_branches(state, &mut branches, value);
                    }
                    if name == "__proto__"
                        && key.is_some_and(|key| key.kind() != HirKind::ComputedPropertyName)
                    {
                        prototype_unknown = true;
                        continue;
                    }
                    (name, value)
                }
                HirKind::ShorthandPropertyIdentifier => {
                    let name = self.text(child).to_owned();
                    let value = state.get(&name);
                    (name, value)
                }
                HirKind::MethodDefinition => {
                    let name = child.child(HirField::Name).map_or(Ok(None), |name| {
                        self.object_property_name(name, state, call_depth)
                    });
                    let name = match name {
                        Err(value) => {
                            return self.finish_assembly_branches(state, &mut branches, value);
                        }
                        Ok(Some(name)) => name,
                        Ok(None) => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                            continue;
                        }
                    };
                    let value = match self.method_accessor_kind(child) {
                        Some("get") => match self.function_value(child, state) {
                            Some(Value::Function(function)) => Value::AccessorGetter(function),
                            _ => Value::Unknown,
                        },
                        Some("set") => Value::Accessor,
                        _ => self.function_value(child, state).unwrap_or(Value::Unknown),
                    };
                    (name, value)
                }
                HirKind::SpreadElement => {
                    let spread = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                    if abrupt_value(&spread) {
                        return self.finish_assembly_branches(state, &mut branches, spread);
                    }
                    match spread {
                        Value::Object(spread) => {
                            for (name, mut value) in spread {
                                if accessor_value(&value) {
                                    self.complete = false;
                                    value = Value::Unknown;
                                }
                                properties.insert(name, value);
                            }
                        }
                        Value::Array(spread) => {
                            for (index, value) in spread.into_iter().enumerate() {
                                properties.insert(index.to_string(), value);
                            }
                        }
                        Value::String(spread) => {
                            for (index, value) in spread.chars().enumerate() {
                                properties
                                    .insert(index.to_string(), Value::String(value.to_string()));
                            }
                        }
                        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) => {}
                        _ => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                        }
                    }
                    if properties.len() > MAX_COLLECTION_ITEMS
                        || !self.budget.admit_bytes(properties_bytes(&properties))
                    {
                        return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
                    }
                    continue;
                }
                _ => {
                    return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
                }
            };
            if value == Value::Accessor
                && matches!(properties.get(&name), Some(Value::AccessorGetter(_)))
            {
                continue;
            }
            properties.insert(name, value);
            if properties.len() > MAX_COLLECTION_ITEMS
                || !self.budget.admit_bytes(properties_bytes(&properties))
            {
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            }
        }
        let value = if prototype_unknown || !exact {
            Value::Unknown
        } else {
            Value::Object(properties)
        };
        self.finish_assembly_branches(state, &mut branches, value)
    }

    pub(super) fn object_property_name(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Result<Option<String>, Value> {
        if node.kind() != HirKind::ComputedPropertyName {
            return Ok(self.property_name(node, state, call_depth));
        }
        let value = named_children(node)
            .next()
            .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
        if abrupt_value(&value) {
            Err(value)
        } else {
            Ok(string_coercion(&value))
        }
    }

    pub(super) fn property_name(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Option<String> {
        match node.kind() {
            HirKind::PropertyIdentifier
            | HirKind::Identifier
            | HirKind::ShorthandPropertyIdentifier
            | HirKind::Number => Some(self.text(node).to_owned()),
            HirKind::String => {
                let source = self.text(node).to_owned();
                self.decode_string(&source)
            }
            HirKind::ComputedPropertyName => named_children(node)
                .next()
                .map(|value| self.eval(value, state, call_depth))
                .and_then(|value| string_coercion(&value)),
            _ => None,
        }
    }

    pub(super) fn decode_string(&mut self, source: &str) -> Option<String> {
        let value = decode_js_string(source)?;
        self.budget.admit_bytes(Some(value.len())).then_some(value)
    }

    pub(super) fn add_values(&mut self, left: Value, right: Value) -> Value {
        match (left, right) {
            (Value::String(mut left), right) => {
                let Some(right) = string_coercion(&right) else {
                    return Value::Unknown;
                };
                let bytes = left.len().checked_add(right.len());
                if !self.budget.admit_bytes(bytes) {
                    return Value::Unknown;
                }
                left.push_str(&right);
                Value::String(left)
            }
            (left, Value::String(right)) => {
                let Some(mut left) = string_coercion(&left) else {
                    return Value::Unknown;
                };
                let bytes = left.len().checked_add(right.len());
                if !self.budget.admit_bytes(bytes) {
                    return Value::Unknown;
                }
                left.push_str(&right);
                Value::String(left)
            }
            (Value::Number(left), Value::Number(right)) => left
                .checked_add(right)
                .map_or(Value::Unknown, Value::Number),
            _ => Value::Unknown,
        }
    }
}
