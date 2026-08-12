//! Python collection, string, attribute, call, and argument expressions.

use super::*;

impl Interpreter<'_> {
    pub(super) fn collection(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let mut values = Vec::new();
        let mut bytes = 0usize;
        for child in named_children(node) {
            if values.len() >= MAX_COLLECTION_ITEMS {
                self.complete = false;
                self.budget.refuse_work();
                return Value::Unknown;
            }
            if child.kind() == HirKind::ListSplat {
                let spread = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                if let Some(items) = sequence_values(&spread, state) {
                    if items.len() > MAX_COLLECTION_ITEMS - values.len() {
                        self.complete = false;
                        self.budget.refuse_work();
                        return Value::Unknown;
                    }
                    let item_bytes = values_bytes(items);
                    let Some(total_bytes) = item_bytes.and_then(|item_bytes| {
                        bytes
                            .checked_add(item_bytes)
                            .filter(|bytes| *bytes <= MAX_VALUE_BYTES)
                    }) else {
                        self.budget.refuse_work();
                        return Value::Unknown;
                    };
                    values.extend_from_slice(items);
                    bytes = total_bytes;
                } else {
                    self.complete = false;
                    return Value::Unknown;
                }
            } else {
                let value = self.eval(child, state, depth);
                let Some(total_bytes) = value_bytes(&value).and_then(|value_bytes| {
                    bytes
                        .checked_add(value_bytes)
                        .filter(|bytes| *bytes <= MAX_VALUE_BYTES)
                }) else {
                    self.budget.refuse_work();
                    return Value::Unknown;
                };
                values.push(value);
                bytes = total_bytes;
            }
        }
        if state.cells.len() >= MAX_CELLS {
            self.budget.refusal = Some(InlineRefusal::WorkLimit);
            return Value::Unknown;
        }
        let cell = state.cells.len();
        state.cells.push(Cell::Sequence {
            values,
            indexable: node.kind() != HirKind::Set,
        });
        Value::Cell(cell)
    }

    pub(super) fn string(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let start = node
            .children()
            .iter()
            .find(|child| child.kind() == HirKind::StringStart)
            .map(|child| self.text(child))
            .unwrap_or_default();
        let prefix_end = start.find(['\'', '"']).unwrap_or(start.len());
        let prefix = start[..prefix_end].to_ascii_lowercase();
        let raw = prefix.contains('r');
        let bytes = prefix.contains('b');
        let formatted = prefix.contains('f');
        let mut value = String::new();
        for child in node.children() {
            match child.kind() {
                HirKind::StringContent => {
                    let Some(content) = decode_string_fragment(self.text(child), raw) else {
                        return Value::Unknown;
                    };
                    if !bounded_push_str(&mut value, &content, &mut self.budget) {
                        return Value::Unknown;
                    }
                }
                HirKind::Interpolation if formatted => {
                    let Some(expression) = child.child(HirField::Expression) else {
                        return Value::Unknown;
                    };
                    let interpolated = self.eval(expression, state, depth);
                    if child.child(HirField::TypeConversion).is_some()
                        || child.child(HirField::FormatSpecifier).is_some()
                    {
                        self.complete = false;
                        return Value::Unknown;
                    }
                    let Some(interpolated) = display_value(&interpolated) else {
                        return Value::Unknown;
                    };
                    if !bounded_push_str(&mut value, &interpolated, &mut self.budget) {
                        return Value::Unknown;
                    }
                }
                _ => {}
            }
        }
        if bytes {
            Value::Bytes(value.into_bytes())
        } else {
            Value::String(value)
        }
    }

    pub(super) fn concatenated_string(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Value {
        let mut result = None;
        for child in named_children(node) {
            let next = self.eval(child, state, depth);
            result = Some(match result {
                None => next,
                Some(value) => binary_value(value, next, "+", &mut self.budget),
            });
        }
        match result.unwrap_or(Value::String(String::new())) {
            Value::String(value) => Value::ImplicitString(value),
            value => value,
        }
    }

    pub(super) fn attribute(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let Some(object) = node.child(HirField::Object) else {
            return Value::Unknown;
        };
        let Some(attribute) = node.child(HirField::Attribute) else {
            return Value::Unknown;
        };
        let object = self.eval(object, state, depth);
        let attribute = self.text(attribute);
        let value = match object {
            Value::None
            | Value::Bool(_)
            | Value::Int(_)
            | Value::String(_)
            | Value::ImplicitString(_)
            | Value::Bytes(_)
            | Value::Path(_)
                if matches!(attribute, "get" | "keys" | "values" | "items") =>
            {
                self.pending_control = Some(Control::Raise);
                Value::Unknown
            }
            Value::Module(module) => {
                if module == Module::Os
                    && let Some(value) = os_open_flag(attribute, self.input.platform)
                {
                    Value::Int(value)
                } else {
                    module_attribute(module, attribute).unwrap_or(Value::ModuleMethod(module))
                }
            }
            Value::Path(path) => Value::PathMethod {
                path,
                method: attribute.to_owned(),
            },
            Value::Cell(cell) => Value::CellMethod {
                cell,
                method: attribute.to_owned(),
            },
            Value::String(value) => Value::StringMethod {
                value,
                method: attribute.to_owned(),
            },
            Value::Bytes(value) => Value::BytesMethod {
                value,
                method: attribute.to_owned(),
            },
            Value::Decoded(value) => Value::DecodedMethod {
                value,
                method: attribute.to_owned(),
            },
            Value::ImportRegistry => import_registry_mutation(attribute)
                .map(Value::ImportRegistryMutator)
                .or_else(|| import_registry_read(attribute).map(Value::ImportRegistryRead))
                .unwrap_or(Value::Unknown),
            Value::Known(KnownFunction::Path) if attribute == "home" => {
                Value::Known(KnownFunction::PathHome)
            }
            Value::Produced(origins) => Value::Produced(origins),
            _ => Value::Unknown,
        };
        if self.budget.admit_value_bytes(value_bytes(&value)) {
            value
        } else {
            Value::Unknown
        }
    }

    pub(super) fn call(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let ipython_target = crate::is_ipython_interpreter(self.program)
            && node.child(HirField::Function).is_some_and(|function| {
                matches!(
                    self.text(function),
                    "get_ipython().system"
                        | "get_ipython().getoutput"
                        | "get_ipython().run_cell_magic"
                )
            });
        let callable = node
            .child(HirField::Function)
            .map_or(Value::Unknown, |function| {
                self.ipython_syntax_function(function)
                    .map(Value::Known)
                    .unwrap_or_else(|| self.eval(function, state, depth))
            });
        if self.pending_control.is_some() {
            return Value::Unknown;
        }
        let arguments = node
            .child(HirField::Arguments)
            .map_or_else(Arguments::default, |arguments| {
                self.arguments(arguments, state, depth)
            });
        if self.pending_control.is_some() {
            return Value::Unknown;
        }
        if matches!(self.initial_state, InitialState::Persistent)
            && matches!(&callable, Value::Unknown)
        {
            self.draft.set_partial();
        }
        match callable {
            Value::Known(function) => self.call_known(function, arguments, state, depth),
            Value::LocalFunction(function) => self.call_local(function, arguments, state, depth),
            Value::PathMethod { path, method } => {
                self.call_path_method(path, &method, arguments, state)
            }
            Value::CellMethod { cell, method } => {
                self.call_cell_method(cell, &method, arguments, state)
            }
            Value::StringMethod { value, method } => {
                self.call_string_method(value, &method, arguments)
            }
            Value::BytesMethod { value, method } => {
                self.call_bytes_method(value, &method, arguments)
            }
            Value::DecodedMethod { value, method } => {
                if method == "decode"
                    && arguments.positional.is_empty()
                    && arguments.keywords.is_empty()
                {
                    match *value {
                        Value::Bytes(value) => String::from_utf8(value).map_or_else(
                            |_| {
                                self.pending_control = Some(Control::Raise);
                                Value::Unknown
                            },
                            |value| Value::Decoded(Box::new(Value::String(value))),
                        ),
                        value => Value::Decoded(Box::new(value)),
                    }
                } else {
                    Value::Unknown
                }
            }
            Value::ImportRegistryMutator(mutation) => {
                let shape = import_registry_mutation_shape(mutation, &arguments);
                if shape == CallShape::Invalid {
                    self.pending_control = Some(Control::Raise);
                    return Value::Unknown;
                }
                invalidate_import_ownership(state);
                self.draft.set_partial();
                Value::Unknown
            }
            Value::ImportRegistryRead(read) => {
                self.admit_call_shape(import_registry_read_shape(read, &arguments));
                Value::Unknown
            }
            Value::ModuleMethod(module) => {
                if module == Module::Environment {
                    invalidate_module(module, state);
                }
                if module == Module::Ipython {
                    self.draft.set_partial();
                }
                state.cwd = NestedExecutionCwd::Unknown;
                Value::Unknown
            }
            Value::Produced(origins) => {
                state.cwd = NestedExecutionCwd::Unknown;
                Value::Produced(origins)
            }
            _ => {
                if invalidate_argument_cells(&arguments, state) {
                    self.draft.set_partial();
                }
                if ipython_target {
                    self.draft.set_partial();
                }
                state.cwd = NestedExecutionCwd::Unknown;
                Value::Unknown
            }
        }
    }

    pub(super) fn ipython_syntax_function(&self, node: &HirNode) -> Option<KnownFunction> {
        if !self.ipython_syntax
            || !Arc::ptr_eq(&self.source, &self.root_source)
            || node.kind() != HirKind::Identifier
        {
            return None;
        }
        match self.text(node) {
            super::super::IPYTHON_CELL_INTRINSIC => Some(KnownFunction::IpythonSyntaxCell),
            super::super::IPYTHON_GETOUTPUT_INTRINSIC => {
                Some(KnownFunction::IpythonSyntaxGetoutput)
            }
            super::super::IPYTHON_SYSTEM_INTRINSIC => Some(KnownFunction::IpythonSyntaxSystem),
            _ => None,
        }
    }

    pub(super) fn arguments(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Arguments {
        let mut arguments = Arguments::default();
        for child in named_children(node) {
            match child.kind() {
                HirKind::KeywordArgument => {
                    let Some(name) = child.child(HirField::Name) else {
                        arguments.complete = false;
                        continue;
                    };
                    let value = child
                        .child(HirField::Value)
                        .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                    let name = self.text(name).to_owned();
                    if arguments
                        .keywords
                        .iter()
                        .any(|(existing, _)| existing == &name)
                    {
                        arguments.complete = false;
                    }
                    arguments.keywords.push((name, value));
                }
                HirKind::ListSplat => {
                    let value = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                    if let Some(values) = sequence_values(&value, state) {
                        arguments.positional.extend_from_slice(values);
                    } else {
                        arguments.complete = false;
                    }
                }
                HirKind::DictionarySplat => {
                    let value = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                    if !matches!(value, Value::EmptyDictionary) {
                        arguments.complete = false;
                    }
                }
                _ => arguments.positional.push(self.eval(child, state, depth)),
            }
        }
        arguments
    }

    pub(super) fn admit_call_shape(&mut self, shape: CallShape) -> bool {
        match shape {
            CallShape::Valid => true,
            CallShape::Invalid => {
                self.pending_control = Some(Control::Raise);
                false
            }
            CallShape::Incomplete => {
                self.complete = false;
                false
            }
        }
    }

    pub(super) fn admit_index_value(&mut self, value: Option<&Value>, none_allowed: bool) -> bool {
        match value {
            None | Some(Value::Int(_) | Value::Bool(_)) => true,
            Some(Value::None) if none_allowed => true,
            Some(Value::Unknown | Value::Produced(_)) => {
                self.draft.set_partial();
                true
            }
            Some(_) => {
                self.pending_control = Some(Control::Raise);
                false
            }
        }
    }

    pub(super) fn admit_value(&mut self, admission: ValueAdmission) -> bool {
        match admission {
            ValueAdmission::Exact => true,
            ValueAdmission::Possible => {
                self.draft.set_partial();
                true
            }
            ValueAdmission::Invalid => {
                self.pending_control = Some(Control::Raise);
                false
            }
        }
    }
}
