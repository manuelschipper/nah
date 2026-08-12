//! Python HIR statement execution, binding, and control flow.

use super::*;

impl Interpreter<'_> {
    pub(super) fn exec_block(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        if let Some(control) = &self.pending_control {
            return control.clone();
        }
        for child in node.children() {
            if matches!(child.kind(), HirKind::Token | HirKind::Comment) {
                continue;
            }
            if !self.budget.enter_statement() || !self.budget.spend() {
                break;
            }
            let control = self.exec_statement(child, state, depth);
            if control != Control::Next {
                return control;
            }
        }
        Control::Next
    }

    pub(super) fn exec_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        let control = match node.kind() {
            HirKind::Module | HirKind::Block => self.exec_block(node, state, depth),
            HirKind::Import => {
                self.import(node, state);
                Control::Next
            }
            HirKind::ImportFrom => {
                self.import_from(node, state);
                Control::Next
            }
            HirKind::ExpressionStatement => {
                if let Some(expression) = named_children(node).next() {
                    if expression.kind() == HirKind::Assignment {
                        self.assignment(expression, state, depth);
                    } else if expression.kind() == HirKind::AugmentedAssignment {
                        self.augmented_assignment(expression, state, depth);
                    } else {
                        self.eval(expression, state, depth);
                    }
                }
                Control::Next
            }
            HirKind::Assignment => {
                self.assignment(node, state, depth);
                Control::Next
            }
            HirKind::AugmentedAssignment => {
                self.augmented_assignment(node, state, depth);
                Control::Next
            }
            HirKind::If => self.if_statement(node, state, depth),
            HirKind::For => self.for_statement(node, state, depth),
            HirKind::While => self.while_statement(node, state, depth),
            HirKind::Function => {
                self.define_function(node, state, depth, false);
                Control::Next
            }
            HirKind::DecoratedDefinition => {
                let mut control = Control::Next;
                for decorator in node
                    .children()
                    .iter()
                    .filter(|child| child.kind() == HirKind::Decorator)
                {
                    for expression in named_children(decorator) {
                        self.eval(expression, state, depth);
                    }
                }
                if let Some(definition) = node.child(HirField::Definition) {
                    if definition.kind() == HirKind::Function {
                        self.define_function(definition, state, depth, true);
                    } else {
                        control = self.exec_class(definition, state, depth);
                    }
                }
                control
            }
            HirKind::Class => self.exec_class(node, state, depth),
            HirKind::Return => {
                let value = named_children(node)
                    .next()
                    .map_or(Value::None, |value| self.eval(value, state, depth));
                Control::Return(value)
            }
            HirKind::Raise => {
                for expression in named_children(node) {
                    self.eval(expression, state, depth);
                }
                Control::Raise
            }
            HirKind::Break => Control::Break,
            HirKind::Continue => Control::Continue,
            HirKind::With => self.with_statement(node, state, depth),
            HirKind::Delete => {
                for target in named_children(node) {
                    self.delete(target, state);
                }
                Control::Next
            }
            HirKind::Try => self.try_statement(node, state, depth),
            HirKind::Exec => {
                if let Some(source) = named_children(node).next() {
                    let value = self.eval(source, state, depth);
                    self.dynamic_execution(value, CodeMode::Exec, state, depth);
                }
                Control::Next
            }
            HirKind::Print => {
                for expression in named_children(node) {
                    self.eval(expression, state, depth);
                }
                Control::Next
            }
            HirKind::Pass | HirKind::Comment | HirKind::Token => Control::Next,
            HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                self.widen_unsupported_bindings(node, state);
                Control::Next
            }
            _ => {
                self.eval(node, state, depth);
                Control::Next
            }
        };
        self.pending_control.take().unwrap_or(control)
    }

    pub(super) fn eval(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        if self.pending_control.is_some() {
            return Value::Unknown;
        }
        if !self.budget.spend() {
            return Value::Unknown;
        }
        match node.kind() {
            HirKind::Identifier => state
                .bindings
                .get(self.text(node))
                .cloned()
                .unwrap_or(Value::Unknown),
            HirKind::String => self.string(node, state, depth),
            HirKind::ConcatenatedString => self.concatenated_string(node, state, depth),
            HirKind::Integer => parse_integer(self.text(node)).map_or(Value::Unknown, Value::Int),
            HirKind::Float => Value::Unknown,
            HirKind::True => Value::Bool(true),
            HirKind::False => Value::Bool(false),
            HirKind::None => Value::None,
            HirKind::List | HirKind::Tuple | HirKind::Set => self.collection(node, state, depth),
            HirKind::Dictionary => {
                let mut empty = true;
                for child in named_children(node) {
                    empty = false;
                    if child.kind() == HirKind::Pair {
                        if let Some(key) = child.child(HirField::Key) {
                            self.eval(key, state, depth);
                        }
                        if let Some(value) = child.child(HirField::Value) {
                            self.eval(value, state, depth);
                        }
                    } else {
                        self.eval(child, state, depth);
                    }
                }
                if empty {
                    Value::EmptyDictionary
                } else {
                    Value::Unknown
                }
            }
            HirKind::ParenthesizedExpression => named_children(node)
                .next()
                .map_or(Value::None, |child| self.eval(child, state, depth)),
            HirKind::Attribute => self.attribute(node, state, depth),
            HirKind::Call => self.call(node, state, depth),
            HirKind::BinaryOperator => self.binary(node, state, depth),
            HirKind::BooleanOperator => self.boolean(node, state, depth),
            HirKind::ComparisonOperator => self.comparison(node, state, depth),
            HirKind::NotOperator => {
                let value = node
                    .child(HirField::Argument)
                    .or_else(|| named_children(node).next())
                    .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                truthy(&value, state).map_or(Value::Unknown, |value| Value::Bool(!value))
            }
            HirKind::UnaryOperator => self.unary(node, state, depth),
            HirKind::ConditionalExpression => self.conditional_expression(node, state, depth),
            HirKind::Subscript => self.subscript(node, state, depth),
            HirKind::Lambda => Value::Unknown,
            HirKind::Generator => Value::Unknown,
            HirKind::Assignment => {
                self.assignment(node, state, depth);
                node.child(HirField::Left)
                    .and_then(|left| state.bindings.get(self.text(left)))
                    .cloned()
                    .unwrap_or(Value::Unknown)
            }
            HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                self.widen_unsupported_bindings(node, state);
                Value::Unknown
            }
            _ => {
                self.eval_children(node, state, depth);
                Value::Unknown
            }
        }
    }

    pub(super) fn eval_children(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        for child in named_children(node) {
            if !matches!(
                child.kind(),
                HirKind::Function | HirKind::Class | HirKind::Lambda
            ) {
                self.eval(child, state, depth);
            }
        }
    }

    pub(super) fn assignment(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        let Some(left) = node.child(HirField::Left) else {
            self.complete = false;
            return;
        };
        let value = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        if self.pending_control.is_some() {
            return;
        }
        self.assign(left, value, state);
    }

    pub(super) fn augmented_assignment(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        let Some(left) = node.child(HirField::Left) else {
            return;
        };
        let mutates_import_registry = is_import_registry(left, state, &self.source);
        let current = self.eval(left, state, depth);
        let right = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        if self.pending_control.is_some() {
            return;
        }
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default()
            .to_owned();
        if mutates_import_registry {
            invalidate_import_ownership(state);
            self.draft.set_partial();
        }
        let value = binary_value(current, right, &operator, &mut self.budget);
        self.assign(left, value, state);
    }

    pub(super) fn assign(&mut self, target: &HirNode, value: Value, state: &mut State) {
        match target.kind() {
            HirKind::Identifier => {
                if value == Value::Module(Module::Ipython) {
                    invalidate_module(Module::Ipython, state);
                    self.draft.set_partial();
                    state
                        .bindings
                        .insert(self.text(target).to_owned(), Value::Unknown);
                    return;
                }
                state.bindings.insert(self.text(target).to_owned(), value);
            }
            HirKind::Tuple | HirKind::List => {
                let values = sequence_values(&value, state).map(Vec::from);
                for (index, child) in named_children(target).enumerate() {
                    let value = values
                        .as_ref()
                        .and_then(|values| values.get(index))
                        .cloned()
                        .unwrap_or(Value::Unknown);
                    self.assign(child, value, state);
                }
            }
            HirKind::Attribute => {
                if is_import_registry_attribute(target, state, &self.source) {
                    invalidate_import_ownership(state);
                    self.draft.set_partial();
                } else {
                    target
                        .child(HirField::Object)
                        .into_iter()
                        .for_each(|object| self.invalidate_mutation_target(object, state));
                }
            }
            HirKind::Subscript => self.invalidate_mutation_target(target, state),
            _ => self.complete = false,
        }
    }

    pub(super) fn invalidate_mutation_target(&mut self, target: &HirNode, state: &mut State) {
        if is_import_registry(target, state, &self.source) {
            invalidate_import_ownership(state);
            self.draft.set_partial();
            return;
        }
        if target.kind() == HirKind::Subscript {
            if let Some(object) = named_children(target).next() {
                self.invalidate_mutation_target(object, state);
            } else {
                self.complete = false;
            }
            return;
        }
        if let Some(module) = owned_module_target(target, state, &self.source) {
            invalidate_module(module, state);
            self.complete = false;
            return;
        }
        let mut root = target;
        while root.kind() != HirKind::Identifier {
            let Some(child) = named_children(root).next() else {
                self.complete = false;
                return;
            };
            root = child;
        }
        let name = self.text(root).to_owned();
        match state.bindings.get(&name).cloned() {
            Some(Value::Cell(cell)) => {
                if let Some(value) = state.cells.get_mut(cell) {
                    *value = Cell::Unknown;
                }
            }
            Some(Value::Module(module)) => {
                invalidate_module(module, state);
            }
            _ => {
                state.bindings.insert(name, Value::Unknown);
            }
        }
        self.complete = false;
    }

    pub(super) fn delete(&mut self, target: &HirNode, state: &mut State) {
        match target.kind() {
            HirKind::Identifier => {
                state
                    .bindings
                    .insert(self.text(target).to_owned(), Value::Unknown);
            }
            HirKind::Tuple | HirKind::List | HirKind::ParenthesizedExpression => {
                for target in named_children(target) {
                    self.delete(target, state);
                }
            }
            HirKind::Attribute => {
                if is_import_registry_attribute(target, state, &self.source) {
                    invalidate_import_ownership(state);
                    self.draft.set_partial();
                } else {
                    target
                        .child(HirField::Object)
                        .into_iter()
                        .for_each(|object| self.invalidate_mutation_target(object, state));
                }
            }
            HirKind::Subscript => self.invalidate_mutation_target(target, state),
            _ => self.complete = false,
        }
    }

    pub(super) fn widen_unsupported_bindings(&mut self, node: &HirNode, state: &mut State) {
        for name in assigned_names(node, &self.source) {
            state.bindings.insert(name, Value::Unknown);
        }
        for name in capture_names(node, &self.source) {
            state.bindings.insert(name, Value::Unknown);
        }
    }

    pub(super) fn import(&mut self, node: &HirNode, state: &mut State) {
        for imported in named_children(node) {
            let (name, alias) = import_name(imported, &self.source);
            let value = if alias.is_some() {
                module_value(&name)
            } else {
                name.split('.').next().and_then(module_value)
            }
            .unwrap_or(Value::Unknown);
            let value = retain_owned_module(value, state);
            let binding =
                alias.unwrap_or_else(|| name.split('.').next().unwrap_or(name.as_str()).to_owned());
            state.bindings.insert(binding, value);
        }
    }

    pub(super) fn import_from(&mut self, node: &HirNode, state: &mut State) {
        let module = node
            .child(HirField::ModuleName)
            .map(|module| self.text(module).trim_matches('.'))
            .unwrap_or_default();
        for imported in node.children().iter().filter(|child| {
            matches!(child.kind(), HirKind::AliasedImport | HirKind::DottedName)
                && child.field() != Some(HirField::ModuleName)
        }) {
            let (name, alias) = import_name(imported, &self.source);
            let binding = alias.unwrap_or_else(|| name.clone());
            let value = if module_value(module).is_some_and(|value| {
                matches!(value, Value::Module(module) if state.invalid_modules.contains(&module))
            }) {
                Value::Unknown
            } else {
                imported_value(module, &name).unwrap_or(Value::Unknown)
            };
            state.bindings.insert(binding, value);
        }
    }

    pub(super) fn define_function(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
        decorated: bool,
    ) {
        let Some(name_node) = node.child(HirField::Name) else {
            return;
        };
        let name = self.text(name_node).to_owned();
        let parameters = node
            .child(HirField::Parameters)
            .and_then(|parameters| self.parameters(parameters, state, depth));
        if let Some(annotation) = node.child(HirField::ReturnType) {
            self.eval(annotation, state, depth);
        }
        if self.pending_control.is_some() {
            return;
        }
        let Some(body) = node.child(HirField::Body) else {
            state.bindings.insert(name, Value::Unknown);
            return;
        };
        if decorated
            || self.text(node).trim_start().starts_with("async ")
            || contains_kind(body, HirKind::Unsupported, self.source.as_ref(), "yield")
        {
            state.bindings.insert(name, Value::Unknown);
            return;
        }
        let function = state.functions.len();
        state.functions.push(LocalFunction {
            name: name.clone(),
            parameters,
            body: body.clone(),
            source: Arc::clone(&self.source),
        });
        state.bindings.insert(name, Value::LocalFunction(function));
    }

    pub(super) fn parameters(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Option<Vec<Parameter>> {
        let mut parameters = Vec::new();
        let mut complete = true;
        for child in named_children(node) {
            match child.kind() {
                HirKind::Identifier => parameters.push(Parameter {
                    name: self.text(child).to_owned(),
                    default: None,
                }),
                HirKind::DefaultParameter | HirKind::TypedDefaultParameter => {
                    if let Some(annotation) = child.child(HirField::Type) {
                        self.eval(annotation, state, depth);
                    }
                    let default = child
                        .child(HirField::Value)
                        .map(|value| self.eval(value, state, depth));
                    if let Some(name) = child
                        .child(HirField::Name)
                        .filter(|name| name.kind() == HirKind::Identifier)
                    {
                        parameters.push(Parameter {
                            name: self.text(name).to_owned(),
                            default,
                        });
                    } else {
                        complete = false;
                    }
                }
                HirKind::TypedParameter => {
                    if let Some(name) = child.child(HirField::Name).or_else(|| {
                        named_children(child).find(|node| node.kind() == HirKind::Identifier)
                    }) {
                        parameters.push(Parameter {
                            name: self.text(name).to_owned(),
                            default: None,
                        });
                    } else {
                        complete = false;
                    }
                    if let Some(annotation) = child.child(HirField::Type) {
                        self.eval(annotation, state, depth);
                    }
                }
                _ => complete = false,
            }
        }
        let mut names = BTreeSet::new();
        if parameters
            .iter()
            .any(|parameter| !names.insert(parameter.name.as_str()))
        {
            complete = false;
        }
        if complete {
            Some(parameters)
        } else {
            self.complete = false;
            None
        }
    }

    pub(super) fn exec_class(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        for child in node.children() {
            if matches!(child.field(), Some(HirField::Name | HirField::Body)) {
                continue;
            }
            if child.kind() != HirKind::Token {
                self.eval(child, state, depth);
            }
        }
        if let Some(body) = node.child(HirField::Body) {
            let mut class_state = state.clone();
            let control = self.exec_block(body, &mut class_state, depth);
            if control != Control::Next {
                self.complete = false;
            }
            propagate_invalid_modules(&class_state.invalid_modules, state);
            state.cwd = class_state.cwd;
            state.cells = class_state.cells;
            if control != Control::Next {
                return control;
            }
        }
        if let Some(name) = node.child(HirField::Name) {
            state
                .bindings
                .insert(self.text(name).to_owned(), Value::Unknown);
        }
        Control::Next
    }

    pub(super) fn if_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |condition| {
                self.eval(condition, state, depth)
            });
        let consequence = node.child(HirField::Consequence);
        let alternatives = node
            .children()
            .iter()
            .filter(|child| child.field() == Some(HirField::Alternative))
            .collect::<Vec<_>>();
        match truthy(&condition, state) {
            Some(true) => {
                consequence.map_or(Control::Next, |body| self.exec_block(body, state, depth))
            }
            Some(false) => self.exec_alternatives(&alternatives, state, depth),
            None => {
                self.complete = false;
                let mut yes = state.clone();
                let mut no = state.clone();
                let dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                let yes_control = consequence
                    .map_or(Control::Next, |body| self.exec_block(body, &mut yes, depth));
                self.execution_dominators.clone_from(&dominators);
                let no_control = self.exec_alternatives(&alternatives, &mut no, depth);
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
                let (joined, control) = merge_branch_states(yes, yes_control, no, no_control);
                *state = joined;
                control
            }
        }
    }

    pub(super) fn exec_alternatives(
        &mut self,
        alternatives: &[&HirNode],
        state: &mut State,
        depth: usize,
    ) -> Control {
        let Some((alternative, rest)) = alternatives.split_first() else {
            return Control::Next;
        };
        match alternative.kind() {
            HirKind::Else => alternative
                .child(HirField::Body)
                .map_or(Control::Next, |body| self.exec_block(body, state, depth)),
            HirKind::Elif => {
                let condition = alternative
                    .child(HirField::Condition)
                    .map_or(Value::Unknown, |condition| {
                        self.eval(condition, state, depth)
                    });
                match truthy(&condition, state) {
                    Some(true) => alternative
                        .child(HirField::Consequence)
                        .map_or(Control::Next, |body| self.exec_block(body, state, depth)),
                    Some(false) => self.exec_alternatives(rest, state, depth),
                    None => {
                        self.complete = false;
                        let mut yes = state.clone();
                        let mut no = state.clone();
                        let dominators = self.execution_dominators.clone();
                        self.conditional_depth += 1;
                        let yes_control = alternative
                            .child(HirField::Consequence)
                            .map_or(Control::Next, |body| self.exec_block(body, &mut yes, depth));
                        self.execution_dominators.clone_from(&dominators);
                        let no_control = self.exec_alternatives(rest, &mut no, depth);
                        self.conditional_depth -= 1;
                        self.execution_dominators = dominators;
                        let (joined, control) =
                            merge_branch_states(yes, yes_control, no, no_control);
                        *state = joined;
                        control
                    }
                }
            }
            _ => Control::Next,
        }
    }

    pub(super) fn for_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        let Some(target) = node.child(HirField::Left) else {
            return Control::Next;
        };
        let iterable = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        let Some(body) = node.child(HirField::Body) else {
            return Control::Next;
        };
        let values = sequence_values(&iterable, state).map(Vec::from);
        let Some(values) = values else {
            self.complete = false;
            let before = state.clone();
            self.assign(target, Value::Unknown, state);
            let dominators = self.execution_dominators.clone();
            self.conditional_depth += 1;
            let control = self.exec_block(body, state, depth);
            self.execution_dominators.clone_from(&dominators);
            let joined_control = match &control {
                Control::Next | Control::Continue => {
                    *state = join_states(before, state.clone());
                    self.exec_loop_else(node, state, depth)
                }
                Control::Break => {
                    let mut zero_iterations = before;
                    let _ = self.exec_loop_else(node, &mut zero_iterations, depth);
                    *state = join_states(zero_iterations, state.clone());
                    Control::Next
                }
                _ => {
                    let mut zero_iterations = before;
                    let zero_control = self.exec_loop_else(node, &mut zero_iterations, depth);
                    *state = zero_iterations;
                    if control == zero_control {
                        control
                    } else {
                        Control::Next
                    }
                }
            };
            self.conditional_depth -= 1;
            self.execution_dominators = dominators;
            return joined_control;
        };
        if values.len() > MAX_LOOP_ITERATIONS {
            self.complete = false;
            self.budget.refusal = Some(InlineRefusal::WorkLimit);
        }
        let complete = values.len() <= MAX_LOOP_ITERATIONS;
        let mut broke = false;
        for value in values.into_iter().take(MAX_LOOP_ITERATIONS) {
            self.assign(target, value, state);
            match self.exec_block(body, state, depth) {
                Control::Next | Control::Continue => {}
                Control::Break => {
                    broke = true;
                    break;
                }
                control => return control,
            }
        }
        if complete && !broke {
            self.exec_loop_else(node, state, depth)
        } else {
            Control::Next
        }
    }

    pub(super) fn while_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        let Some(condition) = node.child(HirField::Condition) else {
            self.complete = false;
            return Control::Next;
        };
        let Some(body) = node.child(HirField::Body) else {
            self.complete = false;
            return Control::Next;
        };
        for _ in 0..MAX_LOOP_ITERATIONS {
            let value = self.eval(condition, state, depth);
            match truthy(&value, state) {
                Some(false) => return self.exec_loop_else(node, state, depth),
                Some(true) => {
                    let before = state.clone();
                    match self.exec_block(body, state, depth) {
                        Control::Next | Control::Continue => {
                            if *state == before {
                                return Control::Diverge;
                            }
                        }
                        Control::Break => return Control::Next,
                        control => return control,
                    }
                }
                None => {
                    self.complete = false;
                    let dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let mut exits = state.clone();
                    let exit_control = self.exec_loop_else(node, &mut exits, depth);
                    self.execution_dominators.clone_from(&dominators);
                    let mut iterates = state.clone();
                    let body_control = self.exec_block(body, &mut iterates, depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = dominators;
                    *state = if matches!(
                        body_control,
                        Control::Return(_) | Control::Raise | Control::Diverge
                    ) {
                        exits
                    } else {
                        join_states(exits, iterates)
                    };
                    return if exit_control == body_control {
                        exit_control
                    } else {
                        Control::Next
                    };
                }
            }
        }
        self.complete = false;
        self.budget.refusal = Some(InlineRefusal::WorkLimit);
        Control::Next
    }

    pub(super) fn exec_loop_else(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        node.child(HirField::Alternative)
            .and_then(|alternative| alternative.child(HirField::Body))
            .map_or(Control::Next, |body| self.exec_block(body, state, depth))
    }

    pub(super) fn with_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        for item in node
            .children()
            .iter()
            .find(|child| child.kind() == HirKind::WithClause)
            .into_iter()
            .flat_map(named_children)
        {
            let Some(value) = item.child(HirField::Value) else {
                self.complete = false;
                continue;
            };
            if value.kind() == HirKind::AsPattern {
                if let Some(context) =
                    named_children(value).find(|child| child.field() != Some(HirField::Alias))
                {
                    self.eval(context, state, depth);
                }
                if self.pending_control.is_some() {
                    break;
                }
                if let Some(alias) = value.child(HirField::Alias) {
                    self.assign_unknown(alias, state);
                } else {
                    self.complete = false;
                }
            } else {
                self.eval(value, state, depth);
            }
        }
        if let Some(control) = self.pending_control.take() {
            return control;
        }
        node.child(HirField::Body)
            .map_or(Control::Next, |body| self.exec_block(body, state, depth))
    }

    pub(super) fn assign_unknown(&mut self, target: &HirNode, state: &mut State) {
        if target.kind() == HirKind::Identifier {
            state
                .bindings
                .insert(self.text(target).to_owned(), Value::Unknown);
            return;
        }
        let mut found = false;
        for child in named_children(target) {
            found = true;
            self.assign_unknown(child, state);
        }
        if !found {
            self.complete = false;
        }
    }

    pub(super) fn try_statement(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Control {
        let mut control = node
            .child(HirField::Body)
            .map_or(Control::Next, |body| self.exec_block(body, state, depth));
        if control == Control::Raise {
            let raised_state = state.clone();
            let mut handled = None;
            let mut catches_all = false;
            let dominators = self.execution_dominators.clone();
            for clause in node
                .children()
                .iter()
                .filter(|child| child.kind() == HirKind::Except)
            {
                let mut children = named_children(clause);
                let first = children.next();
                let bare = first.is_some_and(|child| child.kind() == HirKind::Block)
                    && children.next().is_none();
                if !bare {
                    self.complete = false;
                }
                let Some(body) = clause.child(HirField::Body).or_else(|| {
                    named_children(clause).find(|child| child.kind() == HirKind::Block)
                }) else {
                    self.complete = false;
                    continue;
                };
                let mut handler_state = raised_state.clone();
                let conditional = !bare || handled.is_some();
                if conditional {
                    self.conditional_depth += 1;
                }
                let handler_control = self.exec_block(body, &mut handler_state, depth);
                if conditional {
                    self.conditional_depth -= 1;
                }
                self.execution_dominators.clone_from(&dominators);
                handled = Some(match handled {
                    Some((state, control)) => {
                        merge_branch_states(state, control, handler_state, handler_control)
                    }
                    None => (handler_state, handler_control),
                });
                if bare {
                    catches_all = true;
                    break;
                }
            }
            self.execution_dominators = dominators;
            if let Some((handled_state, handled_control)) = handled {
                let (joined, joined_control) = if catches_all {
                    (handled_state, handled_control)
                } else {
                    merge_branch_states(
                        handled_state,
                        handled_control,
                        raised_state,
                        Control::Raise,
                    )
                };
                *state = joined;
                control = joined_control;
            }
        } else if control == Control::Next
            && let Some(alternative) = node
                .children()
                .iter()
                .find(|child| child.kind() == HirKind::Else)
            && let Some(body) = alternative.child(HirField::Body).or_else(|| {
                named_children(alternative).find(|child| child.kind() == HirKind::Block)
            })
        {
            control = self.exec_block(body, state, depth);
        }
        if control != Control::Diverge
            && let Some(finally) = node
                .children()
                .iter()
                .find(|child| child.kind() == HirKind::Finally)
            && let Some(body) = finally
                .child(HirField::Body)
                .or_else(|| named_children(finally).find(|child| child.kind() == HirKind::Block))
        {
            let final_control = self.exec_block(body, state, depth);
            if final_control != Control::Next {
                control = final_control;
            }
        }
        control
    }
}
