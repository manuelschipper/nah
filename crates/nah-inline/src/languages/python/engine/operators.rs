//! Python operators, comparisons, conditional expressions, and subscripts.

use super::*;

impl Interpreter<'_> {
    pub(super) fn binary(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let left = node
            .child(HirField::Left)
            .map_or(Value::Unknown, |left| self.eval(left, state, depth));
        let right = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default()
            .to_owned();
        binary_value(left, right, &operator, &mut self.budget)
    }

    pub(super) fn boolean(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let Some(left_node) = node.child(HirField::Left) else {
            return Value::Unknown;
        };
        let left = self.eval(left_node, state, depth);
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default();
        match (operator, truthy(&left, state)) {
            ("and", Some(false)) | ("or", Some(true)) => left,
            ("and", Some(true)) | ("or", Some(false)) => node
                .child(HirField::Right)
                .map_or(Value::Unknown, |right| self.eval(right, state, depth)),
            ("and" | "or", None) => {
                self.complete = false;
                let dominators = self.execution_dominators.clone();
                for ordinal in producer_ordinals(&left) {
                    if !self.execution_dominators.contains(&ordinal) {
                        self.execution_dominators.push(ordinal);
                    }
                }
                self.conditional_depth += 1;
                let right = node
                    .child(HirField::Right)
                    .map_or(Value::Unknown, |right| self.eval(right, state, depth));
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
                join_values(left, right)
            }
            _ => {
                self.complete = false;
                Value::Unknown
            }
        }
    }

    pub(super) fn comparison(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let mut left = None;
        let mut operator = None;
        let mut compared = false;
        let mut unknown = false;
        for child in node.children() {
            if child.field() == Some(HirField::Operators) {
                operator = Some(self.text(child).to_owned());
                continue;
            }
            if matches!(child.kind(), HirKind::Token | HirKind::Comment) {
                continue;
            }
            let conditional = unknown && left.is_some();
            let dominators = self.execution_dominators.clone();
            if conditional {
                self.complete = false;
                self.conditional_depth += 1;
            }
            let right = self.eval(child, state, depth);
            if conditional {
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
            }
            let Some(previous) = left.replace(right.clone()) else {
                continue;
            };
            let Some(operator) = operator.take() else {
                self.complete = false;
                return Value::Unknown;
            };
            compared = true;
            match compare_values(&previous, &right, &operator) {
                Some(false) => return Value::Bool(false),
                Some(true) => {}
                None => unknown = true,
            }
        }
        if !compared || operator.is_some() {
            self.complete = false;
            Value::Unknown
        } else if unknown {
            Value::Unknown
        } else {
            Value::Bool(true)
        }
    }

    pub(super) fn unary(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let value = named_children(node)
            .find(|child| child.field() != Some(HirField::Operator))
            .map_or(Value::Unknown, |value| self.eval(value, state, depth));
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default();
        match (operator, value) {
            ("-", Value::Int(value)) => value.checked_neg().map_or(Value::Unknown, Value::Int),
            ("+", Value::Int(value)) => Value::Int(value),
            _ => Value::Unknown,
        }
    }

    pub(super) fn conditional_expression(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Value {
        let children = named_children(node).collect::<Vec<_>>();
        if children.len() != 3 {
            self.eval_children(node, state, depth);
            return Value::Unknown;
        }
        let condition = self.eval(children[1], state, depth);
        match truthy(&condition, state) {
            Some(true) => self.eval(children[0], state, depth),
            Some(false) => self.eval(children[2], state, depth),
            None => {
                self.complete = false;
                let dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                let yes = self.eval(children[0], state, depth);
                self.execution_dominators.clone_from(&dominators);
                let no = self.eval(children[2], state, depth);
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
                join_values(yes, no)
            }
        }
    }

    pub(super) fn subscript(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        match registry_provenance(node, state, &self.source) {
            RegistryProvenance::Exact => return Value::ImportRegistry,
            RegistryProvenance::Possible => {
                invalidate_import_ownership(state);
                self.draft.set_partial();
            }
            RegistryProvenance::None => {}
        }
        let children = named_children(node).collect::<Vec<_>>();
        if children.len() < 2 {
            return Value::Unknown;
        }
        if is_sys_module_dictionary(children[0], state, &self.source)
            && matches!(
                static_string(children[1], state, &self.source),
                StaticString::Exact(value) if value == "version"
            )
        {
            return Value::ImplicitString(String::new());
        }
        let object = self.eval(children[0], state, depth);
        let index = self.eval(children[1], state, depth);
        match object {
            Value::Module(Module::Environment)
                if !state.invalid_modules.contains(&Module::Environment)
                    && value_string(&index).is_some_and(|value| value == "HOME") =>
            {
                Value::String(self.input.home.to_owned())
            }
            Value::Cell(cell) => match state.cells.get(cell) {
                Some(Cell::Sequence {
                    values,
                    indexable: true,
                }) => match exact_index(&index) {
                    Some(index) => sequence_index(values, index).cloned().unwrap_or_else(|| {
                        self.pending_control = Some(Control::Raise);
                        Value::Unknown
                    }),
                    None if matches!(index, Value::Unknown | Value::Produced(_)) => {
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    None => {
                        self.pending_control = Some(Control::Raise);
                        Value::Unknown
                    }
                },
                Some(Cell::Sequence {
                    indexable: false, ..
                }) => {
                    self.pending_control = Some(Control::Raise);
                    Value::Unknown
                }
                Some(Cell::Unknown) | None => Value::Unknown,
            },
            _ => Value::Unknown,
        }
    }
}
