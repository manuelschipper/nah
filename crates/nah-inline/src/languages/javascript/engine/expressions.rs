//! JavaScript expression dispatch, operators, short-circuiting, and ternaries.

use super::*;

impl Interpreter<'_> {
    pub(super) fn eval(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        if !self.budget.spend() {
            return Value::Unknown;
        }
        match node.kind() {
            HirKind::Identifier => state.get(self.text(node)),
            HirKind::String => {
                let source = self.text(node).to_owned();
                self.decode_string(&source)
                    .map_or(Value::Unknown, Value::String)
            }
            HirKind::TemplateString => self.template(node, state, call_depth),
            HirKind::Number => parse_number(self.text(node)).map_or(Value::Unknown, Value::Number),
            HirKind::True => Value::Bool(true),
            HirKind::False => Value::Bool(false),
            HirKind::Null => Value::Null,
            HirKind::Undefined => Value::Undefined,
            HirKind::Array => self.array(node, state, call_depth),
            HirKind::Object => self.object(node, state, call_depth),
            HirKind::FunctionExpression | HirKind::ArrowFunction => {
                self.function_value(node, state).unwrap_or(Value::Unknown)
            }
            HirKind::ParenthesizedExpression | HirKind::TransparentExpression => {
                named_children(node)
                    .next()
                    .map_or(Value::Unknown, |child| self.eval(child, state, call_depth))
            }
            HirKind::AwaitExpression => {
                let value = if let Some(child) = named_children(node).next() {
                    let awaited_call = direct_call_identity(child);
                    let previous = std::mem::replace(&mut self.awaited_call, awaited_call);
                    let value = self.eval(child, state, call_depth);
                    self.awaited_call = previous;
                    value
                } else {
                    Value::Unknown
                };
                if let Some(frame) = self.async_frames.last_mut()
                    && frame.deferred
                    && frame.prefix.is_none()
                {
                    let mut prefix = state.clone();
                    if self.conditional_depth > 0 {
                        prefix.cwd = NestedExecutionCwd::Unknown;
                        self.complete = false;
                    }
                    frame.prefix = Some(prefix);
                }
                match value {
                    Value::RejectedPromise => Value::SynchronousThrow,
                    Value::Promise => Value::Unknown,
                    value => value,
                }
            }
            HirKind::SequenceExpression => {
                let mut value = Value::Undefined;
                for child in named_children(node) {
                    value = self.eval(child, state, call_depth);
                    if abrupt_value(&value) {
                        return value;
                    }
                }
                value
            }
            HirKind::BinaryExpression => self.binary(node, state, call_depth),
            HirKind::UnaryExpression => self.unary(node, state, call_depth),
            HirKind::TernaryExpression => self.ternary(node, state, call_depth),
            HirKind::AssignmentExpression => self.assignment(node, state, call_depth),
            HirKind::AugmentedAssignmentExpression | HirKind::UpdateExpression => {
                self.augmented_assignment(node, state, call_depth)
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression => {
                self.member(node, state, call_depth)
            }
            HirKind::CallExpression => self.call(node, state, call_depth),
            HirKind::NewExpression => self.construct(node, state, call_depth),
            HirKind::ComputedPropertyName | HirKind::TemplateSubstitution => named_children(node)
                .next()
                .map_or(Value::Unknown, |child| self.eval(child, state, call_depth)),
            HirKind::ExpressionStatement => named_children(node)
                .next()
                .map_or(Value::Undefined, |child| {
                    self.eval(child, state, call_depth)
                }),
            HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                Value::Unknown
            }
            _ => Value::Unknown,
        }
    }

    pub(super) fn binary(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let Some(left_node) = node.child(HirField::Left) else {
            return Value::Unknown;
        };
        let Some(right_node) = node.child(HirField::Right) else {
            return Value::Unknown;
        };
        let operator = node
            .child(HirField::Operator)
            .map_or_else(String::new, |operator| self.text(operator).to_owned());
        let left = self.eval(left_node, state, call_depth);
        if abrupt_value(&left) {
            return left;
        }
        match operator.as_str() {
            "&&" => match truthy(&left) {
                Some(false) => left,
                Some(true) => self.eval(right_node, state, call_depth),
                None => {
                    self.complete = false;
                    let before = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let right = self.eval(right_node, state, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, state.clone());
                    join_values(left, right)
                }
            },
            "||" => match truthy(&left) {
                Some(true) => left,
                Some(false) => self.eval(right_node, state, call_depth),
                None => {
                    self.complete = false;
                    let before = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let right = self.eval(right_node, state, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, state.clone());
                    join_values(left, right)
                }
            },
            "??" => match left {
                Value::Null | Value::Undefined => self.eval(right_node, state, call_depth),
                Value::Unknown => {
                    self.complete = false;
                    let before = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let right = self.eval(right_node, state, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, state.clone());
                    join_values(Value::Unknown, right)
                }
                value => value,
            },
            _ => {
                let right = self.eval(right_node, state, call_depth);
                if abrupt_value(&right) {
                    return right;
                }
                match operator.as_str() {
                    "+" => self.add_values(left, right),
                    "===" => strict_equal(&left, &right).map_or(Value::Unknown, Value::Bool),
                    "!==" => strict_equal(&left, &right)
                        .map(|equal| Value::Bool(!equal))
                        .unwrap_or(Value::Unknown),
                    "==" => loose_equal(&left, &right).map_or(Value::Unknown, Value::Bool),
                    "!=" => loose_equal(&left, &right)
                        .map(|equal| Value::Bool(!equal))
                        .unwrap_or(Value::Unknown),
                    _ => Value::Unknown,
                }
            }
        }
    }

    pub(super) fn unary(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let operator = node
            .child(HirField::Operator)
            .map_or_else(String::new, |operator| self.text(operator).to_owned());
        let argument = node
            .child(HirField::Argument)
            .or_else(|| named_children(node).next())
            .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
        if abrupt_value(&argument) {
            return argument;
        }
        match operator.as_str() {
            "!" => truthy(&argument).map_or(Value::Unknown, |value| Value::Bool(!value)),
            "void" => Value::Undefined,
            "+" => match argument {
                Value::Number(value) => Value::Number(value),
                _ => Value::Unknown,
            },
            "-" => match argument {
                Value::Number(value) => value.checked_neg().map_or(Value::Unknown, Value::Number),
                _ => Value::Unknown,
            },
            "delete" => {
                if let Some(argument) = node.child(HirField::Argument) {
                    if let Some(target) = member_assignment_target(argument) {
                        let member = match self.member_reference(target, state, call_depth) {
                            Ok(member) => member,
                            Err(value) => return value,
                        };
                        return match self.delete_member(member, state) {
                            NodeMutation::Applies => Value::Bool(true),
                            NodeMutation::Ignored if self.strict => Value::SynchronousThrow,
                            NodeMutation::Ignored => Value::Bool(false),
                            NodeMutation::Unknown => {
                                self.complete = false;
                                self.draft.set_partial();
                                Value::Unknown
                            }
                        };
                    } else if let Some(value) =
                        self.assign_target(argument, Value::Unknown, state, call_depth)
                    {
                        return value;
                    }
                }
                Value::Bool(true)
            }
            _ => Value::Unknown,
        }
    }

    pub(super) fn ternary(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
        if abrupt_value(&condition) {
            return condition;
        }
        let consequence = node.child(HirField::Consequence);
        let alternative = node.child(HirField::Alternative);
        match truthy(&condition) {
            Some(true) => {
                consequence.map_or(Value::Unknown, |value| self.eval(value, state, call_depth))
            }
            Some(false) => {
                alternative.map_or(Value::Unknown, |value| self.eval(value, state, call_depth))
            }
            None => {
                self.complete = false;
                let mut yes = state.clone();
                let mut no = state.clone();
                let saved_dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                let yes_value = consequence.map_or(Value::Unknown, |value| {
                    self.eval(value, &mut yes, call_depth)
                });
                self.execution_dominators = saved_dominators.clone();
                let no_value = alternative.map_or(Value::Unknown, |value| {
                    self.eval(value, &mut no, call_depth)
                });
                self.conditional_depth -= 1;
                self.execution_dominators = saved_dominators;
                *state = join_states(yes, no);
                join_values(yes_value, no_value)
            }
        }
    }
}
