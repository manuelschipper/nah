//! Optional chains that short-circuit at a proven null or undefined receiver.

use oxc_ast::ast::{CallExpression, ChainElement, Expression, MemberExpression};

use super::expression_values::unparen;
use super::source_string::is_global_undefined;
use super::walker::JsWalker;

impl<'a> JsWalker<'_, 'a> {
    pub(super) fn track_definitely_nullish(&mut self, name: &str, nullish: bool) {
        self.record_source_string_write_name(name);
        if nullish {
            self.definitely_nullish_env.insert(name.to_string());
        } else {
            self.definitely_nullish_env.remove(name);
        }
        self.sync_module_source_strings();
    }

    /// The walk can skip an optional link only when it proves the receiver
    /// is null or undefined.
    pub(super) fn expression_is_definitely_nullish(&self, expression: &Expression<'a>) -> bool {
        match unparen(expression) {
            Expression::NullLiteral(_) => true,
            Expression::Identifier(id) => {
                self.definitely_nullish_env.contains(id.name.as_str())
                    || is_global_undefined(expression, &self.source_env, &self.unbounded_source_env)
            }
            Expression::UnaryExpression(unary) => unary.operator.as_str() == "void",
            Expression::SequenceExpression(sequence) => sequence
                .expressions
                .last()
                .is_some_and(|expression| self.expression_is_definitely_nullish(expression)),
            Expression::AssignmentExpression(assignment) if assignment.operator.is_assign() => {
                self.expression_is_definitely_nullish(&assignment.right)
            }
            Expression::ConditionalExpression(conditional) => {
                self.expression_is_definitely_nullish(&conditional.consequent)
                    && self.expression_is_definitely_nullish(&conditional.alternate)
            }
            Expression::AwaitExpression(awaited) => {
                self.expression_is_definitely_nullish(&awaited.argument)
            }
            _ => false,
        }
    }

    /// Return the sub-expression that still evaluates when a proven
    /// nullish receiver short-circuits an optional chain. With `None`,
    /// the visitor walks the whole chain because no short circuit was proven.
    pub(super) fn short_circuited_chain_base<'b>(
        &self,
        element: &'b ChainElement<'a>,
    ) -> Option<&'b Expression<'a>> {
        match element {
            ChainElement::CallExpression(call) => self.short_circuited_call_base(call),
            ChainElement::TSNonNullExpression(inner) => {
                self.short_circuited_link_base(&inner.expression)
            }
            _ => self.short_circuited_member_base(element.as_member_expression()?),
        }
    }

    fn short_circuited_link_base<'b>(
        &self,
        expression: &'b Expression<'a>,
    ) -> Option<&'b Expression<'a>> {
        match unparen(expression) {
            Expression::CallExpression(call) => self.short_circuited_call_base(call),
            Expression::TSNonNullExpression(inner) => {
                self.short_circuited_link_base(&inner.expression)
            }
            link => self.short_circuited_member_base(link.as_member_expression()?),
        }
    }

    fn short_circuited_member_base<'b>(
        &self,
        member: &'b MemberExpression<'a>,
    ) -> Option<&'b Expression<'a>> {
        // An earlier link stops the chain before this key is evaluated.
        self.short_circuited_link_base(member.object()).or_else(|| {
            (member.optional() && self.expression_is_definitely_nullish(member.object()))
                .then_some(member.object())
        })
    }

    fn short_circuited_call_base<'b>(
        &self,
        call: &'b CallExpression<'a>,
    ) -> Option<&'b Expression<'a>> {
        // A skipped optional call evaluates neither its arguments nor a target.
        self.short_circuited_link_base(&call.callee).or_else(|| {
            (call.optional && self.expression_is_definitely_nullish(&call.callee))
                .then_some(&call.callee)
        })
    }
}
