//! Python expression walking.
//! Operands and deferred bodies are visited according to the execution rules of each expression.

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use rustpython_parser::ast;
use rustpython_parser::ast::Expr;
use rustpython_parser::ast::Ranged;

use crate::value::unresolved_resource;

use super::PythonWalker;
use super::ast_expressions::child_exprs;
use super::resolve::str_literal;

impl PythonWalker<'_, '_> {
    /// Enter arm `arm` of the conditional or short-circuit expression
    /// `origin`: what the arm evaluates runs only under that condition.
    pub(super) fn push_expression_condition(
        &mut self,
        origin: &Expr,
        kind: effinterp_proto::ConditionKind,
        arm: u32,
    ) {
        let condition = self.builder.source_condition_path(
            effinterp_proto::Condition::from_source_with_digest(
                self.source,
                self.condition_source.digest().to_string(),
                effinterp_proto::ByteSpan {
                    start: origin.range().start().into(),
                    end: origin.range().end().into(),
                },
                kind,
                arm,
                2,
                true,
                true,
            ),
        );
        self.builder.push_condition(condition);
    }

    /// Walk an expression with its short-circuit conditions and deferred execution rules.
    pub(super) fn walk_expr(&mut self, expr: &Expr) {
        // Keep guarded expression spines iterative as well as ordinary expressions.
        enum PythonExprWork<'a> {
            Expr(&'a Expr),
            AttributeBase(&'a Expr),
            Push(&'a Expr, effinterp_proto::ConditionKind, u32),
            Pop(usize),
        }
        let initial_depth = self.builder.condition_depth();
        let mut stack = vec![PythonExprWork::Expr(expr)];
        while let Some(work) = stack.pop() {
            let attribute_base = matches!(work, PythonExprWork::AttributeBase(_));
            let expr = match work {
                PythonExprWork::Expr(expr) | PythonExprWork::AttributeBase(expr) => expr,
                PythonExprWork::Push(origin, kind, arm) => {
                    self.push_expression_condition(origin, kind, arm);
                    continue;
                }
                PythonExprWork::Pop(count) => {
                    for _ in 0..count {
                        self.builder.pop_condition();
                    }
                    continue;
                }
            };
            if !self.charge(expr.range()) {
                break;
            }
            if !attribute_base {
                self.record_namespace_escape(expr);
            }
            if let Expr::IfExp(branch) = expr {
                for (arm, body) in [(1, branch.orelse.as_ref()), (0, branch.body.as_ref())] {
                    stack.push(PythonExprWork::Pop(1));
                    stack.push(PythonExprWork::Expr(body));
                    stack.push(PythonExprWork::Push(
                        expr,
                        effinterp_proto::ConditionKind::Branch,
                        arm,
                    ));
                }
                stack.push(PythonExprWork::Expr(&branch.test));
                continue;
            }
            if let Expr::BoolOp(branch) = expr {
                stack.push(PythonExprWork::Pop(branch.values.len().saturating_sub(1)));
                for (index, body) in branch.values.iter().enumerate().rev() {
                    stack.push(PythonExprWork::Expr(body));
                    if index > 0 {
                        stack.push(PythonExprWork::Push(
                            &branch.values[index - 1],
                            effinterp_proto::ConditionKind::ShortCircuit,
                            u32::from(matches!(branch.op, ast::BoolOp::Or)),
                        ));
                    }
                }
                continue;
            }
            if let Expr::Await(awaited) = expr {
                self.record_await_dispatch(awaited);
                self.walk_eager(&awaited.value, true);
                continue;
            }
            if let Expr::NamedExpr(named) = expr {
                self.walk_expr(&named.value);
                let Expr::Name(target) = named.target.as_ref() else {
                    continue;
                };
                let name = target.id.as_str();
                self.imports.shadow(name);
                let instance = match named.value.as_ref() {
                    Expr::Name(source) => self.instance_vars.get(source.id.as_str()).cloned(),
                    _ => None,
                };
                self.clear_bound_receiver(name);
                let was_path = self.path_vars.contains(name);
                let branch_mixed_path = self.is_branch_mixed_path_value(&named.value);
                match self.tracked_assignment_resource(&named.value) {
                    Some(resource) => {
                        self.var_scope.insert(name.to_string(), resource);
                        self.widened_vars.remove(name);
                        if self.is_path_value(&named.value) {
                            self.path_vars.insert(name.to_string());
                        } else {
                            self.path_vars.remove(name);
                        }
                        if self.is_path_value(&named.value) && branch_mixed_path {
                            self.branch_mixed_path_vars.insert(name.to_string());
                        } else {
                            self.branch_mixed_path_vars.remove(name);
                        }
                    }
                    None if was_path || self.may_be_path_value(&named.value) => {
                        self.invalidate_rebound_name(name);
                    }
                    None => {
                        self.var_scope.remove(name);
                        self.path_vars.remove(name);
                        self.branch_mixed_path_vars.remove(name);
                    }
                }
                self.concatenated_vars.remove(name);
                self.unbounded_string_vars.remove(name);
                if let Some(instance) = instance {
                    self.instance_vars.insert(name.to_string(), instance);
                }
                continue;
            }
            let walked_comprehension = match expr {
                Expr::ListComp(comprehension) => {
                    self.walk_comprehension(&comprehension.elt, None, &comprehension.generators)
                }
                Expr::SetComp(comprehension) => {
                    self.walk_comprehension(&comprehension.elt, None, &comprehension.generators)
                }
                Expr::GeneratorExp(comprehension) if self.execute_deferred => {
                    self.walk_comprehension(&comprehension.elt, None, &comprehension.generators)
                }
                Expr::GeneratorExp(comprehension) => {
                    if let Some(generator) = comprehension.generators.first() {
                        self.walk_expr(&generator.iter);
                    }
                    true
                }
                Expr::DictComp(comprehension) => self.walk_comprehension(
                    &comprehension.key,
                    Some(&comprehension.value),
                    &comprehension.generators,
                ),
                _ => false,
            };
            if walked_comprehension {
                continue;
            }
            if let Expr::Call(call) = expr {
                if let Expr::Attribute(attribute) = call.func.as_ref()
                    && attribute.attr.as_str() == "__await__"
                {
                    self.call(call);
                    self.walk_deferred(&attribute.value);
                    for argument in &call.args {
                        self.walk_expr(argument);
                    }
                    for keyword in &call.keywords {
                        self.walk_expr(&keyword.value);
                    }
                    continue;
                }
                if self.deferred_consumer(call) {
                    self.call(call);
                    self.walk_expr(&call.func);
                    self.walk_consumed_arguments(call);
                    continue;
                }
                if self.capture.is_some()
                    && let Some(emitted) = self.stdout_values(call)
                {
                    self.capture_print(call, emitted);
                    continue;
                }
                let before = self.capture.as_ref().map(|capture| capture.effects.len());
                self.call(call);
                if let Some(before) = before {
                    self.capture_consumed(call, before);
                }
            }
            // `os.environ["X"]` in expression position is an environment read
            // (writes are handled on assignment targets, which are not walked as
            // expressions).
            if let Expr::Subscript(sub) = expr
                && self.imports.resolve_callee(&sub.value).as_deref() == Some("os.environ")
            {
                let resource = str_literal(&sub.slice)
                    .filter(|name| !name.is_empty())
                    .map(|name| ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name },
                    })
                    .unwrap_or_else(|| unresolved_resource("environment"));
                let node = self.span_node(sub.range);
                self.emit("environment.read", resource, &[], node);
            }
            for child in child_exprs(expr).into_iter().rev() {
                // Reading a module attribute does not itself escape its owner.
                stack.push(if matches!(expr, Expr::Attribute(_)) {
                    PythonExprWork::AttributeBase(child)
                } else {
                    PythonExprWork::Expr(child)
                });
            }
        }
        while self.builder.condition_depth() > initial_depth {
            self.builder.pop_condition();
        }
    }
}
