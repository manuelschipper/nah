//! Guard regions shared by the execution walk and callable summaries.

use std::collections::HashSet;

use oxc_ast::ast::{
    Argument, BlockStatement, CallExpression, CatchClause, Expression, ForInStatement,
    ForOfStatement, ForStatement, FunctionBody, IfStatement, Statement, SwitchStatement,
    WhileStatement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

use super::bindings::Bindings;
use super::callback_dispatch::promise_known_unfulfilled;
use super::control::statement_stops_sequential_execution;
use super::expression_values::{literal_truth, unparen};
use super::{MAX_WALK_DEPTH, resolve};

/// Guard regions use the source spans and ordinals shared by the walk and summaries.
pub(super) fn js_guard_regions(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    throws_reject: bool,
    bindings: &Bindings,
) -> crate::guards::GuardRegions {
    use effinterp_proto::{ByteSpan, ConditionKind};
    fn span(value: &impl GetSpan) -> ByteSpan {
        ByteSpan {
            start: value.span().start,
            end: value.span().end,
        }
    }
    struct JsGuardRegionCollector<'s> {
        source: &'s str,
        bindings: &'s Bindings,
        throws_reject: bool,
        guards: crate::guards::GuardRegions,
        depth: usize,
        /// Functions invoked where they are written, whose bodies run at the call.
        immediate: HashSet<u32>,
        /// First handlers of `.then(...)`, which run once the promise fulfills,
        /// and candidate `http(s).get` response handlers and listeners.
        fulfillment: HashSet<u32>,
    }
    impl JsGuardRegionCollector<'_> {
        fn function_region(&mut self, origin: ByteSpan, body: ByteSpan) {
            if self.immediate.contains(&origin.start) {
                return;
            }
            // Like the right side of `&&`, a fulfillment handler runs only on
            // success; any other callback may or may not be dispatched.
            let (kind, positive) = if self.fulfillment.contains(&origin.start) {
                (ConditionKind::ShortCircuit, true)
            } else {
                (ConditionKind::Dispatch, false)
            };
            self.guards
                .add(self.source, origin, body, kind, 0, 2, positive);
        }
    }
    impl<'a> Visit<'a> for JsGuardRegionCollector<'_> {
        fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
            let callee = unparen(&it.callee);
            if matches!(
                callee,
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            ) {
                self.immediate.insert(callee.span().start);
            }
            if let Expression::StaticMemberExpression(member) = callee
                && member.property.name.as_str() == "then"
                && !promise_known_unfulfilled(&member.object, self.throws_reject)
                && let Some(handler) = it.arguments.first().and_then(Argument::as_expression)
            {
                self.fulfillment.insert(unparen(handler).span().start);
            }
            // Use the same module binding resolver as the effect walk, so
            // named imports, destructuring, aliases and computed members
            // receive the same callback condition.
            if let Some(target) = resolve::resolve_callee(callee, self.bindings)
                && ((target.module == "fs"
                    && target.function == "readFile"
                    && matches!(it.arguments.len(), 2 | 3))
                    || (matches!(target.module.as_str(), "http" | "https")
                        && target.function == "get"
                        && it.arguments.len() > 1))
                && let Some(handler) = it.arguments.last().and_then(Argument::as_expression)
            {
                self.fulfillment.insert(unparen(handler).span().start);
            }
            // The walk resolves message listeners; other callbacks keep
            // their dispatch condition.
            if let Expression::StaticMemberExpression(member) = callee {
                let handler = match member.property.name.as_str() {
                    "on" | "once"
                        if it.arguments.first().is_some_and(|event| {
                            matches!(event, Argument::StringLiteral(event)
                                if matches!(event.value.as_str(), "data" | "end"))
                        }) =>
                    {
                        it.arguments.get(1)
                    }
                    _ => None,
                };
                if let Some(handler) = handler.and_then(Argument::as_expression) {
                    self.fulfillment.insert(unparen(handler).span().start);
                }
            }
            walk::walk_call_expression(self, it);
        }
        fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
            self.guards.add(
                self.source,
                span(it),
                span(it.body.as_ref()),
                ConditionKind::UnresolvedExecution,
                0,
                2,
                false,
            );
            walk::walk_catch_clause(self, it);
        }
        fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
            for statement in &it.statements {
                if let Statement::IfStatement(branch) = statement {
                    let yes = statement_stops_sequential_execution(&branch.consequent);
                    let no = branch
                        .alternate
                        .as_ref()
                        .is_some_and(statement_stops_sequential_execution);
                    if yes != no {
                        self.guards.add(
                            self.source,
                            span(branch.as_ref()),
                            ByteSpan {
                                start: branch.span.end,
                                end: it.span.end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
            walk::walk_function_body(self, it);
        }
        fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
            for statement in &it.body {
                if let Statement::IfStatement(branch) = statement {
                    let yes = statement_stops_sequential_execution(&branch.consequent);
                    let no = branch
                        .alternate
                        .as_ref()
                        .is_some_and(statement_stops_sequential_execution);
                    if yes != no {
                        self.guards.add(
                            self.source,
                            span(branch.as_ref()),
                            ByteSpan {
                                start: branch.span.end,
                                end: it.span.end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
            walk::walk_block_statement(self, it);
        }
        fn visit_expression(&mut self, it: &Expression<'a>) {
            if self.depth >= MAX_WALK_DEPTH as usize {
                self.guards.widen();
                return;
            }
            self.depth += 1;
            match it {
                Expression::ArrowFunctionExpression(e) => {
                    self.function_region(span(e.as_ref()), span(e.body.as_ref()))
                }
                Expression::FunctionExpression(e) => {
                    if let Some(body) = &e.body {
                        self.function_region(span(e.as_ref()), span(body.as_ref()));
                    }
                }
                Expression::LogicalExpression(e) => self.guards.add(
                    self.source,
                    span(e.as_ref()),
                    span(&e.right),
                    ConditionKind::ShortCircuit,
                    u32::from(e.operator != oxc_ast::ast::LogicalOperator::And),
                    2,
                    true,
                ),
                Expression::ConditionalExpression(e) => {
                    self.guards.add(
                        self.source,
                        span(e.as_ref()),
                        span(&e.consequent),
                        ConditionKind::Branch,
                        0,
                        2,
                        true,
                    );
                    self.guards.add(
                        self.source,
                        span(e.as_ref()),
                        span(&e.alternate),
                        ConditionKind::Branch,
                        1,
                        2,
                        true,
                    );
                }
                _ => (),
            }
            walk::walk_expression(self, it);
            self.depth -= 1;
        }
        fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
            // A literal test always selects one arm, which then runs
            // unconditionally; the effect walk never enters the other.
            if literal_truth(&it.test).is_some() {
                walk::walk_if_statement(self, it);
                return;
            }
            self.guards.add(
                self.source,
                span(it),
                span(&it.consequent),
                ConditionKind::Branch,
                0,
                2,
                true,
            );
            if let Some(other) = &it.alternate {
                self.guards.add(
                    self.source,
                    span(it),
                    span(other),
                    ConditionKind::Branch,
                    1,
                    2,
                    true,
                );
            }
            walk::walk_if_statement(self, it);
        }
        fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
            self.guards.add(
                self.source,
                span(it),
                span(&it.body),
                ConditionKind::Loop,
                0,
                2,
                false,
            );
            walk::walk_while_statement(self, it);
        }
        fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
            self.guards.add(
                self.source,
                span(it),
                span(&it.body),
                ConditionKind::Loop,
                0,
                2,
                false,
            );
            walk::walk_for_statement(self, it);
        }
        fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
            for region in [span(&it.left), span(&it.body)] {
                self.guards.add(
                    self.source,
                    span(it),
                    region,
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                );
            }
            walk::walk_for_of_statement(self, it);
        }
        fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
            for region in [span(&it.left), span(&it.body)] {
                self.guards.add(
                    self.source,
                    span(it),
                    region,
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                );
            }
            walk::walk_for_in_statement(self, it);
        }
        fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
            for (arm, case) in it.cases.iter().enumerate() {
                if arm > 0
                    && !it.cases[arm - 1]
                        .consequent
                        .last()
                        .is_some_and(statement_stops_sequential_execution)
                {
                    self.guards.add_unknown(span(case));
                    continue;
                }

                self.guards.add(
                    self.source,
                    span(it),
                    span(case),
                    ConditionKind::Branch,
                    arm as u32,
                    it.cases.len() as u32
                        + u32::from(!it.cases.iter().any(|case| case.test.is_none())),
                    false,
                );
            }
            walk::walk_switch_statement(self, it);
        }
    }
    let mut collector = JsGuardRegionCollector {
        source,
        bindings,
        throws_reject,
        guards: Default::default(),
        depth: 0,
        immediate: HashSet::new(),
        fulfillment: HashSet::new(),
    };
    collector.visit_program(program);
    collector.guards
}
