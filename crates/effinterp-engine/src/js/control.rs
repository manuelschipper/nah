//! A JavaScript callable's effect-directed control flow.
//!
//! Calls, constructions, tagged templates, decorator applications, and module
//! loads are the sites that may run code. Exceptional continuations enter
//! handlers separately from normal paths.
//! Nested function bodies are not executed where they are defined.

use std::collections::HashSet;

use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::ScopeFlags;
use oxc_span::{GetSpan, Span};

use crate::control_flow::{Catch, ControlExit, Frontier, Graph, Jump};

pub(super) fn span(span: Span) -> crate::control_flow::Span {
    (span.start, span.end)
}

/// The span where a decorator's application, not its expression, registers.
pub(super) fn decorator_span(decorator: &Decorator<'_>) -> crate::control_flow::Span {
    (decorator.span.end, decorator.span.end)
}

/// A module's graph: static imports and re-exports load before any statement.
pub(super) fn build_program(
    graph: &mut Graph,
    program: &Program<'_>,
    readonly_writes: &Option<HashSet<u32>>,
) {
    let mut builder = Builder::new(graph, readonly_writes);
    for statement in &program.body {
        if let Some(loaded) = module_load_span(statement) {
            builder.at = builder.graph.site(builder.at, span(loaded), true);
        }
    }
    for statement in &program.body {
        builder.visit_statement(statement);
    }
    builder.finish();
}

/// A function body's graph; parameter defaults may or may not be evaluated.
pub(super) fn build_function(
    graph: &mut Graph,
    params: &FormalParameters<'_>,
    body: &FunctionBody<'_>,
    readonly_writes: &Option<HashSet<u32>>,
) {
    let mut builder = Builder::new(graph, readonly_writes);
    for parameter in &params.items {
        if let Some(initializer) = &parameter.initializer {
            builder.optional(|builder| builder.visit_expression(initializer));
        }
        builder.visit_binding_pattern(&parameter.pattern);
    }
    for statement in &body.statements {
        builder.visit_statement(statement);
    }
    builder.finish();
}

/// The span of a statement that loads another module before the program runs.
pub(super) fn module_load_span(statement: &Statement<'_>) -> Option<Span> {
    match statement {
        Statement::ImportDeclaration(import) => Some(import.span),
        Statement::ExportAllDeclaration(export) => Some(export.span),
        Statement::ExportNamedDeclaration(export) if export.source.is_some() => Some(export.span),
        _ => None,
    }
}

struct Builder<'g> {
    graph: &'g mut Graph,
    readonly_writes: &'g Option<HashSet<u32>>,
    at: Frontier,
    callee: Option<Span>,
    /// A label waiting for the loop or block it names.
    label: Option<String>,
}

fn always_true(test: &Expression<'_>) -> bool {
    match test.get_inner_expression() {
        Expression::BooleanLiteral(literal) => literal.value,
        Expression::NumericLiteral(literal) => literal.value != 0.0,
        _ => false,
    }
}

fn non_empty_array(expression: &Expression<'_>) -> bool {
    matches!(expression.get_inner_expression(), Expression::ArrayExpression(array)
        if !array.elements.is_empty()
            && array.elements.iter().all(|element| element.is_expression()))
}

impl<'g> Builder<'g> {
    fn new(graph: &'g mut Graph, readonly_writes: &'g Option<HashSet<u32>>) -> Self {
        graph.enable_exceptions();
        if readonly_writes.is_none() {
            graph.widen();
        }
        let at = graph.entry();
        Self {
            graph,
            readonly_writes,
            at,
            callee: None,
            label: None,
        }
    }

    fn finish(self) {
        self.graph.exit(self.at, ControlExit::Success);
    }

    /// Run a construct that may be skipped: its end joins the path around it.
    fn optional(&mut self, run: impl FnOnce(&mut Self)) {
        let start = self.at;
        run(self);
        self.at = self.graph.join(&[start, self.at]);
    }

    fn site(&mut self, at: Span) {
        self.at = self.graph.site(self.at, span(at), true);
    }

    fn join_with(&mut self, others: Vec<u32>) {
        let mut frontiers = vec![self.at];
        frontiers.extend(others.into_iter().map(Some));
        self.at = self.graph.join(&frontiers);
    }

    /// A loop over `body`, entered from a fresh header. `test` runs before
    /// each iteration, `update` after each completed one.
    fn repeat(
        &mut self,
        test: Option<&Expression<'_>>,
        body: &Statement<'_>,
        update: Option<&Expression<'_>>,
        at_least_once: bool,
        binding: Option<&ForStatementLeft<'_>>,
    ) {
        let label = self.label.take();
        let header = self.graph.header(self.at);
        self.at = header;
        if let Some(test) = test {
            self.visit_expression(test);
        }
        let tested = self.at;
        self.graph.push_loop(label, true);
        if let Some(binding) = binding {
            self.visit_for_statement_left(binding);
        }
        self.visit_statement(body);
        let (breaks, continues) = self.graph.pop_loop();
        self.join_with(continues);
        if let Some(update) = update {
            self.visit_expression(update);
        }
        let back = self.at;
        self.graph.backedge(back, header);
        let exhausted = match test {
            Some(test) if always_true(test) => None,
            Some(_) => tested,
            None if at_least_once => back,
            None => header,
        };
        self.at = exhausted;
        self.join_with(breaks);
    }
}

impl<'a> Visit<'a> for Builder<'_> {
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.at.is_none() || module_load_span(it).is_some() {
            return;
        }
        if !self.graph.enter() {
            self.at = None;
            return;
        }
        walk::walk_statement(self, it);
        self.graph.leave();
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.at.is_none() {
            return;
        }
        if !self.graph.enter() {
            self.at = None;
            return;
        }
        walk::walk_expression(self, it);
        self.graph.leave();
    }

    fn visit_function(&mut self, _it: &Function<'a>, _flags: ScopeFlags) {}

    fn visit_arrow_function_expression(&mut self, _it: &ArrowFunctionExpression<'a>) {}

    fn visit_class(&mut self, it: &Class<'a>) {
        for decorator in &it.decorators {
            self.visit_expression(&decorator.expression);
        }
        if let Some(super_class) = &it.super_class {
            self.visit_expression(super_class);
        }
        for element in &it.body.body {
            let (computed_key, runs_now) = match element {
                ClassElement::StaticBlock(_) => (None, true),
                ClassElement::MethodDefinition(method) => {
                    (method.computed.then_some(&method.key), false)
                }
                ClassElement::PropertyDefinition(property) => (
                    property.computed.then_some(&property.key),
                    property.r#static && property.value.is_some(),
                ),
                ClassElement::AccessorProperty(property) => (
                    property.computed.then_some(&property.key),
                    property.r#static && property.value.is_some(),
                ),
                ClassElement::TSIndexSignature(_) => (None, false),
            };
            if let Some(key) = computed_key {
                self.visit_property_key(key);
            }
            let decorated = match element {
                ClassElement::MethodDefinition(method) => !method.decorators.is_empty(),
                ClassElement::PropertyDefinition(property) => !property.decorators.is_empty(),
                ClassElement::AccessorProperty(property) => !property.decorators.is_empty(),
                _ => false,
            };
            if runs_now || decorated {
                // Static initializers and member decorators run unmodeled
                // code at definition.
                self.graph.unknown(self.at);
            }
        }
        for decorator in it.decorators.iter().rev() {
            self.at = self.graph.site(self.at, decorator_span(decorator), true);
        }
    }

    fn visit_ts_module_declaration(&mut self, _it: &TSModuleDeclaration<'a>) {
        self.graph.unknown(self.at);
    }

    fn visit_ts_import_equals_declaration(&mut self, it: &TSImportEqualsDeclaration<'a>) {
        if matches!(
            it.module_reference,
            TSModuleReference::ExternalModuleReference(_)
        ) {
            self.site(it.span);
        }
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let callee = self.callee.replace(it.callee.span());
        self.visit_expression(&it.callee);
        self.callee = callee;
        self.at = self.graph.lookup(self.at, span(it.span));
        for argument in &it.arguments {
            self.visit_argument(argument);
        }
        self.site(it.span);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        walk::walk_new_expression(self, it);
        self.site(it.span);
    }

    fn visit_tagged_template_expression(&mut self, it: &TaggedTemplateExpression<'a>) {
        walk::walk_tagged_template_expression(self, it);
        self.site(it.span);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        walk::walk_import_expression(self, it);
        self.site(it.span);
    }

    fn visit_v8_intrinsic_expression(&mut self, it: &V8IntrinsicExpression<'a>) {
        walk::walk_v8_intrinsic_expression(self, it);
        self.site(it.span);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        walk::walk_binary_expression(self, it);
        if matches!(it.operator.as_str(), "/" | "%")
            && matches!(it.left.get_inner_expression(), Expression::BigIntLiteral(_))
            && matches!(it.right.get_inner_expression(), Expression::BigIntLiteral(value) if value.value == "0")
        {
            self.at = self.graph.throw_now(self.at);
        } else if matches!(it.operator.as_str(), "in" | "instanceof")
            || !matches!(
                it.left.get_inner_expression(),
                Expression::NumericLiteral(_)
            )
            || !matches!(
                it.right.get_inner_expression(),
                Expression::NumericLiteral(_)
            )
        {
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        walk::walk_static_member_expression(self, it);
        if matches!(it.object.get_inner_expression(), Expression::NullLiteral(_)) {
            self.at = self.graph.throw_now(self.at);
        } else if self.callee != Some(it.span) {
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        walk::walk_computed_member_expression(self, it);
        if matches!(it.object.get_inner_expression(), Expression::NullLiteral(_)) {
            self.at = self.graph.throw_now(self.at);
        } else if self.callee != Some(it.span) {
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.visit_expression(&it.left);
        self.optional(|builder| builder.visit_expression(&it.right));
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        self.visit_expression(&it.argument);
        if !matches!(it.operator.as_str(), "!" | "void" | "typeof")
            && !matches!(
                it.argument.get_inner_expression(),
                Expression::NumericLiteral(_)
            )
        {
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        walk::walk_update_expression(self, it);
        if matches!(&it.argument, SimpleAssignmentTarget::AssignmentTargetIdentifier(id) if self.readonly_writes.as_ref().is_some_and(|writes| writes.contains(&id.span.start)))
        {
            self.at = self.graph.throw_now(self.at);
        } else {
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_spread_element(&mut self, it: &SpreadElement<'a>) {
        self.visit_expression(&it.argument);
        self.at = self.graph.may_throw(self.at);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        for expression in &it.expressions {
            self.visit_expression(expression);
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        self.visit_expression(&it.argument);
        self.at = self.graph.may_throw(self.at);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init {
            self.visit_expression(init);
        }
        self.visit_binding_pattern(&it.id);
    }

    fn visit_binding_pattern(&mut self, it: &BindingPattern<'a>) {
        if matches!(
            it,
            BindingPattern::ArrayPattern(_) | BindingPattern::ObjectPattern(_)
        ) {
            self.at = self.graph.may_throw(self.at);
        }
        walk::walk_binding_pattern(self, it);
    }

    fn visit_assignment_pattern(&mut self, it: &AssignmentPattern<'a>) {
        self.optional(|builder| builder.visit_expression(&it.right));
        self.visit_binding_pattern(&it.left);
    }

    fn visit_assignment_target_with_default(&mut self, it: &AssignmentTargetWithDefault<'a>) {
        self.optional(|builder| builder.visit_expression(&it.init));
        self.visit_assignment_target(&it.binding);
    }

    fn visit_assignment_target_property_identifier(
        &mut self,
        it: &AssignmentTargetPropertyIdentifier<'a>,
    ) {
        if let Some(init) = &it.init {
            self.optional(|builder| builder.visit_expression(init));
        }
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if matches!(it, AssignmentTarget::AssignmentTargetIdentifier(id) if self.readonly_writes.as_ref().is_some_and(|writes| writes.contains(&id.span.start)))
        {
            self.at = self.graph.throw_now(self.at);
            return;
        }
        if matches!(
            it,
            AssignmentTarget::AssignmentTargetIdentifier(_)
                | AssignmentTarget::ArrayAssignmentTarget(_)
                | AssignmentTarget::ObjectAssignmentTarget(_)
        ) {
            self.at = self.graph.may_throw(self.at);
        }
        walk::walk_assignment_target(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.visit_expression(&it.test);
        let test = self.at;
        self.visit_expression(&it.consequent);
        let yes = self.at;
        self.at = test;
        self.visit_expression(&it.alternate);
        self.at = self.graph.join(&[yes, self.at]);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if matches!(it.left, AssignmentTarget::AssignmentTargetIdentifier(_)) {
            if it.operator.as_str() != "=" {
                self.at = self.graph.may_throw(self.at);
            }
            if it.operator.is_logical() {
                self.optional(|builder| {
                    builder.visit_expression(&it.right);
                    builder.visit_assignment_target(&it.left);
                });
            } else {
                self.visit_expression(&it.right);
                self.visit_assignment_target(&it.left);
            }
            return;
        }
        if matches!(
            &it.left,
            AssignmentTarget::ArrayAssignmentTarget(_)
                | AssignmentTarget::ObjectAssignmentTarget(_)
        ) {
            self.visit_expression(&it.right);
            self.visit_assignment_target(&it.left);
            return;
        }
        self.visit_assignment_target(&it.left);
        if it.operator.is_logical() {
            self.optional(|builder| builder.visit_expression(&it.right));
        } else {
            self.visit_expression(&it.right);
        }
        if it.operator.as_str() != "=" {
            self.at = self.graph.may_throw(self.at);
        }
    }

    fn visit_chain_expression(&mut self, it: &ChainExpression<'a>) {
        // Any optional link may short-circuit the rest of the chain.
        self.optional(|builder| walk::walk_chain_expression(builder, it));
    }

    fn visit_yield_expression(&mut self, it: &YieldExpression<'a>) {
        walk::walk_yield_expression(self, it);
        // The consumer may stop iterating here.
        self.graph.bypass(self.at);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.visit_expression(&it.test);
        let test = self.at;
        self.visit_statement(&it.consequent);
        let yes = self.at;
        self.at = test;
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
        self.at = self.graph.join(&[yes, self.at]);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.repeat(Some(&it.test), &it.body, None, false, None);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        let label = self.label.take();
        let header = self.graph.header(self.at);
        self.at = header;
        self.graph.push_loop(label, true);
        self.visit_statement(&it.body);
        let (breaks, continues) = self.graph.pop_loop();
        self.join_with(continues);
        self.visit_expression(&it.test);
        let tested = self.at;
        self.graph.backedge(tested, header);
        self.at = if always_true(&it.test) { None } else { tested };
        self.join_with(breaks);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            let label = self.label.take();
            self.visit_for_statement_init(init);
            self.label = label;
        }
        self.repeat(it.test.as_ref(), &it.body, it.update.as_ref(), false, None);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.visit_expression(&it.right);
        self.at = self.graph.may_throw(self.at);
        self.repeat(None, &it.body, None, false, Some(&it.left));
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.visit_expression(&it.right);
        if !matches!(
            it.right.get_inner_expression(),
            Expression::ArrayExpression(_) | Expression::StringLiteral(_)
        ) {
            self.at = self.graph.may_throw(self.at);
        }
        if it.r#await {
            // Each step awaits the iterator's own code.
            self.graph.unknown(self.at);
        }
        self.repeat(
            None,
            &it.body,
            None,
            non_empty_array(&it.right),
            Some(&it.left),
        );
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        let name = it.label.name.to_string();
        match &it.body {
            Statement::WhileStatement(_)
            | Statement::DoWhileStatement(_)
            | Statement::ForStatement(_)
            | Statement::ForInStatement(_)
            | Statement::ForOfStatement(_) => {
                self.label = Some(name);
                self.visit_statement(&it.body);
                self.label = None;
            }
            body => {
                self.graph.push_block(name);
                self.visit_statement(body);
                let (breaks, _) = self.graph.pop_loop();
                self.join_with(breaks);
            }
        }
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        let label = self.label.take();
        self.visit_expression(&it.discriminant);
        let discriminant = self.at;
        self.graph.push_loop(label, false);
        let mut chain = discriminant;
        let mut previous = None;
        let mut default = false;
        for case in &it.cases {
            let entry = match &case.test {
                Some(test) => {
                    self.at = chain;
                    self.visit_expression(test);
                    chain = self.at;
                    chain
                }
                None => {
                    default = true;
                    discriminant
                }
            };
            self.at = self.graph.join(&[entry, previous]);
            for statement in &case.consequent {
                self.visit_statement(statement);
            }
            previous = self.at;
        }
        let (breaks, _) = self.graph.pop_loop();
        self.at = self
            .graph
            .join(&[previous, if default { None } else { chain }]);
        self.join_with(breaks);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        let cleanup = it.finalizer.is_some();
        if cleanup {
            self.graph.push_cleanup();
        }
        if it.handler.is_some() {
            self.graph.push_catch();
        }
        self.visit_block_statement(&it.block);
        let mut ends = vec![self.at];
        if let Some(handler) = &it.handler {
            let thrown = self.graph.pop_catch();
            self.graph.rethrow(&thrown);
            self.at = self.graph.catch_handler(&thrown, Catch::Any);
            self.visit_block_statement(&handler.body);
            ends.push(self.at);
        }
        let normal = self.graph.join(&ends);
        let Some(finalizer) = &it.finalizer else {
            self.at = normal;
            return;
        };
        let (abrupt, pending): (Vec<_>, Vec<_>) = self
            .graph
            .pop_cleanup()
            .into_iter()
            .partition(|(_, jump)| *jump == Jump::Throw);
        self.at = normal;
        self.join_with(pending.iter().map(|(from, _)| *from).collect());
        self.visit_block_statement(finalizer);
        let end = self.at;
        self.graph.resume(end, pending);
        self.at = self.graph.join(
            &abrupt
                .iter()
                .map(|(from, _)| Some(*from))
                .collect::<Vec<_>>(),
        );
        self.visit_block_statement(finalizer);
        self.graph.resume(self.at, abrupt);
        self.at = normal.and(end);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        self.visit_expression(&it.argument);
        self.graph.jump(self.at, Jump::Throw);
        self.at = None;
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(argument) = &it.argument {
            self.visit_expression(argument);
        }
        self.graph.jump(self.at, Jump::Return);
        self.at = None;
    }

    fn visit_break_statement(&mut self, it: &BreakStatement<'a>) {
        let label = it.label.as_ref().map(|label| label.name.to_string());
        self.graph.jump(self.at, Jump::Break(label));
        self.at = None;
    }

    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        let label = it.label.as_ref().map(|label| label.name.to_string());
        self.graph.jump(self.at, Jump::Continue(label));
        self.at = None;
    }
}
