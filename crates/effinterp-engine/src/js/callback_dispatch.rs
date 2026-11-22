//! Callback dispatch and the file, response or promise values available when handlers run.

use oxc_ast::ast::{
    Argument, AssignmentTarget, BindingPattern, CallExpression, Expression, MemberExpression,
    MethodDefinition, ObjectProperty, PropertyDefinition, PropertyKey, SimpleAssignmentTarget,
    Statement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::{GetSpan, Span};

use super::MAX_WALK_DEPTH;
use super::bindings::{collect_binding_names, function_local_binding_names};
use super::callable_bindings::resolve_callable;
use super::expression_values::unparen;
use super::flow_tracking::ResponseKind;
use super::walker::JsWalker;

/// A callback through which file or response bytes become available.
enum MessageHandler {
    /// The handler passed to `get`, whose first parameter is the message.
    Response,
    /// The callback runs after the read; its second parameter holds the file
    /// bytes when the read succeeded.
    File,
    /// A `data` listener, whose first parameter is a chunk of the body.
    Chunk,
    /// An `end` listener, which runs after every chunk arrived, so it reads
    /// whatever the `data` listeners accumulated.
    End,
}

/// The body and selected parameter of an inline callback with a plain name.
fn inline_callback_parameter<'e>(expr: &'e Expression<'_>, index: usize) -> Option<(u32, &'e str)> {
    let (params, body) = match unparen(expr) {
        Expression::ArrowFunctionExpression(function) => (&function.params, &function.body),
        Expression::FunctionExpression(function) => (&function.params, function.body.as_ref()?),
        _ => return None,
    };
    let BindingPattern::BindingIdentifier(id) = &params.items.get(index)?.pattern else {
        return None;
    };
    Some((body.span.start, id.name.as_str()))
}

/// The body span start of an inline callback.
fn callback_body_start(expr: &Expression<'_>) -> Option<u32> {
    match unparen(expr) {
        Expression::ArrowFunctionExpression(function) => Some(function.body.span.start),
        Expression::FunctionExpression(function) => Some(function.body.as_ref()?.span.start),
        _ => None,
    }
}

/// The names a `data` listener appends each chunk to, as `d += c`,
/// `d = d + c` or `chunks.push(c)` (`c` or `c.toString()`), which an `end`
/// listener then reads. A name the listener declares itself is its own.
fn chunk_accumulators(expr: &Expression<'_>) -> Vec<String> {
    let (params, body) = match unparen(expr) {
        Expression::ArrowFunctionExpression(function) => (&function.params, &*function.body),
        Expression::FunctionExpression(function) => match &function.body {
            Some(body) => (&function.params, &**body),
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let Some((_, chunk)) = inline_callback_parameter(expr, 0) else {
        return Vec::new();
    };
    let mut local = function_local_binding_names(body);
    for parameter in &params.items {
        collect_binding_names(&parameter.pattern, &mut local);
    }
    let is_chunk = |value: &Expression<'_>| match unparen(value) {
        Expression::Identifier(id) => id.name.as_str() == chunk,
        Expression::CallExpression(call) => matches!(
            unparen(&call.callee),
            Expression::StaticMemberExpression(member)
                if member.property.name.as_str() == "toString"
                    && matches!(unparen(&member.object), Expression::Identifier(id) if id.name.as_str() == chunk)
        ),
        _ => false,
    };
    let mut names = Vec::new();
    for statement in &body.statements {
        let Statement::ExpressionStatement(statement) = statement else {
            continue;
        };
        let name = match unparen(&statement.expression) {
            Expression::AssignmentExpression(assignment) => {
                let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left else {
                    continue;
                };
                let name = target.name.as_str();
                let appends = match assignment.operator {
                    oxc_ast::ast::AssignmentOperator::Addition => is_chunk(&assignment.right),
                    oxc_ast::ast::AssignmentOperator::Assign => matches!(
                        unparen(&assignment.right),
                        Expression::BinaryExpression(sum)
                            if sum.operator == oxc_ast::ast::BinaryOperator::Addition
                                && matches!(unparen(&sum.left), Expression::Identifier(id) if id.name.as_str() == name)
                                && is_chunk(&sum.right)
                    ),
                    _ => false,
                };
                if !appends {
                    continue;
                }
                name
            }
            Expression::CallExpression(call) => {
                let Expression::StaticMemberExpression(member) = unparen(&call.callee) else {
                    continue;
                };
                let Expression::Identifier(target) = unparen(&member.object) else {
                    continue;
                };
                if member.property.name.as_str() != "push"
                    || !call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .is_some_and(is_chunk)
                {
                    continue;
                }
                target.name.as_str()
            }
            _ => continue,
        };
        if !local.contains(name) && !names.iter().any(|known| known == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// Whether a promise is known never to fulfill: a chain in which some
/// `.then` or `.finally` handler always throws and no later link recovers.
/// Nothing about a promise's origin is taken as proof, because any promise
/// exposes the runtime `Promise` through `.constructor`. `throws_reject`
/// is false when the program may replace how a handler's throw settles the
/// chain, and then nothing is proven.
pub(super) fn promise_known_unfulfilled(receiver: &Expression<'_>, throws_reject: bool) -> bool {
    if !throws_reject {
        return false;
    }
    let mut links = Vec::new();
    let mut root = receiver;
    while let Expression::CallExpression(call) = unparen(root)
        && let Expression::StaticMemberExpression(member) = unparen(&call.callee)
        && matches!(member.property.name.as_str(), "then" | "catch" | "finally")
    {
        links.push((member.property.name.as_str(), call));
        root = &member.object;
    }
    let mut unfulfilled = false;
    for (method, call) in links.into_iter().rev() {
        let throws = |index: usize| {
            call.arguments
                .get(index)
                .and_then(Argument::as_expression)
                .is_some_and(handler_always_throws)
        };
        let present = |index: usize| call.arguments.get(index).is_some();
        unfulfilled = match method {
            // A rejection handler that may complete normally recovers the chain.
            "then" if unfulfilled => !present(1) || throws(1),
            "then" => throws(0),
            "catch" => unfulfilled && (!present(0) || throws(0)),
            _ => unfulfilled || throws(0),
        };
    }
    unfulfilled
}

/// Whether an inline handler's block body starts with a top-level `throw`,
/// so it throws before anything else can complete.
fn handler_always_throws(handler: &Expression<'_>) -> bool {
    let body = match unparen(handler) {
        Expression::ArrowFunctionExpression(function) if !function.expression => &*function.body,
        Expression::FunctionExpression(function) => match &function.body {
            Some(body) => &**body,
            None => return false,
        },
        _ => return false,
    };
    matches!(body.statements.first(), Some(Statement::ThrowStatement(_)))
}

/// Whether the program can be trusted not to replace how a promise handler's
/// `throw` settles its chain, such as through a replaced `then`. Any of these
/// lexical tripwires declines: the words `prototype`, `constructor`,
/// `__proto__`, `setPrototypeOf`, `defineProperty`, `defineProperties`,
/// `__defineGetter__`, `__defineSetter__` or `Reflect` anywhere in the
/// source; `then` assigned as a member or used as a property key; or a
/// computed member write whose key is not a literal.
pub(super) fn throws_reject(program: &oxc_ast::ast::Program<'_>, source: &str) -> bool {
    const WORDS: [&str; 9] = [
        "prototype",
        "constructor",
        "__proto__",
        "setPrototypeOf",
        "defineProperty",
        "defineProperties",
        "__defineGetter__",
        "__defineSetter__",
        "Reflect",
    ];
    let identifier = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let has_word = |word: &str| {
        source.match_indices(word).any(|(at, _)| {
            !source[..at].ends_with(identifier)
                && !source[at + word.len()..].starts_with(identifier)
        })
    };
    if WORDS.iter().any(|word| has_word(word)) {
        return false;
    }
    #[derive(Default)]
    struct Tripwires {
        found: bool,
        depth: u32,
    }
    impl Tripwires {
        fn key_is_then(key: &PropertyKey<'_>) -> bool {
            key.static_name().is_some_and(|name| name == "then")
        }
    }
    impl<'a> Visit<'a> for Tripwires {
        fn visit_statement(&mut self, it: &Statement<'a>) {
            // Past the depth limit the program is not known to be free of them.
            if self.depth >= MAX_WALK_DEPTH {
                self.found = true;
                return;
            }
            self.depth += 1;
            walk::walk_statement(self, it);
            self.depth -= 1;
        }
        fn visit_expression(&mut self, it: &Expression<'a>) {
            if self.depth >= MAX_WALK_DEPTH {
                self.found = true;
                return;
            }
            self.depth += 1;
            walk::walk_expression(self, it);
            self.depth -= 1;
        }
        fn visit_simple_assignment_target(&mut self, it: &SimpleAssignmentTarget<'a>) {
            match it.as_member_expression() {
                Some(MemberExpression::StaticMemberExpression(member)) => {
                    self.found |= member.property.name.as_str() == "then";
                }
                Some(MemberExpression::ComputedMemberExpression(member)) => {
                    self.found |= match &member.expression {
                        Expression::StringLiteral(key) => key.value == "then",
                        Expression::NumericLiteral(_) => false,
                        _ => true,
                    };
                }
                _ => {}
            }
            walk::walk_simple_assignment_target(self, it);
        }
        fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
            self.found |= Self::key_is_then(&it.key);
            walk::walk_object_property(self, it);
        }
        fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
            self.found |= Self::key_is_then(&it.key);
            walk::walk_method_definition(self, it);
        }
        fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
            self.found |= Self::key_is_then(&it.key);
            walk::walk_property_definition(self, it);
        }
    }
    let mut tripwires = Tripwires::default();
    tripwires.visit_program(program);
    !tripwires.found
}

fn callback_needs_resolution(expr: &Expression<'_>) -> bool {
    match unparen(expr) {
        Expression::Identifier(id) => id.name.as_str() != "undefined",
        Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_)
        | Expression::CallExpression(_)
        | Expression::ChainExpression(_)
        | Expression::ConditionalExpression(_)
        | Expression::LogicalExpression(_)
        | Expression::SequenceExpression(_)
        | Expression::AssignmentExpression(_)
        | Expression::TaggedTemplateExpression(_) => true,
        Expression::AwaitExpression(awaited) => callback_needs_resolution(&awaited.argument),
        _ => false,
    }
}

impl<'a> JsWalker<'_, 'a> {
    /// Follow callback arguments under dispatch or fulfillment conditions and seed any proven input bytes.
    pub(super) fn follow_call_callbacks(
        &mut self,
        call: &CallExpression<'a>,
        original_callee: &Expression<'a>,
        quiet_promise: bool,
    ) -> usize {
        // Callbacks passed as arguments may be invoked: follow conservatively.
        let mut callbacks = 0;
        // A fulfillment handler receives the value its promise settles with.
        let then_receiver = match original_callee {
            Expression::StaticMemberExpression(member)
                if quiet_promise && member.property.name.as_str() == "then" =>
            {
                Some(&member.object)
            }
            _ => None,
        };
        let settled = then_receiver.and_then(|receiver| self.init_producer(receiver));
        let response = then_receiver.and_then(|receiver| self.response_kind(receiver));
        let message = self.message_handler(original_callee, call);
        for (index, arg) in call.arguments.iter().enumerate() {
            if let Some(expr) = arg.as_expression() {
                let handler = message
                    .as_ref()
                    .filter(|(handler_index, _, _)| *handler_index == index);
                let (settled, response) = match handler {
                    Some((_, stage, MessageHandler::Response)) => {
                        (Some(*stage), Some(ResponseKind::Message))
                    }
                    Some((_, stage, MessageHandler::Chunk | MessageHandler::File)) => {
                        (Some(*stage), None)
                    }
                    Some((_, _, MessageHandler::End)) => (None, None),
                    None => (settled.filter(|_| index == 0), response),
                };
                // A fulfillment handler runs, like the right side of `&&`,
                // once an established promise fulfills, and a response
                // handler once its request succeeds; other callbacks may or
                // may not be dispatched.
                let (kind, polarity) = if handler.is_some()
                    || index == 0
                        && then_receiver.is_some_and(|receiver| {
                            !promise_known_unfulfilled(receiver, self.bindings.throws_reject)
                        }) {
                    (effinterp_proto::ConditionKind::ShortCircuit, Some(true))
                } else {
                    (effinterp_proto::ConditionKind::Dispatch, None)
                };
                if let Some(stage) = settled
                    && !matches!(handler, Some((_, _, MessageHandler::File)))
                    && response.is_none()
                    && self.promise_handler_code_execution(expr, call.span, stage, kind, polarity)
                {
                    continue;
                }
                self.callback_seed = settled.and_then(|stage| {
                    let parameter =
                        usize::from(matches!(handler, Some((_, _, MessageHandler::File))));
                    let (body, param) = inline_callback_parameter(expr, parameter)?;
                    Some((body, param.to_string(), stage, response))
                });
                if let Some((_, _, MessageHandler::End)) = handler {
                    self.callback_captures = callback_body_start(expr).map(|body| {
                        let captures = self
                            .flow_vars
                            .iter()
                            .map(|(name, stage)| {
                                (name.clone(), *stage, self.response_vars.get(name).copied())
                            })
                            .collect();
                        (body, captures)
                    });
                }
                self.callback_producer = None;
                let followed = self.follow_callback_under(expr, kind, polarity);
                self.callback_seed = None;
                self.callback_captures = None;
                if let Some((_, stage, MessageHandler::Chunk)) = handler {
                    for name in chunk_accumulators(expr) {
                        if self.insert_flow_slot(name.clone()) {
                            self.response_vars.remove(&name);
                            self.flow_vars.insert(name, *stage);
                        }
                    }
                }
                // The chained promise settles with what the handler returns.
                if settled.is_some()
                    && !matches!(handler, Some((_, _, MessageHandler::File)))
                    && let Some(producer) = self.callback_producer.take()
                {
                    self.stage_by_span.insert(call.span.start, producer);
                }
                callbacks += usize::from(followed);
                if quiet_promise && !followed && callback_needs_resolution(expr) {
                    self.unresolved_call(call.span, "promise callback", None);
                }
            }
        }
        callbacks
    }

    /// The callback argument, its byte producer, and its role for a file
    /// read, HTTP response, or listener registered on that response.
    fn message_handler(
        &self,
        callee: &Expression<'a>,
        call: &CallExpression<'a>,
    ) -> Option<(usize, usize, MessageHandler)> {
        if let Some(target) = self.resolve_effect_callee(callee)
            && target.module == "fs"
            && target.function == "readFile"
            && matches!(call.arguments.len(), 2 | 3)
        {
            let stage = *self.stage_by_span.get(&call.span.start)?;
            return Some((call.arguments.len() - 1, stage, MessageHandler::File));
        }
        if let Some(target) = self.resolve_effect_callee(callee)
            && matches!(target.module.as_str(), "http" | "https")
            && target.function == "get"
        {
            let stage = *self.stage_by_span.get(&call.span.start)?;
            let index = call
                .arguments
                .len()
                .checked_sub(1)
                .filter(|index| *index > 0)?;
            return Some((index, stage, MessageHandler::Response));
        }
        let Expression::StaticMemberExpression(member) = callee else {
            return None;
        };
        let Expression::Identifier(receiver) = unparen(&member.object) else {
            return None;
        };
        if !matches!(member.property.name.as_str(), "on" | "once")
            || self.response_vars.get(receiver.name.as_str()) != Some(&ResponseKind::Message)
        {
            return None;
        }
        let stage = *self.flow_vars.get(receiver.name.as_str())?;
        let event = call.arguments.first().and_then(Argument::as_expression)?;
        let handler = match unparen(event) {
            Expression::StringLiteral(event) if event.value == "data" => MessageHandler::Chunk,
            Expression::StringLiteral(event) if event.value == "end" => MessageHandler::End,
            _ => return None,
        };
        Some((1, stage, handler))
    }

    /// `promise.then(eval)`: the settled value runs as code.
    fn promise_handler_code_execution(
        &mut self,
        handler: &Expression<'a>,
        call: Span,
        settled: usize,
        kind: effinterp_proto::ConditionKind,
        polarity: Option<bool>,
    ) -> bool {
        if !matches!(unparen(handler), Expression::Identifier(id) if id.name.as_str() == "eval")
            || !self.bindings.is_runtime_code(handler)
        {
            return false;
        }
        self.push_callback_condition(handler.span(), kind, polarity);
        let before = self.builder.effects_len();
        self.dynamic_code_execution(call, "eval");
        let after = self.builder.effects_len();
        self.builder.pop_condition();
        if let Some(stage) = self.new_stage(handler.span(), before, after) {
            self.stage_writer.add_edge(settled, stage, 0);
        }
        true
    }

    pub(super) fn follow_callback(&mut self, expr: &Expression<'a>) -> bool {
        self.follow_callback_under(expr, effinterp_proto::ConditionKind::Dispatch, None)
    }

    /// Follow a callback under the condition that it is invoked: a generic
    /// dispatch, or a promise's fulfillment, which like the right side of
    /// `&&` runs only on success.
    fn follow_callback_under(
        &mut self,
        expr: &Expression<'a>,
        kind: effinterp_proto::ConditionKind,
        polarity: Option<bool>,
    ) -> bool {
        self.push_callback_condition(expr.span(), kind, polarity);
        let result = self.follow_guarded_callback(expr);
        self.builder.pop_condition();
        result
    }

    /// Enter the condition under which the callback at `span` is invoked.
    pub(super) fn push_callback_condition(
        &mut self,
        span: Span,
        kind: effinterp_proto::ConditionKind,
        polarity: Option<bool>,
    ) {
        self.builder
            .push_condition(effinterp_proto::Condition::atom(
                effinterp_proto::ConditionAtom {
                    origin: effinterp_proto::ConditionOrigin {
                        source_digest: self.bindings.source_digest.clone(),
                        span: effinterp_proto::ByteSpan {
                            start: span.start,
                            end: span.end,
                        },
                        kind,
                        ordinal: span.start,
                        call_instance: None,
                    },
                    arm: 0,
                    arms: 2,
                    exhaustive: true,
                    polarity,
                    evidence: effinterp_proto::ConditionEvidence::Source {
                        path: None,
                        excerpt: None,
                    },
                },
            ));
    }

    fn follow_guarded_callback(&mut self, expr: &Expression<'a>) -> bool {
        match unparen(expr) {
            Expression::FunctionExpression(function) => {
                if function.generator {
                    true
                } else if let Some(body) = &function.body {
                    let self_binding = function.id.as_ref().map(|id| id.name.as_str());
                    self.callback_producer = self
                        .enter_inline_body(
                            body,
                            &function.params,
                            self_binding,
                            &[],
                            &[],
                            false,
                            function.r#async,
                            false,
                        )
                        .producer;
                    true
                } else {
                    false
                }
            }
            Expression::ArrowFunctionExpression(function) => {
                self.callback_producer = self
                    .enter_inline_body(
                        &function.body,
                        &function.params,
                        None,
                        &[],
                        &[],
                        false,
                        function.r#async,
                        function.expression,
                    )
                    .producer;
                true
            }
            Expression::Identifier(id) => {
                if let Some(function) = resolve_callable(
                    self.functions,
                    &self.callable_env,
                    id.name.as_str(),
                    id.span,
                ) {
                    let _ = self.enter_function(function, &[], &[], false);
                    true
                } else {
                    false
                }
            }
            Expression::ObjectExpression(object) => {
                let mut followed = false;
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            followed |= self.follow_callback(&property.value)
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            followed |= self.follow_callback(&spread.argument)
                        }
                    }
                }
                followed
            }
            Expression::ArrayExpression(array) => {
                let mut followed = false;
                for element in &array.elements {
                    if let Some(expr) = element.as_expression() {
                        followed |= self.follow_callback(expr);
                    }
                }
                followed
            }
            Expression::AwaitExpression(awaited) => self.follow_callback(&awaited.argument),
            _ => false,
        }
    }
}
