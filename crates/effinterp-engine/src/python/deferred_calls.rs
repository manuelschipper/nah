//! Deferred Python calls.
//! A coroutine, generator or lazy wrapper can be constructed without its body executing.

use rustpython_parser::ast;
use rustpython_parser::ast::Expr;
use rustpython_parser::text_size::TextRange;

use crate::module_summary::CallEdge;
use crate::{ObjectIdentity, SemanticValue};

use super::{MAX_CALL_EDGES, PythonWalker};

impl PythonWalker<'_, '_> {
    /// During summary capture, record an `__await__` edge for an awaited
    /// call with a class identity.
    pub(super) fn record_await_dispatch(&mut self, awaited: &ast::ExprAwait) {
        if self.capture.is_none() {
            return;
        }
        let Expr::Call(inner) = awaited.value.as_ref() else {
            return;
        };
        let Some(iref) = self.ctor_class(inner) else {
            return;
        };
        let Some(ObjectIdentity::Class { name, .. }) =
            iref.as_object().map(|object| &object.identity)
        else {
            return;
        };
        let edge = CallEdge {
            callee: format!("{name}.__await__"),
            awaited: true,
            receiver: Some(iref),
            ..Default::default()
        };
        if let Some(cap) = self.capture.as_mut()
            && cap.calls.len() < MAX_CALL_EDGES
        {
            cap.calls.push(edge);
        }
    }

    /// Enable deferred execution for this expression's walk, then restore
    /// the enclosing walk's execution state.
    pub(super) fn walk_deferred(&mut self, expr: &Expr) {
        self.deferred(expr, false);
    }

    /// [`Self::walk_deferred`], returning the flow stage whose value `expr`
    /// evaluates to: what a loop iterates or a `with` enters.
    /// Consume a deferred expression and return the value-flow stage of its result.
    pub(super) fn flow_deferred(&mut self, expr: &Expr) -> Option<usize> {
        self.deferred(expr, true)
    }

    fn deferred(&mut self, expr: &Expr, flow: bool) -> Option<usize> {
        let deferred_indices = match expr {
            Expr::Name(name) => self.deferred_vars.get(name.id.as_str()),
            Expr::Starred(starred) => match starred.value.as_ref() {
                Expr::Name(name) => self.deferred_containers.get(name.id.as_str()),
                _ => None,
            },
            _ => None,
        }
        .cloned();
        if let Some(indices) = deferred_indices
            && let Some(capture) = self.capture.as_mut()
        {
            for index in indices {
                if let Some(edge) = capture.calls.get_mut(index) {
                    edge.awaited = true;
                }
            }
        }
        if let Expr::Name(name) = expr
            && self.bound_vars.contains(name.id.as_str())
            && let Some(capture) = self.capture.as_mut()
            && let Some(edge) = capture.calls.iter_mut().rev().find(|edge| {
                edge.result_bindings()
                    .any(|(_, binding)| binding == name.id.as_str())
            })
        {
            edge.awaited = true;
        }
        let prior = std::mem::replace(&mut self.execute_deferred, true);
        let root = match expr {
            Expr::Call(call) => Some(call.range),
            _ => None,
        };
        let prior_call = std::mem::replace(&mut self.deferred_call, root);
        let stage = if flow {
            self.flow_expr(expr)
        } else {
            self.walk_expr(expr);
            None
        };
        self.deferred_call = prior_call;
        self.execute_deferred = prior;
        stage
    }

    /// Walk the values a `deferred_consumer` call consumes.
    pub(super) fn walk_consumed_arguments(&mut self, call: &ast::ExprCall) {
        let eager = self.eager_consumer(call);
        let synchronous = self.synchronous_consumer(call);
        for value in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
        {
            if eager {
                self.walk_eager(value, synchronous);
            } else {
                self.walk_deferred(value);
            }
        }
    }

    /// Walk a deferred value that is awaited or scheduled to run;
    /// `synchronous` when it runs to completion right there.
    pub(super) fn walk_eager(&mut self, expr: &Expr, synchronous: bool) {
        let root = match expr {
            Expr::Call(call) => Some(call.range),
            _ => None,
        };
        let prior = std::mem::replace(&mut self.eager_call, root);
        let prior_synchronous =
            std::mem::replace(&mut self.synchronous_call, root.filter(|_| synchronous));
        self.walk_deferred(expr);
        self.eager_call = prior;
        self.synchronous_call = prior_synchronous;
    }

    /// Whether a consumed call runs to completion where it is made.
    pub(super) fn synchronously_executes_call(&self, range: TextRange) -> bool {
        self.eagerly_executes_call(range) && self.synchronous_call == Some(range)
    }

    /// Eager consumers that run their coroutine to completion before
    /// returning, rather than scheduling it.
    fn synchronous_consumer(&self, call: &ast::ExprCall) -> bool {
        self.imports.resolve_callee(&call.func).as_deref() == Some("asyncio.run")
            || matches!(call.func.as_ref(), Expr::Attribute(attribute)
                if attribute.attr.as_str() == "run_until_complete")
                && self.deferred_receiver_consumer(call)
    }

    /// Whether a consumed call is awaited or scheduled to run.
    pub(super) fn eagerly_executes_call(&self, range: TextRange) -> bool {
        self.executes_deferred_call(range) && self.eager_call == Some(range)
    }

    /// Consumers that run or schedule the coroutines they receive; the lazy
    /// ones (`wait_for`, `wait`, ...) only wrap them in another coroutine.
    fn eager_consumer(&self, call: &ast::ExprCall) -> bool {
        matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some(
                "asyncio.run" | "asyncio.create_task" | "asyncio.ensure_future" | "asyncio.gather"
            )
        ) || self.deferred_receiver_consumer(call)
    }

    pub(super) fn executes_deferred_call(&self, range: TextRange) -> bool {
        self.execute_deferred && self.deferred_call == Some(range)
    }

    pub(super) fn deferred_consumer(&self, call: &ast::ExprCall) -> bool {
        let canonical = self.imports.resolve_callee(&call.func);
        matches!(
            canonical.as_deref(),
            Some(
                "asyncio.run"
                    | "asyncio.gather"
                    | "asyncio.wait"
                    | "asyncio.wait_for"
                    | "asyncio.as_completed"
                    | "asyncio.create_task"
                    | "asyncio.ensure_future"
                    | "asyncio.run_coroutine_threadsafe"
            )
        ) || matches!(
            canonical.as_deref(),
            Some("next" | "list" | "tuple" | "set" | "sorted")
        ) || self.deferred_receiver_consumer(call)
    }

    fn deferred_receiver_consumer(&self, call: &ast::ExprCall) -> bool {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return false;
        };
        let receiver = self.instance_of_expr(&attribute.value);
        let Some(ObjectIdentity::Class { name, .. }) = receiver
            .as_ref()
            .and_then(SemanticValue::as_object)
            .map(|object| &object.identity)
        else {
            return false;
        };
        let canonical = self
            .imports
            .resolve_written(name)
            .unwrap_or_else(|| name.clone());
        matches!(
            (canonical.as_str(), attribute.attr.as_str()),
            (
                "asyncio.new_event_loop" | "asyncio.get_event_loop",
                "run_until_complete"
            ) | (
                "asyncio.new_event_loop" | "asyncio.get_event_loop" | "asyncio.get_running_loop",
                "create_task"
            ) | ("asyncio.TaskGroup", "create_task")
        )
    }

    pub(super) fn executed_local_call<'c>(&self, value: &'c Expr) -> Option<&'c ast::ExprCall> {
        match value {
            Expr::Await(awaited) => match awaited.value.as_ref() {
                Expr::Call(call) => Some(call),
                _ => None,
            },
            Expr::Call(call)
                if matches!(
                    self.imports.resolve_callee(&call.func).as_deref(),
                    Some("asyncio.run" | "asyncio.wait_for")
                ) =>
            {
                match call.args.first() {
                    Some(Expr::Call(inner)) => Some(inner),
                    _ => None,
                }
            }
            Expr::Call(call) => {
                let name = self.local_callee(&call.func)?;
                let deferred = self
                    .defs
                    .iter()
                    .find(|def| def.name == name)
                    .is_some_and(|def| def.is_async || def.is_generator);
                (!deferred).then_some(call)
            }
            _ => None,
        }
    }
}
