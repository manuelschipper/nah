//! Python context managers.

use effinterp_proto::{BoundaryClass, BoundaryReason, CalleeReference, ResourceExpr};
use rustpython_parser::ast;
use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{Expr, Stmt};
use rustpython_parser::text_size::TextRange;

use crate::control_flow::SiteFacts;
use crate::{ObjectIdentity, SemanticValue};

use super::ast_expressions::callee_written;
use super::name_bindings::rebound_target_names;
use super::{PythonWalker, control, model};

impl PythonWalker<'_, '_> {
    fn bind_context(&mut self, item: &ast::WithItem) {
        let resource = self
            .temporary_context_resource(&item.context_expr)
            .or_else(|| self.context_resource(&item.context_expr));
        self.bind_context_resource(item, resource);
    }

    fn bind_context_resource(&mut self, item: &ast::WithItem, resource: Option<ResourceExpr>) {
        let Some(target) = item.optional_vars.as_deref() else {
            return;
        };
        self.walk_assignment_target(target);
        if self.capture.is_some() {
            self.rebind_printed(&rebound_target_names(target), &[]);
        }
        let Expr::Name(target) = target else {
            self.invalidate_rebound_target(target);
            return;
        };
        let name = target.id.to_string();
        self.clear_bound_receiver(&name);
        self.bind_write_handle(&name, &item.context_expr);
        match resource {
            Some(resource) => {
                self.var_scope.insert(name.clone(), resource);
                self.widened_vars.remove(&name);
                self.path_vars.remove(&name);
                self.branch_mixed_path_vars.remove(&name);
            }
            None => {
                self.var_scope.remove(&name);
                self.widened_vars.insert(name.clone());
                self.path_vars.remove(&name);
                self.branch_mixed_path_vars.remove(&name);
            }
        }
        self.concatenated_vars.remove(&name);
        self.unbounded_string_vars.remove(&name);
        self.collections.remove(&name);
        match self.net_receiver(&item.context_expr) {
            Some(receiver) => {
                self.sessions.insert(name.clone(), receiver);
            }
            None => {
                self.sessions.remove(&name);
                self.modeled_values.remove(&name);
            }
        }
        self.connected_sockets.remove(&name);
        if let Expr::Call(call) = &item.context_expr
            && matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("open" | "io.open")
            )
            && let Some(instance) = self.ctor_class(call)
        {
            self.instance_vars.insert(name.clone(), instance);
        }
        if let Some(value) = self.modeled_value(&item.context_expr)
            && matches!(&value, model::ModeledValue::Temporary { kind, .. } if kind == "tempfile.NamedTemporaryFile")
        {
            self.modeled_values.insert(name.clone(), value);
        }
        if self.capture.is_some()
            && let Expr::Call(call) = &item.context_expr
            && self.imports.resolve_callee(&call.func).as_deref() == Some("asyncio.TaskGroup")
            && let Some(instance) = self.ctor_class(call)
        {
            self.instance_vars.insert(name, instance);
        }
        self.imports.shadow(target.id.as_str());
    }

    fn local_context(&self, expr: &Expr) -> Option<(String, SemanticValue, TextRange)> {
        let (receiver, span) = match expr {
            Expr::Call(call) => (self.ctor_class(call)?, call.range),
            Expr::Name(name) => (
                self.instance_vars.get(name.id.as_str())?.clone(),
                name.range,
            ),
            _ => return None,
        };
        let ObjectIdentity::Class { name, .. } = &receiver.as_object()?.identity else {
            return None;
        };
        let name = name.clone();
        self.defs
            .iter()
            .any(|def| def.name == format!("{name}.__enter__"))
            .then_some((name, receiver, span))
    }

    /// Enter context managers in item order and run local exit methods in reverse order.
    pub(super) fn walk_with(&mut self, items: &[ast::WithItem], body: &[Stmt]) {
        let rebound: Vec<_> = items
            .iter()
            .filter_map(|item| item.optional_vars.as_deref())
            .flat_map(rebound_target_names)
            .collect();
        let prior_printed = self.printed_by(&rebound);
        let mut contexts = Vec::new();
        for item in items {
            let before = self.capture.as_ref().map(|capture| capture.effects.len());
            let mut entered = None;
            // Entering a context does not consume a filesystem iterator.
            if matches!(&item.context_expr, Expr::Call(call)
                if matches!(self.imports.resolve_callee(&call.func).as_deref(),
                    Some("glob.iglob" | "os.walk")))
            {
                self.walk_expr(&item.context_expr);
            } else {
                entered = self.flow_deferred(&item.context_expr);
            }
            let (enter, suppress) = control::context_spans(item);
            let capture = self.capture.is_some();
            if let Some((class, receiver, span)) = self.local_context(&item.context_expr) {
                let applications = std::mem::take(&mut self.control_applications);
                let resource = self.apply_context_method(&class, "__enter__", &receiver, span);
                let entered = std::mem::replace(&mut self.control_applications, applications);
                if let [entered] = entered.as_slice() {
                    self.builder
                        .control_site(self.source, capture, enter, entered.clone());
                }
                self.bind_context_resource(item, resource);
                contexts.push((class, receiver, span));
            } else {
                let modeled = self.modeled_context(&item.context_expr)
                    || self.context_resource(&item.context_expr).is_some()
                    || matches!(&item.context_expr, Expr::Call(call) if self.imports.resolve_callee(&call.func).as_deref().is_some_and(|name| matches!(name, "open" | "io.open")));
                let file = matches!(&item.context_expr, Expr::Call(call) if self.imports.resolve_callee(&call.func).as_deref().is_some_and(|name| matches!(name, "open" | "io.open")));
                if file {
                    // A file object neither runs code on entry nor swallows
                    // exceptions on exit.
                    self.builder.control_site(
                        self.source,
                        capture,
                        enter,
                        SiteFacts::known(Vec::new()),
                    );
                    self.builder.control_site(
                        self.source,
                        capture,
                        suppress,
                        SiteFacts {
                            returns: false,
                            ..SiteFacts::default()
                        },
                    );
                }
                self.bind_context(item);
                if !modeled {
                    let name = callee_written(&item.context_expr).unwrap_or_else(|| {
                        self.source[usize::from(item.context_expr.range().start())
                            ..usize::from(item.context_expr.range().end())]
                            .to_string()
                    });
                    self.emit_unresolved_call(
                        &name,
                        BoundaryReason::DYNAMIC_DISPATCH,
                        BoundaryClass::Unresolved,
                        crate::external::ALL_DOMAINS,
                        item.context_expr.range(),
                        Some(CalleeReference {
                            module: name.clone(),
                            symbol: "__enter__/__exit__".to_string(),
                        }),
                    );
                }
            }
            // `with open(p) as f` binds what the context expression
            // produced: the file `f.read()` then reads.
            if let Some(Expr::Name(target)) = item.optional_vars.as_deref() {
                let name = target.id.to_string();
                if let Some(before) = before {
                    let effects = self.carried_effects(&item.context_expr, before);
                    self.rebind_printed(std::slice::from_ref(&name), &effects);
                }
                match entered {
                    Some(entered) => self.flow_vars.insert(name, entered),
                    None => self.flow_vars.remove(&name),
                };
            }
        }
        // Only a complete one-step dump establishes a document. Multiple
        // writes, cursor changes and arbitrary writer methods stay unknown.
        let dumped = if let ([item], [Stmt::Expr(statement)]) = (items, body)
            && let Some(Expr::Name(binding)) = item.optional_vars.as_deref()
            && let Expr::Call(open) = &item.context_expr
            && let Expr::Call(call) = statement.value.as_ref()
            && matches!(call.args.get(1), Some(Expr::Name(writer)) if writer.id == binding.id)
        {
            self.json_dump_to_open(call, open, call.range)
        } else {
            false
        };
        if !dumped {
            self.walk_body(body);
        }
        // Leaving the statement closes the file objects it bound.
        for name in &rebound {
            self.write_handles.remove(name);
        }
        for (class, receiver, span) in contexts.into_iter().rev() {
            self.apply_context_method(&class, "__exit__", &receiver, span);
        }
        // Paths skipping an enclosing branch keep the targets' prior values.
        if self.capture_conditional() {
            self.restore_printed(prior_printed);
        }
    }

    fn context_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        let Expr::Call(call) = expr else { return None };
        let name = self.local_callee(&call.func)?;
        let def = self.defs.iter().find(|def| def.name == name)?;
        let is_contextmanager = def.decorators.iter().any(|decorator| {
            matches!(
                self.imports
                    .resolve_written(decorator)
                    .unwrap_or_else(|| decorator.clone())
                    .as_str(),
                "contextlib.contextmanager" | "contextlib.asynccontextmanager"
            )
        });
        if !is_contextmanager {
            return None;
        }
        let values = self.static_iter_values(expr)?;
        let [value] = values.as_slice() else {
            return None;
        };
        Some(value.clone())
    }
}
