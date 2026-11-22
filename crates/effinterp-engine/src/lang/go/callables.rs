//! Go callable values and callbacks supplied to another call.

use std::collections::BTreeMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
};
use gosyn::ast::Expression;

use crate::{CallableValue, ObjectIdentity, SemanticValue, SemanticValueKind};

use super::call_resolution::GoCallee;
use super::semantic_values::exact_go_property_value;
use super::summary::is_callback_field;
use super::walk_output::GoWalkOutput;
use super::walker::GoWalker;
use super::{GO_DOMAINS, go_callback_positions};

impl GoWalker<'_, '_> {
    /// The callback positions of a standard-library call, resolving a method
    /// through its receiver's declared package type (`var once sync.Once`).
    pub(super) fn callback_positions(&self, callee: &GoCallee) -> &'static [usize] {
        match callee {
            GoCallee::Pkg { path, method, .. } => go_callback_positions(path, method),
            GoCallee::Method { recv, method } => self
                .go_receiver_import_path(recv)
                .map_or(&[][..], |path| go_callback_positions(&path, method)),
            _ => &[],
        }
    }

    /// The callable a standard-library wrapper returns rather than invokes:
    /// `sync.OnceFunc(cleanup)` runs `cleanup` when the value it returns is
    /// called, so the value carries the callable to that call site.
    pub(super) fn deferred_callback_value(&self, call: &gosyn::ast::Call) -> Option<SemanticValue> {
        let GoCallee::Pkg { path, method, .. } = self.resolve_go_callee(&call.func) else {
            return None;
        };
        if path != "sync" || !matches!(method.as_str(), "OnceFunc" | "OnceValue" | "OnceValues") {
            return None;
        }
        let value = self.go_semantic_value(call.args.first()?)?;
        crate::contains_callable(&value).then_some(value)
    }

    /// Every function this file declares that the value may hold, or nothing
    /// when any alternative is a callable this file cannot name.
    pub(super) fn named_callables(&self, value: &SemanticValue) -> Option<Vec<String>> {
        match &value.kind {
            SemanticValueKind::Callable(
                CallableValue::Function { name } | CallableValue::Closure { name, .. },
            ) if self.named_go_function(name).is_some() => Some(vec![name.clone()]),
            SemanticValueKind::Union(alternatives) => {
                let names = alternatives
                    .iter()
                    .map(|alternative| self.named_callables(alternative))
                    .collect::<Option<Vec<_>>>()?;
                Some(names.into_iter().flatten().collect())
            }
            _ => None,
        }
    }

    /// A function value passed to an imported-package call is a callback that
    /// package may invoke (`once.Do(func() {...})`, `sort.Slice(xs, less)`):
    /// walk it here, since the package itself is never entered. Only a shape
    /// this file can name is walked — a literal, a function declared here, or
    /// another package's function; whether it walked one is the caller's cue
    /// that any remaining callable escaped unaccounted for.
    pub(super) fn fire_callback_arg(
        &mut self,
        arg: &Expression,
        span: (u32, u32),
        sequence: bool,
    ) -> bool {
        if let Expression::Call(call) = arg
            && let GoCallee::Pkg { path, method, .. } = self.resolve_go_callee(&call.func)
            && path == "slices"
            && matches!(method.as_str(), "Values" | "All" | "Backward")
        {
            return true;
        }
        if let Expression::FuncLit(literal) = arg {
            self.walk_function_literal(literal);
            return true;
        }
        if !matches!(arg, Expression::Ident(_) | Expression::Selector(_)) {
            return false;
        }
        // A callable read out of a struct field (`h.less`) names its target
        // exactly even though the expression is a selector, not a call target.
        // A branch may leave a finite set of them, and each one may run.
        if let Some(names) = self
            .go_semantic_value(arg)
            .and_then(|value| self.named_callables(&value))
        {
            let node = self.record_go_source_provenance(span);
            for name in names {
                self.enter_go_local_call(&name, &[], node, None, sequence, None);
            }
            return true;
        }
        match self.resolve_go_callee(arg) {
            GoCallee::Local(name) => {
                let node = self.record_go_source_provenance(span);
                self.enter_go_local_call(&name, &[], node, None, sequence, None);
                true
            }
            GoCallee::Pkg {
                path,
                method,
                local,
            } => {
                if self.collect_edges {
                    self.record_go_call_edge(
                        &format!("{local}.{method}"),
                        Vec::new(),
                        Vec::new(),
                        None,
                    );
                } else {
                    let node = self.record_go_source_provenance(span);
                    self.model_call(&path, &method, &[], node);
                }
                true
            }
            // A Go package spans its whole directory, so a callback may be
            // declared in a sibling file this walk never sees. Recorded as a
            // call edge, exactly as a direct call to that name is, so
            // composition resolves it against the package and enters it.
            GoCallee::MaybeSibling(name) if self.collect_edges => {
                self.record_go_call_edge(&name, Vec::new(), Vec::new(), None);
                true
            }
            // A callback named by a local binding (a function-typed parameter,
            // a variable): composition resolves it through the value bound to
            // that name, never through a package function spelled the same.
            GoCallee::Dynamic(name) if self.collect_edges => {
                self.record_go_dynamic_call_edge(&name, Vec::new(), Vec::new(), None);
                true
            }
            _ => false,
        }
    }

    pub(super) fn unresolved_callable(&mut self, name: &str, node: ProvenanceRef) {
        self.out_boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: self.fact_function.clone(),
                symbol: name.to_string(),
            }),
            domains: GO_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call through unresolved callable value {name}")),
        });
    }

    /// Dispatch a Go callable value when its target is an import or a body this file declares.
    pub(super) fn dispatch_callable_value(
        &mut self,
        func: &Expression,
        args: &[Expression],
        node: ProvenanceRef,
    ) -> bool {
        let Some(value) = self.go_semantic_value(func) else {
            return false;
        };
        let (name, captures) = match value.kind {
            SemanticValueKind::Callable(CallableValue::Function { name }) => {
                (name, BTreeMap::new())
            }
            SemanticValueKind::Callable(CallableValue::Closure { name, captures }) => {
                (name, captures)
            }
            _ => return false,
        };
        if let Some((pkg, method)) = name.split_once('.')
            && let Some(path) = self.imports.get(pkg).cloned()
        {
            self.model_call(&path, method, args, node);
            return true;
        }
        if self.named_go_function(&name).is_none() {
            return false;
        }
        let saved = self.values.clone();
        self.values.extend(captures);
        let (receiver, args) = if self
            .named_go_function(&name)
            .is_some_and(|function| function.receiver.is_some())
        {
            (
                args.first().and_then(|arg| self.go_semantic_value(arg)),
                args.get(1..).unwrap_or_default(),
            )
        } else {
            (None, args)
        };
        self.enter_go_local_call(&name, args, node, None, false, receiver);
        self.values = saved;
        true
    }

    pub(super) fn fire_cobra_callbacks(
        &mut self,
        recv: &str,
        method: &str,
        node: ProvenanceRef,
    ) -> bool {
        if !matches!(&self.out, GoWalkOutput::Plan { .. })
            || !matches!(method, "Execute" | "ExecuteContext")
        {
            return false;
        }
        let Some(value) = self.values.get(recv).cloned() else {
            return false;
        };
        let SemanticValueKind::Object(object) = &value.kind else {
            return false;
        };
        let ObjectIdentity::Class { name, constructor } = &object.identity else {
            return false;
        };
        let Some((package, typ)) = name.split_once('.') else {
            return false;
        };
        if typ != "Command"
            || self.imports.get(package).map(String::as_str) != Some("github.com/spf13/cobra")
        {
            return false;
        }
        let mut fields: Vec<String> = object
            .properties
            .keys()
            .chain(
                constructor
                    .iter()
                    .filter_map(|argument| argument.name.as_ref()),
            )
            .filter(|name| is_callback_field(name))
            .cloned()
            .collect();
        fields.sort();
        fields.dedup();
        for field in fields {
            let Some(names) = exact_go_property_value(&value, &field, self.value_limits)
                .and_then(|callback| self.named_callables(&callback))
            else {
                continue;
            };
            for name in names {
                self.enter_go_local_call(&name, &[], node, None, false, None);
            }
        }
        true
    }
}
