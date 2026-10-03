//! Python receiver and instance tracking: which class an assigned name,
//! instance attribute or call argument was constructed from, and the receiver
//! of a method call.

use std::collections::HashSet;

use rustpython_parser::ast;
use rustpython_parser::ast::{Constant, Expr};

use crate::{ObjectIdentity, SemanticValue, ValueArgument, merge_arguments, positional_arguments};

use super::{
    PythonWalker, callee_written, rebound_target_names, resolve, sequence_expr_elements,
    unpack_assignment_elements,
};

impl PythonWalker<'_, '_> {
    /// Track receiver typing for an assignment being walked in capture mode:
    /// `x = ClassName(...)` / `x = cls(...)` types `x` directly; any other
    /// call RHS marks the (possibly tuple-unpacked) targets so the recorded
    /// edge carries `binds`. Reassignment drops stale typing.
    pub(super) fn track_assign(&mut self, assign: &ast::StmtAssign) {
        self.track_bound_call(&assign.targets, &assign.value);
    }

    /// Same binding as a plain assignment for a single annotated target.
    pub(super) fn track_named_value(&mut self, target: &Expr, value: &Expr) {
        self.track_bound_call(std::slice::from_ref(target), value);
    }

    pub(super) fn clear_bound_receiver(&mut self, name: &str) {
        self.modeled_values.remove(name);
        self.receiver_rebindings.insert(name.to_string());
        self.instance_vars.remove(name);
        self.instance_sequences.remove(name);
        self.bound_vars.remove(name);
    }

    pub(super) fn clear_bound_value(&mut self, name: &str) {
        self.clear_bound_receiver(name);
        self.deferred_containers.remove(name);
        self.deferred_vars.remove(name);
    }

    pub(super) fn track_instance_attr_assignments(&mut self, targets: &[Expr]) {
        for target in targets {
            for name in rebound_target_names(target) {
                self.instance_attr_rebindings.remove(&name);
                if let Some(attrs) = self.invalidated_instance_attrs(&name) {
                    self.instance_attr_rebindings.insert(name, attrs);
                }
            }
            self.track_instance_attr_assignment(target);
        }
    }

    pub(super) fn track_instance_attr_rebinding(&mut self, receiver: &str, attr: &str) {
        if let Some(value) = self.modeled_values.remove(receiver) {
            self.modeled_values.retain(|_, other| *other != value);
        }
        let Some(instance) = self.instance_vars.get(receiver) else {
            return;
        };
        let aliases: Vec<_> = self
            .instance_vars
            .iter()
            .filter(|(_, value)| *value == instance)
            .map(|(name, _)| name.clone())
            .collect();
        for receiver in aliases {
            self.instance_attr_rebindings
                .entry(receiver)
                .or_default()
                .insert(attr.to_string());
        }
    }

    pub(super) fn invalidated_instance_attrs(&self, receiver: &str) -> Option<HashSet<String>> {
        let instance = self.instance_vars.get(receiver)?;
        let attrs: HashSet<_> = self
            .instance_vars
            .iter()
            .filter(|(_, value)| *value == instance)
            .filter_map(|(name, _)| self.instance_attr_rebindings.get(name))
            .flatten()
            .cloned()
            .collect();
        (!attrs.is_empty()).then_some(attrs)
    }

    pub(super) fn track_instance_attr_assignment(&mut self, target: &Expr) {
        match target {
            Expr::Attribute(attribute) => {
                let Expr::Name(receiver) = attribute.value.as_ref() else {
                    return;
                };
                self.track_instance_attr_rebinding(receiver.id.as_str(), attribute.attr.as_str());
            }
            Expr::List(list) => {
                self.track_instance_attr_assignments(&list.elts);
            }
            Expr::Tuple(tuple) => {
                self.track_instance_attr_assignments(&tuple.elts);
            }
            Expr::Starred(starred) => {
                self.track_instance_attr_assignment(&starred.value);
            }
            _ => {}
        }
    }

    /// Copy constructor identity from a simple name alias, including chained
    /// `u = t = s` and static unpack `src, dst = store, backup`.
    pub(super) fn instance_source_aliases(
        &self,
        targets: &[Expr],
        value: &Expr,
    ) -> Vec<(String, SemanticValue)> {
        let mut aliases = Vec::new();
        if let Expr::Name(source) = value
            && let Some(instance) = self.instance_vars.get(source.id.as_str())
        {
            for target in targets {
                if let Expr::Name(name) = target {
                    aliases.push((name.id.to_string(), instance.clone()));
                }
            }
        }
        if let Some(target_elts) = unpack_assignment_elements(targets)
            && let Some(value_elts) = sequence_expr_elements(value)
            && target_elts.len() == value_elts.len()
        {
            for (target, value) in target_elts.iter().zip(value_elts) {
                let Expr::Name(name) = target else {
                    continue;
                };
                let Expr::Name(source) = value else {
                    continue;
                };
                if let Some(instance) = self.instance_vars.get(source.id.as_str()) {
                    aliases.push((name.id.to_string(), instance.clone()));
                }
            }
        }
        aliases
    }

    pub(super) fn track_bound_call(&mut self, targets: &[Expr], value: &Expr) {
        // The resource assignment already established these exact values.
        let modeled: Vec<_> = targets
            .iter()
            .filter_map(|target| {
                let Expr::Name(name) = target else {
                    return None;
                };
                self.modeled_values
                    .get(name.id.as_str())
                    .cloned()
                    .map(|value| (name.id.to_string(), value))
            })
            .collect();
        self.pending_binds = None;
        self.pending_deferred_container = None;
        let instance_aliases = self.instance_source_aliases(targets, value);
        let instances = self.static_iter_instances(value);
        let targets: Vec<(usize, String)> = match targets {
            [Expr::Name(n)] => vec![(0, n.id.to_string())],
            [Expr::Tuple(t)] => t
                .elts
                .iter()
                .enumerate()
                .filter_map(|(i, e)| match e {
                    Expr::Name(n) => Some((i, n.id.to_string())),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        for (_, name) in &targets {
            self.clear_bound_value(name);
        }
        for (name, _) in &instance_aliases {
            if !targets.iter().any(|(_, target)| target == name) {
                self.clear_bound_value(name);
            }
        }
        self.modeled_values.extend(modeled);
        if let Some(instances) = instances
            && let [(0, name)] = targets.as_slice()
        {
            self.instance_sequences.insert(name.clone(), instances);
        }
        let Expr::Call(call) = value else {
            if let [(0, name)] = targets.as_slice() {
                let elements = match value {
                    Expr::List(list) => Some(list.elts.as_slice()),
                    Expr::Tuple(tuple) => Some(tuple.elts.as_slice()),
                    Expr::Set(set) => Some(set.elts.as_slice()),
                    _ => None,
                };
                let ranges: Vec<_> = elements
                    .into_iter()
                    .flatten()
                    .filter_map(|element| match element {
                        Expr::Call(call) => Some(call.range),
                        _ => None,
                    })
                    .collect();
                if !ranges.is_empty() {
                    self.deferred_containers.insert(name.clone(), Vec::new());
                    self.pending_deferred_container = Some((name.clone(), ranges));
                }
            }
            for (name, instance) in instance_aliases {
                self.instance_vars.insert(name, instance);
            }
            return;
        };
        if targets.is_empty() {
            return;
        }
        if let Some(mut iref) = self.instance_value(value)
            && targets.len() == 1
        {
            if self.module_capture
                && self.call_type(call).is_some()
                && let Some(scope) = &self.fact_scope
            {
                iref = SemanticValue::object(ObjectIdentity::ModuleBinding {
                    scope: scope.clone(),
                    name: targets[0].1.clone(),
                })
                .with_type(self.call_type(call));
            }
            self.instance_vars.insert(targets[0].1.clone(), iref);
        }
        // Always record the result binding: an imported name classified as a
        // possible constructor may turn out to be a function, in which case
        // the local is typed by the call's returned instance instead.
        self.pending_binds = Some((call.range, targets));
    }

    /// The instance a constructor call produces, when the callee is an
    /// unambiguous class reference: `cls(...)`, a locally defined class, or an
    /// imported name (verified to be a class at composition time).
    pub(super) fn ctor_class(&self, call: &ast::ExprCall) -> Option<SemanticValue> {
        // Builtin value construction must not participate in user-class dispatch.
        if let Some(canonical) = self.imports.resolve_callee(&call.func)
            && canonical != "open"
            && resolve::is_builtin(canonical.strip_prefix("builtins.").unwrap_or(&canonical))
        {
            return None;
        }
        if matches!(call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "cls") {
            return Some(SemanticValue::object(ObjectIdentity::DynamicClass));
        }
        // A modeled path function such as `os.path.expanduser` returns the
        // path it resolves, not an instance that would replace that value.
        if self.modeled_path(&Expr::Call(call.clone())).is_some() {
            return None;
        }
        let name = callee_written(&call.func)?;
        // A local class, or an imported name (whether the import is actually a
        // class is verified at composition time against the target's class
        // table — a function never matches, so nothing is invented).
        if !self.class_names.contains(&name) && self.imports.resolve_callee(&call.func).is_none() {
            return None;
        }
        let origin = self.site_origin(call.range, 0);
        let constructor = self.value_args_of(call);
        Some(
            SemanticValue::object(ObjectIdentity::Class { name, constructor })
                .with_origin(Some(origin))
                .with_type(self.call_type(call)),
        )
    }

    pub(super) fn value_args_of(&self, call: &ast::ExprCall) -> Vec<ValueArgument> {
        let mut arguments = self.resolved_value_args_of(call);
        let mkdir_call = matches!(call.func.as_ref(), Expr::Attribute(method)
            if method.attr.as_str() == "mkdir");
        if mkdir_call
            && let Some(keyword) = call
                .keywords
                .iter()
                .find(|keyword| keyword.arg.as_ref().map(|name| name.as_str()) == Some("parents"))
            && let Expr::Constant(constant) = &keyword.value
            && let Constant::Bool(value) = constant.value
            && let Some(argument) = arguments
                .iter_mut()
                .find(|argument| argument.name.as_deref() == Some("parents"))
        {
            argument.value = SemanticValue::literal(value.to_string());
        }
        arguments
    }

    pub(super) fn resolved_value_args_of(&self, call: &ast::ExprCall) -> Vec<ValueArgument> {
        let mut arguments =
            positional_arguments(call.args.iter().map(|arg| self.resolve_value(arg)));
        arguments.extend(call.keywords.iter().filter_map(|keyword| {
            keyword.arg.as_ref().map(|name| {
                ValueArgument::keyword(name.to_string(), 0, self.resolve_value(&keyword.value))
            })
        }));
        merge_arguments(&mut arguments, self.obj_args_of(call));
        arguments
    }

    /// The instance-typed arguments of a call, positional and keyword.
    pub(super) fn obj_args_of(&self, call: &ast::ExprCall) -> Vec<ValueArgument> {
        let mut out = Vec::new();
        for (i, arg) in call.args.iter().enumerate() {
            if let Some(instance) = self.instance_of_expr(arg) {
                if matches!(
                    instance.as_object().map(|object| &object.identity),
                    Some(ObjectIdentity::Parameter { .. })
                ) {
                    continue;
                }
                out.push(ValueArgument {
                    name: None,
                    index: i,
                    value: instance,
                });
            }
        }
        for kw in &call.keywords {
            let Some(param) = kw.arg.as_ref() else {
                continue;
            };
            if let Some(instance) = self.instance_of_expr(&kw.value) {
                if matches!(
                    instance.as_object().map(|object| &object.identity),
                    Some(ObjectIdentity::Parameter { .. })
                ) {
                    continue;
                }
                out.push(ValueArgument {
                    name: Some(param.to_string()),
                    index: 0,
                    value: instance,
                });
            }
        }
        out
    }

    /// An expression's instance reference, when its provenance is unambiguous.
    pub(super) fn instance_of_expr(&self, expr: &Expr) -> Option<SemanticValue> {
        match expr {
            Expr::Name(n) => {
                let id = n.id.as_str();
                if id == "self" {
                    return Some(SemanticValue::object(ObjectIdentity::Receiver));
                }
                if id == "cls" {
                    return Some(SemanticValue::object(ObjectIdentity::DynamicClass));
                }
                if let Some(iref) = self.instance_vars.get(id) {
                    return Some(iref.clone());
                }
                if self.class_names.contains(id) {
                    return Some(SemanticValue::object(ObjectIdentity::Class {
                        name: id.to_string(),
                        constructor: Vec::new(),
                    }));
                }
                if self.current_params.iter().any(|p| p == id) {
                    return Some(SemanticValue::object(ObjectIdentity::Parameter {
                        name: id.to_string(),
                        fallback: None,
                    }));
                }
                self.bound_vars
                    .contains(id)
                    .then(|| {
                        SemanticValue::object(ObjectIdentity::Local {
                            name: id.to_string(),
                            fallback: None,
                        })
                    })
                    .or_else(|| self.imported_module_var(expr))
            }
            Expr::Attribute(a) => match a.value.as_ref() {
                Expr::Name(n) if n.id.as_str() == "self" => Some(SemanticValue::object(
                    ObjectIdentity::ReceiverProperty(a.attr.to_string()),
                )),
                _ => None,
            },
            Expr::Call(call) => self.ctor_class(call),
            _ => None,
        }
    }

    /// The receiver of a method call, when its class provenance is
    /// unambiguous: `self.m()`, `cls.m()`, `Class.m()` (a locally defined
    /// class), a constructor-typed or call-bound local, a parameter, or a
    /// one-level `self.attr.m()`.
    pub(super) fn recv_of(&self, func: &Expr) -> Option<SemanticValue> {
        let Expr::Attribute(attr) = func else {
            return None;
        };
        match attr.value.as_ref() {
            Expr::Name(n) if n.id.as_str() == "self" => {
                Some(SemanticValue::object(ObjectIdentity::Receiver))
            }
            Expr::Name(n) if n.id.as_str() == "cls" => {
                Some(SemanticValue::object(ObjectIdentity::DynamicClass))
            }
            Expr::Name(n) if self.class_names.contains(n.id.as_str()) => {
                Some(SemanticValue::object(ObjectIdentity::Class {
                    name: n.id.to_string(),
                    constructor: Vec::new(),
                }))
            }
            // A plain Name: a constructor-typed local, parameter, or
            // call-bound local.
            Expr::Name(_) => self
                .instance_of_expr(attr.value.as_ref())
                .or_else(|| self.imported_module_var(attr.value.as_ref())),
            Expr::Attribute(inner) => match inner.value.as_ref() {
                Expr::Name(n) if n.id.as_str() == "self" => Some(SemanticValue::object(
                    ObjectIdentity::ReceiverProperty(inner.attr.to_string()),
                )),
                _ => self.imported_module_var(attr.value.as_ref()),
            },
            _ => self.imported_module_var(attr.value.as_ref()),
        }
    }
}
