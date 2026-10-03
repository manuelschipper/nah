//! What a Python module body defines before it is walked: its functions,
//! closures and classes, their parameters, defaults, decorators and return
//! sites, and the attribute values `__init__` assigns.

use std::collections::HashSet;
use std::rc::Rc;

use effinterp_proto::ResourceExpr;
use rustpython_parser::ast;
use rustpython_parser::ast::{Expr, Stmt};

use crate::module_summary::ClassEntry;

use super::resolve::str_literal;
use super::{Def, InitAttrValue, callee_written, child_exprs};

/// Register function definitions by name, params, and body. Module-level
/// functions come first; class methods are also registered (as `Class.method`,
/// the bare method name when free, and `Class` for `__init__`) so
/// `self.method()`, `Class.method()`, and `Class()` can be followed. The first
/// definition of a name wins.
pub(super) fn collect_defs(body: &[Stmt], defs: &mut Vec<Def>) {
    for stmt in body {
        match stmt {
            Stmt::FunctionDef(f) => {
                let name = f.name.to_string();
                push_def(
                    defs,
                    name.clone(),
                    param_names(&f.args),
                    parameter_bindings(&f.args),
                    positional_param_count(&f.args),
                    callable_defaults(&f.args),
                    param_defaults(&f.args),
                    param_types(&f.args),
                    None,
                    &f.body,
                    false,
                );
                set_decorators(defs, &name, &f.decorator_list);
                collect_closures(&f.body, &name, None, defs);
            }
            Stmt::AsyncFunctionDef(f) => {
                let name = f.name.to_string();
                push_def(
                    defs,
                    name.clone(),
                    param_names(&f.args),
                    parameter_bindings(&f.args),
                    positional_param_count(&f.args),
                    callable_defaults(&f.args),
                    param_defaults(&f.args),
                    param_types(&f.args),
                    None,
                    &f.body,
                    true,
                );
                set_decorators(defs, &name, &f.decorator_list);
                collect_closures(&f.body, &name, None, defs);
            }
            Stmt::ClassDef(c) => {
                for item in &c.body {
                    let (name, args, fn_body, decorators, is_async) = match item {
                        Stmt::FunctionDef(f) => (
                            f.name.to_string(),
                            &f.args,
                            &f.body,
                            &f.decorator_list,
                            false,
                        ),
                        Stmt::AsyncFunctionDef(f) => (
                            f.name.to_string(),
                            &f.args,
                            &f.body,
                            &f.decorator_list,
                            true,
                        ),
                        _ => continue,
                    };
                    // Drop the implicit receiver so `self._read(p)` binds `p`.
                    let params = method_params(args);
                    let types = method_param_types(args);
                    let owner = Some(c.name.to_string());
                    push_def(
                        defs,
                        format!("{}.{name}", c.name),
                        params.clone(),
                        parameter_bindings(args),
                        method_positional_param_count(args),
                        method_callable_defaults(args),
                        method_param_defaults(args),
                        types.clone(),
                        owner.clone(),
                        fn_body,
                        is_async,
                    );
                    set_decorators(defs, &format!("{}.{name}", c.name), decorators);
                    collect_closures(fn_body, &format!("{}.{name}", c.name), owner.clone(), defs);
                    push_def(
                        defs,
                        name.clone(),
                        params.clone(),
                        parameter_bindings(args),
                        method_positional_param_count(args),
                        method_callable_defaults(args),
                        method_param_defaults(args),
                        types.clone(),
                        owner.clone(),
                        fn_body,
                        is_async,
                    );
                    set_decorators(defs, &name, decorators);
                    collect_closures(fn_body, &name, owner.clone(), defs);
                    if name == "__init__" {
                        push_def(
                            defs,
                            c.name.to_string(),
                            params,
                            parameter_bindings(args),
                            method_positional_param_count(args),
                            method_callable_defaults(args),
                            method_param_defaults(args),
                            types,
                            owner,
                            fn_body,
                            is_async,
                        );
                        set_decorators(defs, c.name.as_str(), decorators);
                        collect_closures(fn_body, c.name.as_str(), Some(c.name.to_string()), defs);
                    }
                }
            }
            // A def nested in module-level control flow (websockets guards its
            // `get_version` behind `if not released:`) is still a module-level
            // function once the block runs; function bodies are NOT descended,
            // so a closure never registers as a module def.
            Stmt::If(s) => {
                collect_defs(&s.body, defs);
                collect_defs(&s.orelse, defs);
            }
            Stmt::Try(s) => {
                collect_defs(&s.body, defs);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_defs(&h.body, defs);
                }
                collect_defs(&s.orelse, defs);
                collect_defs(&s.finalbody, defs);
            }
            Stmt::With(s) => collect_defs(&s.body, defs),
            _ => {}
        }
    }
}

/// Top-level class definitions: declared bases (as written) and the instance
/// attributes `__init__` binds to a constructor parameter or to a direct
/// constructor call — the only unambiguous attribute-typing sources.
pub(super) fn collect_classes(body: &[Stmt]) -> (Vec<ClassEntry>, Vec<InitAttrValue>) {
    let mut out = Vec::new();
    let mut values = Vec::new();
    for stmt in body {
        let Stmt::ClassDef(c) = stmt else { continue };
        let bases = c.bases.iter().filter_map(callee_written).collect();
        let mut attr_params = Vec::new();
        let mut attr_classes = Vec::new();
        let mut attr_values = Vec::new();
        let init = c.body.iter().find_map(|item| match item {
            Stmt::FunctionDef(f) if f.name.as_str() == "__init__" => Some((&f.args, &f.body)),
            Stmt::AsyncFunctionDef(f) if f.name.as_str() == "__init__" => Some((&f.args, &f.body)),
            _ => None,
        });
        if let Some((args, init_body)) = init {
            let params = method_params(args);
            collect_init_attrs(
                init_body,
                &params,
                &mut attr_params,
                &mut attr_classes,
                &mut attr_values,
            );
            let mut reassigned = HashSet::new();
            for item in &c.body {
                match item {
                    Stmt::FunctionDef(function) if function.name.as_str() != "__init__" => {
                        collect_receiver_attr_writes(&function.body, "self", &mut reassigned);
                    }
                    Stmt::AsyncFunctionDef(function) if function.name.as_str() != "__init__" => {
                        collect_receiver_attr_writes(&function.body, "self", &mut reassigned);
                    }
                    _ => {}
                }
            }
            attr_values.retain(|(attr, _)| !reassigned.contains(attr));
            let types = method_param_types(args);
            for (attr, param) in &attr_params {
                if let Some((_, ty)) = types.iter().find(|(name, _)| name == param)
                    && !attr_classes.iter().any(|(name, _)| name == attr)
                {
                    attr_classes.push((attr.clone(), ty.clone()));
                }
            }
        }
        out.push(ClassEntry {
            name: c.name.to_string(),
            bases,
            attr_params,
            attr_classes,
            ..Default::default()
        });
        values.extend(attr_values.into_iter().map(|(attr, value)| InitAttrValue {
            owner: c.name.to_string(),
            attr,
            value,
        }));
    }
    (out, values)
}

/// Walk an `__init__` body for `self.attr = <param>` and `self.attr = Cls(...)`
/// assignments (following control flow, not nested defs). The last definite
/// write wins; branch disagreement and opaque reassignment drop the attribute.
fn collect_init_attrs(
    body: &[Stmt],
    params: &[String],
    attr_params: &mut Vec<(String, String)>,
    attr_classes: &mut Vec<(String, String)>,
    attr_values: &mut Vec<(String, Rc<Expr>)>,
) {
    for stmt in body {
        match stmt {
            Stmt::Assign(a) => {
                let direct_attr = match a.targets.as_slice() {
                    [Expr::Attribute(target)] if matches!(target.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self") => {
                        Some(target.attr.to_string())
                    }
                    _ => None,
                };
                let prior_class = direct_attr.as_ref().and_then(|attr| {
                    attr_classes
                        .iter()
                        .find(|(name, _)| name == attr)
                        .map(|(_, ty)| ty.clone())
                });
                let prior_value = direct_attr.as_ref().and_then(|attr| {
                    attr_values
                        .iter()
                        .find(|(name, _)| name == attr)
                        .map(|(_, value)| Rc::clone(value))
                });
                for target in &a.targets {
                    drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                }
                let Some(attr) = direct_attr else {
                    continue;
                };
                match a.value.as_ref() {
                    Expr::Name(v) if params.iter().any(|p| p == v.id.as_str()) => {
                        attr_params.push((attr.clone(), v.id.to_string()));
                    }
                    Expr::Call(call) => {
                        let preserves_attr = matches!(call.func.as_ref(), Expr::Attribute(method)
                            if matches!(method.value.as_ref(), Expr::Attribute(receiver)
                                if receiver.attr.as_str() == attr
                                    && matches!(receiver.value.as_ref(), Expr::Name(name)
                                        if name.id.as_str() == "self")));
                        if preserves_attr {
                            if let Some(ty) = prior_class {
                                attr_classes.push((attr.clone(), ty));
                            }
                            if let Some(value) = prior_value {
                                attr_values.push((attr.clone(), value));
                            }
                        } else if let Some(name) = callee_written(&call.func) {
                            if name.rsplit('.').next() == Some("Path")
                                && let [Expr::Name(value)] = call.args.as_slice()
                                && params.iter().any(|param| param == value.id.as_str())
                            {
                                attr_params.push((attr.clone(), value.id.to_string()));
                            }
                            attr_classes.push((attr.clone(), name));
                        }
                    }
                    _ => {}
                }
                if is_init_attr_value(&a.value, params)
                    && !attr_values.iter().any(|(name, _)| *name == attr)
                {
                    attr_values.push((attr.clone(), Rc::new(a.value.as_ref().clone())));
                }
            }
            Stmt::Delete(s) => {
                for target in &s.targets {
                    drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                }
            }
            Stmt::If(s) => {
                let mut body_params = attr_params.clone();
                let mut body_classes = attr_classes.clone();
                let mut body_values = attr_values.clone();
                let mut else_params = attr_params.clone();
                let mut else_classes = attr_classes.clone();
                let mut else_values = attr_values.clone();
                collect_init_attrs(
                    &s.body,
                    params,
                    &mut body_params,
                    &mut body_classes,
                    &mut body_values,
                );
                collect_init_attrs(
                    &s.orelse,
                    params,
                    &mut else_params,
                    &mut else_classes,
                    &mut else_values,
                );
                retain_init_attr_agreement(attr_params, &body_params, &else_params);
                retain_init_attr_agreement(attr_classes, &body_classes, &else_classes);
                retain_init_attr_agreement(attr_values, &body_values, &else_values);
            }
            Stmt::AugAssign(s) => {
                drop_init_attr_targets(&s.target, attr_params, attr_classes, attr_values);
            }
            Stmt::For(s) => {
                drop_init_attr_targets(&s.target, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
            }
            Stmt::AsyncFor(s) => {
                drop_init_attr_targets(&s.target, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
            }
            Stmt::While(s) => {
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
            }
            Stmt::With(s) => {
                for item in &s.items {
                    if let Some(target) = &item.optional_vars {
                        drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                    }
                }
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values)
            }
            Stmt::AsyncWith(s) => {
                for item in &s.items {
                    if let Some(target) = &item.optional_vars {
                        drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                    }
                }
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values)
            }
            Stmt::Try(s) => {
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_init_attrs(&h.body, params, attr_params, attr_classes, attr_values);
                }
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.finalbody, params, attr_params, attr_classes, attr_values);
            }
            Stmt::TryStar(s) => {
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_init_attrs(&h.body, params, attr_params, attr_classes, attr_values);
                }
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.finalbody, params, attr_params, attr_classes, attr_values);
            }
            Stmt::Match(s) => {
                for case in &s.cases {
                    let mut case_params = attr_params.clone();
                    let mut case_classes = attr_classes.clone();
                    let mut case_values = attr_values.clone();
                    collect_init_attrs(
                        &case.body,
                        params,
                        &mut case_params,
                        &mut case_classes,
                        &mut case_values,
                    );
                    attr_params.retain(|entry| case_params.contains(entry));
                    attr_classes.retain(|entry| case_classes.contains(entry));
                    attr_values.retain(|entry| case_values.contains(entry));
                }
            }
            _ => {}
        }
    }
}

fn drop_init_attr_targets(
    target: &Expr,
    attr_params: &mut Vec<(String, String)>,
    attr_classes: &mut Vec<(String, String)>,
    attr_values: &mut Vec<(String, Rc<Expr>)>,
) {
    let targets = receiver_attr_target_names(target, "self");
    attr_params.retain(|(attr, _)| !targets.contains(attr));
    attr_classes.retain(|(attr, _)| !targets.contains(attr));
    attr_values.retain(|(attr, _)| !targets.contains(attr));
}

fn receiver_attr_target_names(target: &Expr, receiver: &str) -> Vec<String> {
    match target {
        Expr::Attribute(attribute) if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == receiver) =>
        {
            vec![attribute.attr.to_string()]
        }
        Expr::List(list) => list
            .elts
            .iter()
            .flat_map(|element| receiver_attr_target_names(element, receiver))
            .collect(),
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .flat_map(|element| receiver_attr_target_names(element, receiver))
            .collect(),
        Expr::Starred(starred) => receiver_attr_target_names(&starred.value, receiver),
        _ => Vec::new(),
    }
}

fn retain_init_attr_agreement<T: Clone + PartialEq>(target: &mut Vec<T>, body: &[T], orelse: &[T]) {
    target.clear();
    target.extend(body.iter().filter(|entry| orelse.contains(entry)).cloned());
}

fn is_init_attr_value(expr: &Expr, params: &[String]) -> bool {
    if str_literal(expr).is_some()
        || matches!(expr, Expr::Name(name) if params.iter().any(|param| param == name.id.as_str()))
        || matches!(expr, Expr::Subscript(subscript) if callee_written(&subscript.value).as_deref() == Some("os.environ"))
    {
        return true;
    }
    match expr {
        Expr::Call(call) => {
            callee_written(&call.func).is_some_and(|name| {
                matches!(
                    name.rsplit('.').next(),
                    Some("Path" | "PurePath" | "PosixPath" | "PurePosixPath")
                )
            }) || matches!(call.func.as_ref(), Expr::Attribute(method) if is_init_attr_value(&method.value, params))
        }
        Expr::Attribute(attribute) => is_init_attr_value(&attribute.value, params),
        Expr::Subscript(subscript) => is_init_attr_value(&subscript.value, params),
        Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
            is_init_attr_value(&binary.left, params)
        }
        _ => false,
    }
}

fn collect_receiver_attr_target_writes(
    target: &Expr,
    receivers: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    for receiver in receivers {
        out.extend(receiver_attr_target_names(target, receiver));
    }
}

fn collect_receiver_alias_attr_writes(
    body: &[Stmt],
    receivers: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    for stmt in body {
        match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_receiver_attr_target_writes(target, receivers, out);
                }
                if let Expr::Name(source) = assign.value.as_ref()
                    && receivers.contains(source.id.as_str())
                {
                    receivers.extend(assign.targets.iter().filter_map(|target| match target {
                        Expr::Name(name) => Some(name.id.to_string()),
                        _ => None,
                    }));
                }
            }
            Stmt::Delete(stmt) => {
                for target in &stmt.targets {
                    collect_receiver_attr_target_writes(target, receivers, out);
                }
            }
            Stmt::AnnAssign(assign) => {
                collect_receiver_attr_target_writes(&assign.target, receivers, out);
                if let Expr::Name(target) = assign.target.as_ref()
                    && let Some(Expr::Name(source)) = assign.value.as_deref()
                    && receivers.contains(source.id.as_str())
                {
                    receivers.insert(target.id.to_string());
                }
            }
            Stmt::AugAssign(assign) => {
                collect_receiver_attr_target_writes(&assign.target, receivers, out);
            }
            Stmt::If(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::For(stmt) => {
                collect_receiver_attr_target_writes(&stmt.target, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::AsyncFor(stmt) => {
                collect_receiver_attr_target_writes(&stmt.target, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::While(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::With(stmt) => {
                for item in &stmt.items {
                    if let Some(target) = &item.optional_vars {
                        collect_receiver_attr_target_writes(target, receivers, out);
                    }
                }
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
            }
            Stmt::AsyncWith(stmt) => {
                for item in &stmt.items {
                    if let Some(target) = &item.optional_vars {
                        collect_receiver_attr_target_writes(target, receivers, out);
                    }
                }
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
            }
            Stmt::Try(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    collect_receiver_alias_attr_writes(&handler.body, receivers, out);
                }
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.finalbody, receivers, out);
            }
            Stmt::TryStar(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    collect_receiver_alias_attr_writes(&handler.body, receivers, out);
                }
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.finalbody, receivers, out);
            }
            Stmt::Match(stmt) => {
                for case in &stmt.cases {
                    collect_receiver_alias_attr_writes(&case.body, receivers, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_receiver_attr_writes(body: &[Stmt], receiver: &str, out: &mut HashSet<String>) {
    let mut receivers = HashSet::from([receiver.to_string()]);
    collect_receiver_alias_attr_writes(body, &mut receivers, out);
}

fn parameter_attr_writes(params: &[String], body: &[Stmt]) -> Vec<(String, String)> {
    let mut writes = Vec::new();
    for param in params {
        let mut attrs = HashSet::new();
        collect_receiver_attr_writes(body, param, &mut attrs);
        writes.extend(attrs.into_iter().map(|attr| (param.clone(), attr)));
    }
    writes.sort();
    writes
}

#[allow(clippy::too_many_arguments)]
fn push_def(
    defs: &mut Vec<Def>,
    name: String,
    params: Vec<String>,
    parameter_bindings: Vec<String>,
    positional_param_count: usize,
    callable_defaults: Vec<Option<String>>,
    param_defaults: Vec<Option<Rc<Expr>>>,
    param_types: Vec<(String, String)>,
    owner: Option<String>,
    body: &[Stmt],
    is_async: bool,
) {
    if !defs.iter().any(|d| d.name == name) {
        let parameter_attr_writes = parameter_attr_writes(&params, body);
        let local_name = name.clone();
        defs.push(Def {
            name,
            local_name,
            parent: None,
            params,
            parameter_bindings,
            positional_param_count,
            callable_defaults,
            param_defaults,
            param_types,
            owner,
            body: Rc::new(body.to_vec()),
            parameter_attr_writes,
            decorators: Vec::new(),
            is_async,
            is_generator: body_has_yield(body),
        });
    }
}

pub(super) fn decorator_names(decorators: &[Expr]) -> Vec<String> {
    decorators
        .iter()
        .map(|decorator| match decorator {
            Expr::Call(call) => callee_written(&call.func)
                .map(|name| format!("{name}()"))
                .unwrap_or_else(|| "<dynamic>".to_string()),
            _ => callee_written(decorator).unwrap_or_else(|| "<dynamic>".to_string()),
        })
        .collect()
}

fn set_decorators(defs: &mut [Def], name: &str, decorators: &[Expr]) {
    if let Some(def) = defs.iter_mut().find(|def| def.name == name) {
        def.decorators = decorator_names(decorators);
    }
}

fn collect_closures(body: &[Stmt], parent: &str, owner: Option<String>, defs: &mut Vec<Def>) {
    for stmt in body {
        let (name, args, nested, is_async) = match stmt {
            Stmt::FunctionDef(function) => (
                function.name.to_string(),
                &function.args,
                &function.body,
                false,
            ),
            Stmt::AsyncFunctionDef(function) => (
                function.name.to_string(),
                &function.args,
                &function.body,
                true,
            ),
            Stmt::If(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::For(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::AsyncFor(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::While(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::With(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                continue;
            }
            Stmt::AsyncWith(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                continue;
            }
            Stmt::Try(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    collect_closures(&handler.body, parent, owner.clone(), defs);
                }
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                collect_closures(&stmt.finalbody, parent, owner.clone(), defs);
                continue;
            }
            _ => continue,
        };
        let key = format!("{parent}.<locals>.{name}");
        if !defs.iter().any(|def| def.name == key) {
            let params = param_names(args);
            let parameter_attr_writes = parameter_attr_writes(&params, nested);
            defs.push(Def {
                name: key.clone(),
                local_name: name,
                parent: Some(parent.to_string()),
                params,
                parameter_bindings: parameter_bindings(args),
                positional_param_count: positional_param_count(args),
                callable_defaults: callable_defaults(args),
                param_defaults: param_defaults(args),
                param_types: param_types(args),
                owner: owner.clone(),
                body: Rc::new(nested.to_vec()),
                parameter_attr_writes,
                decorators: match stmt {
                    Stmt::FunctionDef(function) => decorator_names(&function.decorator_list),
                    Stmt::AsyncFunctionDef(function) => decorator_names(&function.decorator_list),
                    _ => Vec::new(),
                },
                is_async,
                is_generator: body_has_yield(nested),
            });
            collect_closures(nested, &key, owner.clone(), defs);
        }
    }
}

fn method_params(args: &ast::Arguments) -> Vec<String> {
    let names = param_names(args);
    match names.first().map(String::as_str) {
        Some("self" | "cls") => names.into_iter().skip(1).collect(),
        _ => names,
    }
}

fn positional_param_count(args: &ast::Arguments) -> usize {
    args.posonlyargs.len() + args.args.len()
}

fn method_positional_param_count(args: &ast::Arguments) -> usize {
    match param_names(args).first().map(String::as_str) {
        Some("self" | "cls") => positional_param_count(args).saturating_sub(1),
        _ => positional_param_count(args),
    }
}

fn callable_defaults(args: &ast::Arguments) -> Vec<Option<String>> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|arg| arg.default.as_deref().and_then(callee_written))
        .collect()
}

fn param_defaults(args: &ast::Arguments) -> Vec<Option<Rc<Expr>>> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|arg| {
            arg.default
                .as_deref()
                .map(|default| Rc::new(default.clone()))
        })
        .collect()
}

fn method_callable_defaults(args: &ast::Arguments) -> Vec<Option<String>> {
    let defaults = callable_defaults(args);
    match param_names(args).first().map(String::as_str) {
        Some("self" | "cls") => defaults.into_iter().skip(1).collect(),
        _ => defaults,
    }
}

fn method_param_defaults(args: &ast::Arguments) -> Vec<Option<Rc<Expr>>> {
    let defaults = param_defaults(args);
    match param_names(args).first().map(String::as_str) {
        Some("self" | "cls") => defaults.into_iter().skip(1).collect(),
        _ => defaults,
    }
}

fn param_types(args: &ast::Arguments) -> Vec<(String, String)> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .filter_map(|arg| {
            let annotation = arg.def.annotation.as_deref()?;
            Some((arg.def.arg.to_string(), callee_written(annotation)?))
        })
        .collect()
}

fn method_param_types(args: &ast::Arguments) -> Vec<(String, String)> {
    let mut types = param_types(args);
    if matches!(
        param_names(args).first().map(String::as_str),
        Some("self" | "cls")
    ) {
        types.retain(|(name, _)| !matches!(name.as_str(), "self" | "cls"));
    }
    types
}

pub(super) fn collect_path_attrs(classes: &[ClassEntry]) -> Vec<(String, String, String)> {
    classes
        .iter()
        .flat_map(|class| {
            class
                .attr_classes
                .iter()
                .map(|(attr, ty)| (class.name.clone(), attr.clone(), ty.clone()))
        })
        .collect()
}

pub(super) fn collect_class_bases(
    classes: &[ClassEntry],
) -> std::collections::HashMap<String, Vec<String>> {
    classes
        .iter()
        .map(|class| (class.name.clone(), class.bases.clone()))
        .collect()
}

pub(super) fn collect_class_strings(
    body: &[Stmt],
) -> std::collections::HashMap<(String, String), String> {
    let mut out = std::collections::HashMap::new();
    for stmt in body {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        for item in &class.body {
            match item {
                Stmt::Assign(assign) => {
                    let [Expr::Name(name)] = assign.targets.as_slice() else {
                        continue;
                    };
                    if let Some(value) = str_literal(&assign.value) {
                        out.insert((class.name.to_string(), name.id.to_string()), value);
                    }
                }
                Stmt::AnnAssign(assign) => {
                    let Expr::Name(name) = assign.target.as_ref() else {
                        continue;
                    };
                    if let Some(value) = assign.value.as_deref().and_then(str_literal) {
                        out.insert((class.name.to_string(), name.id.to_string()), value);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

pub(super) fn collect_class_sets(body: &[Stmt]) -> std::collections::HashMap<String, Vec<String>> {
    fn tuple_names(value: &Expr) -> Option<Vec<String>> {
        let Expr::Tuple(tuple) = value else {
            return None;
        };
        let names: Vec<String> = tuple
            .elts
            .iter()
            .map(callee_written)
            .collect::<Option<_>>()?;
        (!names.is_empty()).then_some(names)
    }

    let mut out = std::collections::HashMap::new();
    for stmt in body {
        match stmt {
            Stmt::Assign(assign) => {
                let [Expr::Name(name)] = assign.targets.as_slice() else {
                    continue;
                };
                if let Some(names) = tuple_names(&assign.value) {
                    out.insert(name.id.to_string(), names);
                }
            }
            Stmt::AnnAssign(assign) => {
                let Expr::Name(name) = assign.target.as_ref() else {
                    continue;
                };
                if let Some(names) = assign.value.as_deref().and_then(tuple_names) {
                    out.insert(name.id.to_string(), names);
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether a resolved resource carries usable information (anything but a
/// widened unknown). A free parameter is usable — `def f(p): return p` returns
/// its argument.
pub(super) fn is_resolvable(expr: &ResourceExpr) -> bool {
    !matches!(expr, ResourceExpr::Unresolved { .. })
}

pub(super) fn contains_literal(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Literal { .. } => true,
        ResourceExpr::Join { parts } => parts.iter().any(contains_literal),
        _ => false,
    }
}

/// Gather the value expressions of every `return` reachable in a function body
/// (following control flow, not descending into nested defs/classes). Sets
/// `saw_bare` when a valueless `return` is seen — the function does not always
/// return a value, so return-value inference must give up.
pub(super) fn collect_returns<'a>(body: &'a [Stmt], out: &mut Vec<&'a Expr>, saw_bare: &mut bool) {
    for stmt in body {
        match stmt {
            Stmt::Return(r) => match &r.value {
                Some(v) => out.push(v),
                None => *saw_bare = true,
            },
            Stmt::If(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::For(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::AsyncFor(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::While(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::With(s) => collect_returns(&s.body, out, saw_bare),
            Stmt::AsyncWith(s) => collect_returns(&s.body, out, saw_bare),
            Stmt::Try(s) => {
                collect_returns(&s.body, out, saw_bare);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_returns(&h.body, out, saw_bare);
                }
                collect_returns(&s.orelse, out, saw_bare);
                collect_returns(&s.finalbody, out, saw_bare);
            }
            // Nested functions and classes are separate scopes.
            _ => {}
        }
    }
}

pub(super) fn body_has_yield(body: &[Stmt]) -> bool {
    fn expression_has_yield(root: &Expr) -> bool {
        let mut stack = vec![root];
        while let Some(expr) = stack.pop() {
            if matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_)) {
                return true;
            }
            stack.extend(child_exprs(expr));
        }
        false
    }

    for stmt in body {
        let found = match stmt {
            Stmt::Expr(expr) => expression_has_yield(&expr.value),
            Stmt::Assign(assign) => expression_has_yield(&assign.value),
            Stmt::AnnAssign(assign) => assign.value.as_deref().is_some_and(expression_has_yield),
            Stmt::Return(ret) => ret.value.as_deref().is_some_and(expression_has_yield),
            Stmt::If(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::For(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::AsyncFor(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::While(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::With(stmt) => body_has_yield(&stmt.body),
            Stmt::AsyncWith(stmt) => body_has_yield(&stmt.body),
            Stmt::Try(stmt) => {
                body_has_yield(&stmt.body)
                    || stmt.handlers.iter().any(|handler| {
                        let ast::ExceptHandler::ExceptHandler(handler) = handler;
                        body_has_yield(&handler.body)
                    })
                    || body_has_yield(&stmt.orelse)
                    || body_has_yield(&stmt.finalbody)
            }
            // A nested function or class owns its own generator protocol.
            _ => false,
        };
        if found {
            return true;
        }
    }
    false
}

fn parameter_bindings(args: &ast::Arguments) -> Vec<String> {
    param_names(args)
        .into_iter()
        .chain(
            args.vararg
                .iter()
                .chain(&args.kwarg)
                .map(|arg| arg.arg.to_string()),
        )
        .collect()
}

/// Positional parameter names of a function, in order.
fn param_names(args: &ast::Arguments) -> Vec<String> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|a| a.def.arg.to_string())
        .collect()
}
