use std::collections::{HashMap, HashSet};

use rustpython_parser::ast;
use rustpython_parser::ast::{Expr, Stmt};

use super::resolve::str_literal;
use super::{callee_written, child_exprs, rebound_body_names};
use crate::{Registration, RegistrationKind};

pub(super) fn fastapi_registrations(
    body: &[Stmt],
    file: &str,
    max_bytes: u64,
) -> Result<Vec<Registration>, &'static str> {
    let mut out = Vec::new();
    let mut bytes_left = max_bytes;
    scan_body(
        body,
        file,
        None,
        &mut RegistrationBindings::default(),
        &mut out,
        &mut bytes_left,
    )?;
    Ok(out)
}

#[derive(Clone, Default)]
struct RegistrationBindings {
    imports: HashMap<String, RegistrationImport>,
    receivers: HashMap<String, RegistrationReceiver>,
    handlers: HashMap<String, String>,
}

#[derive(Clone)]
struct RegistrationReceiver {
    prefix: Option<String>,
    shadowed_members: HashSet<String>,
}

#[derive(Clone, PartialEq, Eq)]
enum RegistrationImport {
    Imported(String),
    Unavailable,
    Shadowed,
}

impl RegistrationBindings {
    fn invalidate(&mut self, name: &str) {
        self.imports
            .insert(name.to_string(), RegistrationImport::Shadowed);
        self.receivers.remove(name);
        self.handlers.remove(name);
    }

    fn invalidate_target(&mut self, target: &Expr) {
        match target {
            Expr::Name(name) => self.invalidate(name.id.as_str()),
            Expr::Tuple(tuple) => {
                for target in &tuple.elts {
                    self.invalidate_target(target);
                }
            }
            Expr::List(list) => {
                for target in &list.elts {
                    self.invalidate_target(target);
                }
            }
            Expr::Starred(starred) => self.invalidate_target(&starred.value),
            Expr::Attribute(attribute) => {
                if let Expr::Name(name) = attribute.value.as_ref()
                    && let Some(receiver) = self.receivers.get_mut(name.id.as_str())
                {
                    // Member writes preserve the receiver. A changed prefix no longer
                    // proves a local address, and replaced decorators prove no route.
                    if attribute.attr.as_str() == "prefix" {
                        receiver.prefix = None;
                    } else {
                        receiver.shadowed_members.insert(attribute.attr.to_string());
                    }
                }
                self.invalidate_import_member(&attribute.value);
            }
            Expr::Subscript(subscript) => self.invalidate_import_member(&subscript.value),
            _ => {}
        }
    }

    fn invalidate_import_member(&mut self, value: &Expr) {
        match value {
            Expr::Name(name) if self.imports.contains_key(name.id.as_str()) => {
                self.imports
                    .insert(name.id.to_string(), RegistrationImport::Shadowed);
            }
            Expr::Attribute(attribute) => self.invalidate_import_member(&attribute.value),
            Expr::Subscript(subscript) => self.invalidate_import_member(&subscript.value),
            _ => {}
        }
    }

    fn merge_receiver_mutations(&mut self, branch: &Self) {
        for (name, receiver) in &mut self.receivers {
            if let Some(changed) = branch.receivers.get(name) {
                if changed.prefix != receiver.prefix {
                    receiver.prefix = None;
                }
                receiver
                    .shadowed_members
                    .extend(changed.shadowed_members.iter().cloned());
            }
        }
    }
}

fn invalidate_expression(bindings: &mut RegistrationBindings, expression: &Expr) {
    let mut expressions = vec![expression];
    while let Some(expression) = expressions.pop() {
        if let Expr::NamedExpr(named) = expression {
            bindings.invalidate_target(&named.target);
        }
        expressions.extend(child_exprs(expression));
    }
}

fn merge_imports(
    mut left: HashMap<String, RegistrationImport>,
    right: HashMap<String, RegistrationImport>,
) -> HashMap<String, RegistrationImport> {
    // Unbound/None alternatives cannot construct an app. Keep the imported
    // alternative, but reject competing callable bindings or different imports.
    for (name, binding) in right {
        left.entry(name)
            .and_modify(|existing| {
                if *existing == RegistrationImport::Unavailable {
                    *existing = binding.clone();
                } else if binding != RegistrationImport::Unavailable && *existing != binding {
                    *existing = RegistrationImport::Shadowed;
                }
            })
            .or_insert(binding);
    }
    left
}

fn scan_body(
    body: &[Stmt],
    file: &str,
    owner: Option<&str>,
    bindings: &mut RegistrationBindings,
    out: &mut Vec<Registration>,
    bytes_left: &mut u64,
) -> Result<(), &'static str> {
    // Bindings are interpreted in statement order: rebinding an import or receiver
    // removes its proof before the next declaration is considered.
    for stmt in body {
        let mut branch_imports = None;
        match stmt {
            Stmt::If(statement) => {
                let mut initial = bindings.clone();
                invalidate_expression(&mut initial, &statement.test);
                let mut yes = initial.clone();
                let mut no = initial;
                scan_body(&statement.body, file, owner, &mut yes, out, bytes_left)?;
                scan_body(&statement.orelse, file, owner, &mut no, out, bytes_left)?;
                bindings.merge_receiver_mutations(&yes);
                bindings.merge_receiver_mutations(&no);
                branch_imports = Some(merge_imports(yes.imports, no.imports));
            }
            Stmt::With(statement) => {
                let mut branch = bindings.clone();
                for item in &statement.items {
                    invalidate_expression(&mut branch, &item.context_expr);
                    if let Some(target) = &item.optional_vars {
                        branch.invalidate_target(target);
                    }
                }
                scan_body(&statement.body, file, owner, &mut branch, out, bytes_left)?;
                bindings.merge_receiver_mutations(&branch);
                branch_imports = Some(branch.imports);
            }
            Stmt::Try(statement) => {
                let mut success = bindings.clone();
                let mut interrupted_imports = bindings.imports.clone();
                for statement in &statement.body {
                    scan_body(
                        std::slice::from_ref(statement),
                        file,
                        owner,
                        &mut success,
                        out,
                        bytes_left,
                    )?;
                    interrupted_imports =
                        merge_imports(interrupted_imports, success.imports.clone());
                }
                scan_body(
                    &statement.orelse,
                    file,
                    owner,
                    &mut success,
                    out,
                    bytes_left,
                )?;
                bindings.merge_receiver_mutations(&success);
                let mut imports = success.imports;
                for handler in &statement.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    let mut branch = bindings.clone();
                    // A handler can observe partial writes before the exception.
                    for name in rebound_body_names(&statement.body, false) {
                        branch.invalidate(&name);
                    }
                    branch.imports = interrupted_imports.clone();
                    if let Some(name) = &handler.name {
                        branch.invalidate(name.as_str());
                    }
                    scan_body(&handler.body, file, owner, &mut branch, out, bytes_left)?;
                    if let Some(name) = &handler.name {
                        branch.invalidate(name.as_str());
                    }
                    bindings.merge_receiver_mutations(&branch);
                    imports = merge_imports(imports, branch.imports);
                }
                let mut final_bindings = bindings.clone();
                for name in rebound_body_names(std::slice::from_ref(stmt), false) {
                    final_bindings.invalidate(&name);
                }
                final_bindings.imports = imports;
                scan_body(
                    &statement.finalbody,
                    file,
                    owner,
                    &mut final_bindings,
                    out,
                    bytes_left,
                )?;
                bindings.merge_receiver_mutations(&final_bindings);
                branch_imports = Some(final_bindings.imports);
            }
            _ => {}
        }
        match stmt {
            Stmt::Import(import) => {
                for alias in &import.names {
                    let name = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                    bindings.imports.insert(
                        name.clone(),
                        RegistrationImport::Imported(alias.name.to_string()),
                    );
                    bindings.receivers.remove(&name);
                }
            }
            Stmt::ImportFrom(import) if import.level.is_none_or(|level| level.to_u32() == 0) => {
                for alias in &import.names {
                    let name = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                    bindings.imports.insert(
                        name.clone(),
                        RegistrationImport::Imported(format!(
                            "{}.{}",
                            import.module.as_ref().map(|s| s.as_str()).unwrap_or(""),
                            alias.name
                        )),
                    );
                    bindings.receivers.remove(&name);
                }
            }
            Stmt::Assign(assign) => {
                let receiver = receiver_prefix(&assign.value, &bindings.imports);
                for target in &assign.targets {
                    bindings.invalidate_target(target);
                    if let Expr::Name(name) = target
                        && matches!(assign.value.as_ref(), Expr::Constant(value) if value.value == ast::Constant::None)
                    {
                        bindings
                            .imports
                            .insert(name.id.to_string(), RegistrationImport::Unavailable);
                    }
                    if let Expr::Name(name) = target
                        && let Some(prefix) = &receiver
                    {
                        bindings.receivers.insert(
                            name.id.to_string(),
                            RegistrationReceiver {
                                prefix: prefix.clone(),
                                shadowed_members: HashSet::new(),
                            },
                        );
                    }
                }
            }
            Stmt::AnnAssign(assign) => {
                if let Some(value) = &assign.value {
                    let receiver = receiver_prefix(value, &bindings.imports);
                    bindings.invalidate_target(&assign.target);
                    if let Expr::Name(name) = assign.target.as_ref()
                        && matches!(value.as_ref(), Expr::Constant(value) if value.value == ast::Constant::None)
                    {
                        bindings
                            .imports
                            .insert(name.id.to_string(), RegistrationImport::Unavailable);
                    }
                    if let Expr::Name(name) = assign.target.as_ref()
                        && let Some(prefix) = receiver
                    {
                        bindings.receivers.insert(
                            name.id.to_string(),
                            RegistrationReceiver {
                                prefix,
                                shadowed_members: HashSet::new(),
                            },
                        );
                    }
                }
            }
            Stmt::AugAssign(assign) => {
                bindings.invalidate_target(&assign.target);
                invalidate_expression(bindings, &assign.value);
            }
            Stmt::Delete(delete) => {
                for target in &delete.targets {
                    bindings.invalidate_target(target);
                }
            }
            Stmt::FunctionDef(function) => {
                add_decorators(
                    &owner.map_or_else(
                        || function.name.to_string(),
                        |owner| format!("{owner}.{}", function.name),
                    ),
                    &function.decorator_list,
                    &bindings.receivers,
                    file,
                    out,
                    bytes_left,
                )?;
                bindings.invalidate(function.name.as_str());
                bindings.handlers.insert(
                    function.name.to_string(),
                    owner.map_or_else(
                        || function.name.to_string(),
                        |owner| format!("{owner}.{}", function.name),
                    ),
                );
            }
            Stmt::AsyncFunctionDef(function) => {
                add_decorators(
                    &owner.map_or_else(
                        || function.name.to_string(),
                        |owner| format!("{owner}.{}", function.name),
                    ),
                    &function.decorator_list,
                    &bindings.receivers,
                    file,
                    out,
                    bytes_left,
                )?;
                bindings.invalidate(function.name.as_str());
                bindings.handlers.insert(
                    function.name.to_string(),
                    owner.map_or_else(
                        || function.name.to_string(),
                        |owner| format!("{owner}.{}", function.name),
                    ),
                );
            }
            Stmt::ClassDef(class) => {
                if owner.is_none() {
                    scan_body(
                        &class.body,
                        file,
                        Some(class.name.as_str()),
                        &mut bindings.clone(),
                        out,
                        bytes_left,
                    )?;
                }
                bindings.invalidate(class.name.as_str());
            }
            Stmt::Expr(expression) => {
                if let Expr::Call(call) = expression.value.as_ref() {
                    let handler = call
                        .keywords
                        .iter()
                        .find(|kw| kw.arg.as_ref().is_some_and(|arg| arg == "endpoint"))
                        .map(|kw| &kw.value)
                        .or_else(|| call.args.get(1));
                    if let Some(Expr::Name(handler)) = handler
                        && let Some(handler) = bindings.handlers.get(handler.id.as_str())
                    {
                        add_call(
                            call,
                            handler,
                            &bindings.receivers,
                            file,
                            true,
                            out,
                            bytes_left,
                        )?;
                    }
                }
                for name in rebound_body_names(std::slice::from_ref(stmt), false) {
                    bindings.invalidate(&name);
                }
            }
            _ => {
                for name in rebound_body_names(std::slice::from_ref(stmt), false) {
                    bindings.invalidate(&name);
                }
            }
        }
        if let Some(imports) = branch_imports {
            bindings.imports = imports;
        }
    }
    Ok(())
}

fn add_decorators(
    handler: &str,
    decorators: &[Expr],
    receivers: &HashMap<String, RegistrationReceiver>,
    file: &str,
    out: &mut Vec<Registration>,
    bytes_left: &mut u64,
) -> Result<(), &'static str> {
    for decorator in decorators {
        if let Expr::Call(call) = decorator {
            add_call(call, handler, receivers, file, false, out, bytes_left)?;
        }
    }
    Ok(())
}

fn add_call(
    call: &ast::ExprCall,
    handler: &str,
    receivers: &HashMap<String, RegistrationReceiver>,
    file: &str,
    direct: bool,
    out: &mut Vec<Registration>,
    bytes_left: &mut u64,
) -> Result<(), &'static str> {
    let Some(written) = callee_written(&call.func) else {
        return Ok(());
    };
    let Some((owner, method)) = written.rsplit_once('.') else {
        return Ok(());
    };
    let Some(receiver) = receivers.get(owner) else {
        return Ok(());
    };
    if receiver.shadowed_members.contains(method) {
        return Ok(());
    }
    let methods = match (direct, method) {
        (false, "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "trace") => {
            vec![Some(method.to_ascii_uppercase())]
        }
        (false, "api_route" | "route") | (true, "add_api_route" | "add_route") => {
            match call
                .keywords
                .iter()
                .find(|kw| kw.arg.as_ref().is_some_and(|arg| arg == "methods"))
            {
                None => vec![Some("GET".into())],
                Some(kw) => {
                    let values = match &kw.value {
                        Expr::List(list) => Some(&list.elts),
                        Expr::Tuple(tuple) => Some(&tuple.elts),
                        Expr::Set(set) => Some(&set.elts),
                        _ => None,
                    };
                    values
                        .map(|values| {
                            values
                                .iter()
                                .map(|value| str_literal(value).map(|s| s.to_ascii_uppercase()))
                                .collect()
                        })
                        .unwrap_or_else(|| vec![None])
                }
            }
        }
        _ => return Ok(()),
    };
    let local_path = call
        .args
        .first()
        .or_else(|| {
            call.keywords
                .iter()
                .find(|kw| kw.arg.as_ref().is_some_and(|arg| arg == "path"))
                .map(|kw| &kw.value)
        })
        .and_then(str_literal);
    let path = receiver
        .prefix
        .as_ref()
        .zip(local_path)
        .map(|(prefix, path)| format!("{prefix}{path}"));
    for method in methods {
        let mut unresolved = vec![
            "external_mount".into(),
            "middleware_and_dependencies".into(),
        ];
        if method.is_none() || path.is_none() {
            unresolved.push("dynamic_registration".into());
        }
        let registration = Registration {
            kind: RegistrationKind::Route {
                method,
                path: path.clone(),
            },
            file: file.to_string(),
            owner: owner.to_string(),
            primary_handler: handler.to_string(),
            selected_handlers: vec![handler.to_string()],
            spans: vec![(call.range.start().to_u32(), call.range.end().to_u32())],
            unresolved,
        };
        crate::registration::charge_registration(bytes_left, &registration)?;
        out.push(registration);
    }
    Ok(())
}

fn receiver_prefix(
    value: &Expr,
    imports: &HashMap<String, RegistrationImport>,
) -> Option<Option<String>> {
    let Expr::Call(call) = value else { return None };
    let written = callee_written(&call.func)?;
    let (root, suffix) = written.split_once('.').unwrap_or((&written, ""));
    let RegistrationImport::Imported(module) = imports.get(root)? else {
        return None;
    };
    let resolved = if suffix.is_empty() {
        module.clone()
    } else {
        format!("{module}.{suffix}")
    };
    matches!(resolved.as_str(), "fastapi.FastAPI" | "fastapi.APIRouter").then(|| {
        if resolved == "fastapi.FastAPI" {
            return Some(String::new());
        }
        call.keywords
            .iter()
            .find(|kw| kw.arg.as_ref().is_some_and(|arg| arg == "prefix"))
            .map(|kw| str_literal(&kw.value))
            .unwrap_or(Some(String::new()))
    })
}
