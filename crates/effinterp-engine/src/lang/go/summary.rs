//! Go callable discovery and module summary inference.

use super::*;

pub(super) fn summarize_ast(
    source: &str,
    file: &gosyn::ast::File,
    fact_file: &str,
    fact_scope: ScopeKey,
    value_limits: crate::ValueLimits,
) -> ModuleSummary {
    let imports = collect_imports(file);
    let funcs = collect_funcs(file);
    let package = match &fact_scope {
        ScopeKey::GoPackage { key } => key.as_str(),
        _ => file.pkg_name.name.as_str(),
    };
    let dispatch_contracts = go_dispatch_contracts(file, &imports, package);
    let dispatch_signatures = go_dispatch_signatures(file, &imports, package);
    let return_types = go_return_types(file, &imports, package, fact_file);
    let summaries = compute_summaries(
        source,
        &imports,
        &funcs,
        &[],
        Some(file),
        fact_file,
        Some(&fact_scope),
        None,
        value_limits,
    );
    let functions: Vec<FunctionEntry> = funcs
        .iter()
        .filter_map(|(name, f)| {
            let mut summary = summaries.get(name)?.clone();
            let (calls, sites) = collect_call_edges(
                source,
                &imports,
                &funcs,
                &summaries,
                f,
                Some(file),
                fact_file,
                &fact_scope,
                name,
                value_limits,
            );
            summary.control_flow.bind_calls(&sites);
            Some(FunctionEntry {
                name: name.clone(),
                visibility: crate::CallableVisibility::Public,
                is_async: false,
                decorator_shape: Default::default(),
                decorator_gate: Vec::new(),
                summary,
                positional_param_count: None,
                calls,
                callable_defaults: Vec::new(),
                parameter_type_narrowing: Vec::new(),
                returns_instances: returns_instances(&f.body),
                return_types: return_types.get(name).cloned().unwrap_or_default(),
                return_bindings: return_bindings(&f.body),
                dispatch_impl: None,
                dispatch_signature: dispatch_signatures.get(name).cloned(),
                lexical_span: None,
            })
        })
        .collect();

    // Execution roots the repository composition follows: package-variable
    // initializers and init() bodies here, with main() kept separately so only
    // the selected entrypoint's main runs.
    let (mut initializer, module_values) = collect_package_initializers(
        source,
        &imports,
        &funcs,
        &summaries,
        file,
        fact_file,
        &fact_scope,
        value_limits,
    );
    let mut module_calls = std::mem::take(&mut initializer.edges);
    for name in init_names(file) {
        if let Some(function) = functions.iter().find(|function| function.name == name) {
            // An init() that exhausted the node cap still owes its limit
            // boundary to the module initializer that runs it.
            initializer.boundaries.extend(
                function
                    .summary
                    .boundaries
                    .iter()
                    .filter(|boundary| boundary.limit.as_deref() == Some("max_go_nodes"))
                    .cloned(),
            );
            let base = module_calls.len() as u32;
            let requirements = initializer
                .control
                .requirements(&function.summary.control_flow);
            initializer.control.register(
                source,
                true,
                control::body_span(&funcs[&name].body),
                SiteFacts::call(&requirements, |fact| match fact {
                    ControlFact::Call(slot) => Some(ControlFact::Call(base + slot)),
                    ControlFact::CallSuccess(slot) => Some(ControlFact::CallSuccess(base + slot)),
                    ControlFact::Effect(_) => None,
                }),
            );
            module_calls.extend(function.calls.iter().cloned());
        }
    }
    let main = functions.iter().find(|function| function.name == "main");
    let main_calls = main
        .map(|function| function.calls.clone())
        .unwrap_or_default();
    let main_control_flow = main
        .map(|function| function.summary.control_flow.calls_only())
        .unwrap_or_else(ControlFlow::empty_body);
    let module_control_flow = initializer
        .control
        .leave(0)
        .expect("module capture frame")
        .flow;

    let mut ordered: Vec<FunctionEntry> = functions;
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let mut imports_out = extract_import_bindings(&imports);
    imports_out.sort_by(|a, b| a.local.cmp(&b.local));
    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            dispatch: crate::DispatchStyle::Structural,
            ..Default::default()
        },
        functions: ordered,
        module_calls,
        module_effects: initializer.effects,
        module_transfers: initializer.transfers,
        module_boundaries: initializer
            .boundaries
            .into_iter()
            .filter(|boundary| boundary.limit.is_some())
            .collect(),
        main_calls,
        main_control_flow,
        module_control_flow,
        imports: imports_out,
        module_values,
        module_value_rebindings: collect_package_rebindings(file),
        classes: collect_classes(file),
        dispatch_contracts,
        dispatch_type_aliases: go_dispatch_type_aliases(file, &imports, package),
        ..Default::default()
    };
    for function in &mut summary.functions {
        if function.name.starts_with("init#") || function.name.starts_with("func#") {
            function.visibility = crate::CallableVisibility::Internal;
        }
    }
    crate::module_summary::set_effects_propagated(&mut summary, |edge| {
        !edge.callee.contains('.') && !edge.callee.contains("::")
    });
    summary
}

// ---------------------------------------------------------------------------
// Imports and function collection

/// local package name -> import path (e.g. "exec" -> "os/exec").
pub(super) type Imports = HashMap<String, String>;

#[derive(Clone)]
pub(super) struct GoFunc {
    pub(super) params: Vec<String>,
    /// Per parameter: whether the body assigns through it, so a caller that
    /// handed it a pointer, a slice, or a map loses its exact view of that
    /// argument once the call returns. A parameter the body hands on to a
    /// callee that writes through it counts too.
    pub(super) writes_through: Vec<bool>,
    /// A method's receiver name, and whether the body assigns through it: a
    /// pointer receiver is the caller's own storage exactly as a parameter is.
    pub(super) receiver: Option<String>,
    pub(super) writes_receiver: bool,
    /// The calls in this body that hand a parameter or the receiver on, so the
    /// writes a callee performs are attributed to the caller too.
    escapes: Vec<EscapeSite>,
    /// The names a closure body assigns that it does not declare itself: the
    /// caller's own bindings it rebinds when it runs.
    pub(super) assigns_outer: BTreeSet<String>,
    /// Declared parameter, result, and receiver types as written (`Options`,
    /// `global.Options`). Assignment provenance for method dispatch.
    pub(super) types: HashMap<String, String>,
    pub(super) locals: HashSet<String>,
    pub(super) body: BlockStmt,
    pub(super) is_closure: bool,
    /// Two functions of this file each bound a different closure to this name.
    /// Closures are registered by the name they are bound to, so nothing here
    /// says which of them a call site names: the call resolves to neither.
    ambiguous: bool,
}

pub(super) fn is_str_lit(lit: &gosyn::ast::BasicLit) -> bool {
    lit.value.starts_with('"') || lit.value.starts_with('`')
}

pub(super) fn unquote(raw: &str) -> String {
    let s = raw.trim();
    if let Some(inner) = s.strip_prefix('`').and_then(|r| r.strip_suffix('`')) {
        return inner.to_string();
    }
    if let Some(inner) = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return inner
            .replace("\\\"", "\"")
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\\\", "\\");
    }
    s.to_string()
}

pub(super) fn collect_imports(file: &File) -> Imports {
    let mut out = HashMap::new();
    for imp in &file.imports {
        let path = unquote(&imp.path.value);
        let local = match &imp.name {
            Some(id) => id.name.clone(),
            None => {
                let mut parts = path.rsplit('/');
                let last = parts.next().unwrap_or(&path);
                if path.starts_with("gopkg.in/")
                    && let Some((package, version)) = last.rsplit_once(".v")
                    && !package.is_empty()
                    && !version.is_empty()
                    && version.chars().all(|c| c.is_ascii_digit())
                {
                    package.to_string()
                } else if last.strip_prefix('v').is_some_and(|version| {
                    !version.is_empty() && version.chars().all(|c| c.is_ascii_digit())
                }) {
                    parts.next().unwrap_or(last).to_string()
                } else {
                    last.to_string()
                }
            }
        };
        // `_`/`.` imports do not bind a usable qualifier for our purposes.
        if local != "_" && local != "." {
            out.insert(local, path);
        }
    }
    out
}

pub(super) fn collect_funcs(file: &File) -> HashMap<String, GoFunc> {
    let mut out = HashMap::new();
    let mut init_ordinal = 0;
    for decl in &file.decl {
        if let Declaration::Function(fd) = decl {
            let Some(body) = &fd.body else { continue };
            let params: Vec<String> = fd
                .typ
                .params
                .list
                .iter()
                .flat_map(|field| field.name.iter().map(|id| id.name.clone()))
                .collect();
            let mut types = field_types(&fd.typ.params);
            types.extend(field_types(&fd.typ.result));
            let constraints = generic_constraints(&fd.typ);
            for typ in types.values_mut() {
                if let Some(constraint) = constraints.get(typ) {
                    *typ = constraint.clone();
                }
            }
            let mut locals = field_names(&fd.typ.params);
            locals.extend(field_names(&fd.typ.result));
            // Methods key as `Type.Method` (the receiver type's base
            // identifier) — the form instance dispatch resolves at composition
            // time. A bare call can never reach them.
            let key = match &fd.recv {
                Some(recv) => {
                    types.extend(field_types(recv));
                    locals.extend(field_names(recv));
                    let Some(typ) = recv.list.first().and_then(|f| base_type_ident(&f.typ)) else {
                        continue;
                    };
                    format!("{typ}.{}", fd.name.name)
                }
                None if fd.name.name == "init" => {
                    let key = format!("init#{init_ordinal}");
                    init_ordinal += 1;
                    key
                }
                None => fd.name.name.clone(),
            };
            let receiver = fd
                .recv
                .as_ref()
                .and_then(|recv| recv.list.first())
                .and_then(|field| field.name.first())
                .map(|id| id.name.clone());
            let mut handed = handed_field_names(&fd.typ.params);
            if let Some(recv) = &fd.recv {
                handed.extend(handed_field_names(recv));
            }
            let writes = body_writes(body, &params, receiver.as_deref(), &handed);
            out.entry(key).or_insert(GoFunc {
                params,
                writes_through: writes.through,
                writes_receiver: writes.receiver,
                escapes: writes.escapes,
                receiver,
                assigns_outer: BTreeSet::new(),
                types,
                locals,
                body: body.clone(),
                is_closure: false,
                ambiguous: false,
            });
        }
    }
    // Function literals bound to locals (`dial := func() {...}`) act as named
    // functions: a later `dial()` resolves like any local call. Top-level
    // functions were collected first, so they win name collisions.
    for decl in &file.decl {
        match decl {
            Declaration::Function(fd) => {
                if let Some(body) = &fd.body {
                    collect_closures(body, &mut out);
                }
            }
            Declaration::Variable(variable) => {
                for value in variable.specs.iter().flat_map(|spec| &spec.values) {
                    if let Expression::FuncLit(literal) = value {
                        register_func_literal(literal, &mut out);
                    }
                    collect_func_literals(value, &mut out);
                }
            }
            _ => {}
        }
    }
    resolve_escaping_writes(&mut out);
    out
}

pub(super) fn declared_callable_names(file: &File, funcs: &HashMap<String, GoFunc>) -> Vec<String> {
    let mut names = Vec::new();
    for declaration in &file.decl {
        let Declaration::Function(function) = declaration else {
            continue;
        };
        if function.body.is_none() {
            continue;
        }
        let name = match &function.recv {
            Some(receiver) => receiver
                .list
                .first()
                .and_then(|field| base_type_ident(&field.typ))
                .map(|owner| format!("{owner}.{}", function.name.name)),
            None => Some(function.name.name.clone()),
        };
        if let Some(name) = name
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    let mut remaining: Vec<String> = funcs
        .keys()
        .filter(|name| !names.contains(*name))
        .cloned()
        .collect();
    remaining.sort();
    names.extend(remaining);
    names
}

/// Follow the storage a function hands on: a parameter or receiver passed to a
/// callee that writes through that position is written by the caller too, so a
/// forwarded pointer costs the original caller its exact view. Iterated to a
/// fixpoint because forwarding chains through several functions.
fn resolve_escaping_writes(funcs: &mut HashMap<String, GoFunc>) {
    let sites: Vec<(String, Vec<EscapeSite>)> = funcs
        .iter()
        .filter(|(_, function)| !function.escapes.is_empty())
        .map(|(key, function)| (key.clone(), function.escapes.clone()))
        .collect();
    loop {
        let mut writes: Vec<(String, String)> = Vec::new();
        for (caller, sites) in &sites {
            for site in sites {
                let target = escape_target(funcs, caller, site).and_then(|key| funcs.get(&key));
                for (index, name) in &site.handed {
                    let written = match target {
                        Some(function) => {
                            function.writes_through.get(*index).copied().unwrap_or(true)
                        }
                        // A callee this file cannot read may write any of them.
                        None => true,
                    };
                    if written {
                        writes.push((caller.clone(), name.clone()));
                    }
                }
                if let Some(name) = &site.receiver
                    && target.is_none_or(|function| function.writes_receiver)
                {
                    writes.push((caller.clone(), name.clone()));
                }
            }
        }
        let mut changed = false;
        for (caller, name) in writes {
            let Some(function) = funcs.get_mut(&caller) else {
                continue;
            };
            if let Some(index) = function.params.iter().position(|param| *param == name)
                && !function.writes_through[index]
            {
                function.writes_through[index] = true;
                changed = true;
            }
            if function.receiver.as_deref() == Some(name.as_str()) && !function.writes_receiver {
                function.writes_receiver = true;
                changed = true;
            }
        }
        if !changed {
            return;
        }
    }
}

/// The function a bare name reaches, when the file binds exactly one body to
/// it. A name two closures share names neither.
pub(super) fn unambiguous<'a>(
    funcs: &'a HashMap<String, GoFunc>,
    name: &str,
) -> Option<&'a GoFunc> {
    funcs.get(name).filter(|function| !function.ambiguous)
}

/// The key of the function a call site names, when this file declares it: a
/// plain name, or a method resolved through the receiver's declared type.
fn escape_target(
    funcs: &HashMap<String, GoFunc>,
    caller: &str,
    site: &EscapeSite,
) -> Option<String> {
    match site.callee.as_ref()? {
        // A parameter, a result, or a name the body declares shadows every
        // package function of that name, so `run(c, apply)` calls the value it
        // was handed, not the sibling `apply`, whose write behaviour says
        // nothing about it. A shadowing name resolves only to a closure bound
        // to it: `apply := func(...)` beside a package `apply` leaves the
        // package function registered under the name.
        CalleeName::Func(name) => (!funcs
            .get(caller)
            .is_some_and(|function| function.locals.contains(name))
            && unambiguous(funcs, name)
                .is_some_and(|function| !site.callee_local || function.is_closure))
        .then(|| name.clone()),
        CalleeName::Method { recv, method } => {
            let typ = funcs.get(caller)?.types.get(recv)?;
            let base = typ.rsplit('.').next().unwrap_or(typ.as_str());
            let key = format!("{base}.{method}");
            funcs.contains_key(&key).then_some(key)
        }
    }
}

pub(super) fn init_names(file: &File) -> Vec<String> {
    let count = file
        .decl
        .iter()
        .filter(|decl| {
            matches!(decl, Declaration::Function(fd) if fd.recv.is_none() && fd.name.name == "init")
        })
        .count();
    (0..count).map(|index| format!("init#{index}")).collect()
}

/// Register `name := func(...) {...}` / `var name = func(...) {...}` bindings
/// in `block` (nested blocks and closure bodies included) as callable
/// functions.
fn collect_closures(block: &BlockStmt, out: &mut HashMap<String, GoFunc>) {
    for stmt in &block.list {
        closure_stmt(stmt, out);
    }
}

fn closure_stmt(stmt: &Statement, out: &mut HashMap<String, GoFunc>) {
    fn bind(
        name: Option<&gosyn::ast::Ident>,
        value: &Expression,
        out: &mut HashMap<String, GoFunc>,
    ) {
        if let (Some(id), Expression::FuncLit(fl)) = (name, value) {
            let params: Vec<String> = fl
                .typ
                .params
                .list
                .iter()
                .flat_map(|field| field.name.iter().map(|i| i.name.clone()))
                .collect();
            let locals = function_locals(&fl.typ);
            let writes = body_writes(&fl.body, &params, None, &handed_field_names(&fl.typ.params));
            match out.entry(id.name.clone()) {
                std::collections::hash_map::Entry::Occupied(mut existing) => {
                    // A top-level function keeps the name (it was collected
                    // first and wins); a second closure under it makes the name
                    // say nothing about which body a call site reaches.
                    let held = existing.get_mut();
                    if held.is_closure && held.body.pos != fl.body.pos {
                        held.ambiguous = true;
                    }
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(GoFunc {
                        writes_through: writes.through,
                        writes_receiver: false,
                        escapes: writes.escapes,
                        receiver: None,
                        assigns_outer: assigned_outer_names(&fl.body, locals.clone()),
                        params,
                        types: function_types(&fl.typ),
                        locals,
                        body: fl.body.clone(),
                        is_closure: true,
                        ambiguous: false,
                    });
                }
            }
            collect_closures(&fl.body, out);
        }
    }
    match stmt {
        Statement::Assign(a) => {
            for (l, r) in a.left.iter().zip(&a.right) {
                let name = match l {
                    Expression::Ident(id) => Some(id),
                    _ => None,
                };
                bind(name, r, out);
                collect_func_literals(r, out);
            }
        }
        Statement::Declaration(DeclStmt::Variable(d)) => {
            for spec in &d.specs {
                for (id, value) in spec.name.iter().zip(&spec.values) {
                    bind(Some(id), value, out);
                    collect_func_literals(value, out);
                }
            }
        }
        Statement::If(i) => {
            collect_closures(&i.body, out);
            if let Some(e) = &i.else_ {
                closure_stmt(e, out);
            }
        }
        Statement::For(f) => collect_closures(&f.body, out),
        Statement::Range(r) => {
            collect_func_literals(&r.expr, out);
            collect_closures(&r.body, out);
        }
        Statement::Block(b) => collect_closures(b, out),
        Statement::Expr(expr) => collect_func_literals(&expr.expr, out),
        Statement::Return(ret) => {
            for expr in &ret.ret {
                // `return func() {...}`: the caller receives the literal
                // itself, so it needs the callable identity `value_of` gives
                // it to be entered where the returned value is called.
                if let Expression::FuncLit(literal) = expr {
                    register_func_literal(literal, out);
                }
                collect_func_literals(expr, out);
            }
        }
        Statement::Switch(s) => {
            for clause in &s.block.body {
                for st in clause.body.iter() {
                    closure_stmt(st, out);
                }
            }
        }
        _ => {}
    }
}

pub(super) fn literal_function_name(literal: &FuncLit) -> String {
    format!("func#{}", literal.typ.pos)
}

fn register_func_literal(literal: &FuncLit, out: &mut HashMap<String, GoFunc>) {
    let name = literal_function_name(literal);
    let params: Vec<String> = literal
        .typ
        .params
        .list
        .iter()
        .flat_map(|field| field.name.iter().map(|id| id.name.clone()))
        .collect();
    let locals = function_locals(&literal.typ);
    let writes = body_writes(
        &literal.body,
        &params,
        None,
        &handed_field_names(&literal.typ.params),
    );
    let assigns_outer = assigned_outer_names(&literal.body, locals.clone());
    out.entry(name).or_insert(GoFunc {
        params,
        writes_through: writes.through,
        writes_receiver: false,
        escapes: writes.escapes,
        receiver: None,
        assigns_outer,
        types: function_types(&literal.typ),
        locals,
        body: literal.body.clone(),
        is_closure: true,
        ambiguous: false,
    });
    collect_closures(&literal.body, out);
}

fn collect_func_literals(expr: &Expression, out: &mut HashMap<String, GoFunc>) {
    match expr {
        Expression::FuncLit(literal) => register_func_literal(literal, out),
        Expression::Paren(paren) => collect_func_literals(&paren.expr, out),
        Expression::Operation(operation) => {
            collect_func_literals(&operation.x, out);
            if let Some(right) = &operation.y {
                collect_func_literals(right, out);
            }
        }
        Expression::Star(star) => collect_func_literals(&star.right, out),
        Expression::Call(call) => {
            collect_func_literals(&call.func, out);
            for arg in &call.args {
                collect_func_literals(arg, out);
            }
        }
        Expression::Selector(selector) => collect_func_literals(&selector.x, out),
        Expression::Index(index) => {
            collect_func_literals(&index.left, out);
            collect_func_literals(&index.index, out);
        }
        Expression::IndexList(index) => {
            collect_func_literals(&index.left, out);
            for argument in &index.indices {
                collect_func_literals(argument, out);
            }
        }
        Expression::CompositeLit(literal) => collect_literal_func_literals(&literal.val, out, 0),
        _ => {}
    }
}

pub(super) fn is_callback_field(name: &str) -> bool {
    matches!(
        name,
        "Run"
            | "RunE"
            | "PreRun"
            | "PreRunE"
            | "PostRun"
            | "PostRunE"
            | "PersistentPreRun"
            | "PersistentPreRunE"
            | "PersistentPostRun"
            | "PersistentPostRunE"
            | "Action"
    )
}

fn collect_literal_func_literals(
    literal: &gosyn::ast::LiteralValue,
    out: &mut HashMap<String, GoFunc>,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    for element in &literal.values {
        let callback = matches!(
            element.key.as_ref(),
            Some(Element::Expr(Expression::Ident(id))) if is_callback_field(&id.name)
        );
        match &element.val {
            Element::Expr(Expression::FuncLit(literal)) if callback => {
                register_func_literal(literal, out);
            }
            Element::Expr(Expression::CompositeLit(nested)) => {
                collect_literal_func_literals(&nested.val, out, depth + 1)
            }
            Element::Expr(value) => collect_func_literals(value, out),
            Element::LitValue(nested) => collect_literal_func_literals(nested, out, depth + 1),
        }
    }
}

/// The base identifier of a (possibly pointer/generic) type expression:
/// `*writeInPlaceHandlerImpl` -> `writeInPlaceHandlerImpl`.
fn base_type_ident(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Ident(id) => Some(id.name.clone()),
        Expression::Star(s) => base_type_ident(&s.right),
        Expression::TypePointer(p) => base_type_ident(&p.typ),
        Expression::Operation(op) if op.y.is_none() => base_type_ident(&op.x),
        Expression::Paren(p) => base_type_ident(&p.expr),
        Expression::Index(i) => base_type_ident(&i.left),
        Expression::IndexList(i) => base_type_ident(&i.left),
        _ => None,
    }
}

/// A named type as written, preserving a package qualifier:
/// `*global.Options` -> `global.Options`. Pointers unwrap; anything else is
/// unknown (slices, maps, function types).
pub(super) fn named_type(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Ident(id) => Some(id.name.clone()),
        Expression::Selector(sel) => match &*sel.x {
            Expression::Ident(pkg) => Some(format!("{}.{}", pkg.name, sel.sel.name)),
            _ => None,
        },
        Expression::Star(s) => named_type(&s.right),
        Expression::TypePointer(p) => named_type(&p.typ),
        Expression::Operation(op) if op.y.is_none() => named_type(&op.x),
        Expression::Paren(p) => named_type(&p.expr),
        Expression::Index(index) => named_type(&index.left),
        Expression::IndexList(index) => named_type(&index.left),
        _ => None,
    }
}

/// Parameter / receiver names to their declared named types.
pub(super) fn field_types(fields: &gosyn::ast::FieldList) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for field in &fields.list {
        let Some(typ) = named_type(&field.typ) else {
            continue;
        };
        for id in &field.name {
            out.insert(id.name.clone(), typ.clone());
        }
    }
    out
}

/// Parameter and receiver names declared with a type Go passes by reference —
/// a pointer, a slice, a map — through which a body writes the caller's own
/// storage.
fn handed_field_names(fields: &gosyn::ast::FieldList) -> HashSet<String> {
    fields
        .list
        .iter()
        .filter(|field| passed_by_reference(&field.typ))
        .flat_map(|field| field.name.iter().map(|id| id.name.clone()))
        .collect()
}

fn passed_by_reference(typ: &Expression) -> bool {
    match typ {
        Expression::TypePointer(_)
        | Expression::Star(_)
        | Expression::TypeSlice(_)
        | Expression::TypeMap(_) => true,
        Expression::Paren(paren) => passed_by_reference(&paren.expr),
        Expression::Operation(operation) if operation.y.is_none() => operation.op == Operator::Star,
        _ => false,
    }
}

fn field_names(fields: &gosyn::ast::FieldList) -> HashSet<String> {
    fields
        .list
        .iter()
        .flat_map(|field| field.name.iter().map(|id| id.name.clone()))
        .collect()
}

fn function_types(typ: &gosyn::ast::FuncType) -> HashMap<String, String> {
    let mut types = field_types(&typ.params);
    types.extend(field_types(&typ.result));
    let constraints = generic_constraints(typ);
    for value in types.values_mut() {
        if let Some(constraint) = constraints.get(value) {
            *value = constraint.clone();
        }
    }
    types
}

fn generic_constraints(typ: &gosyn::ast::FuncType) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for field in &typ.typ_params.list {
        let Some(constraint) = named_type(&field.typ) else {
            continue;
        };
        for name in &field.name {
            out.insert(name.name.clone(), constraint.clone());
        }
    }
    out
}

pub(super) fn function_locals(typ: &gosyn::ast::FuncType) -> HashSet<String> {
    let mut locals = field_names(&typ.params);
    locals.extend(field_names(&typ.result));
    locals
}

/// Types declared in the file, exposed as classes so composition can dispatch
/// `Type.Method` through constructor-typed receivers.
fn collect_classes(file: &File) -> Vec<ClassEntry> {
    let mut out = Vec::new();
    for decl in &file.decl {
        if let Declaration::Type(d) = decl {
            for spec in &d.specs {
                let structure = match &spec.typ {
                    Expression::TypeStruct(structure) => Some(structure),
                    _ => None,
                };
                let attr_params = structure
                    .into_iter()
                    .flat_map(|structure| &structure.fields)
                    .flat_map(|field| {
                        field
                            .name
                            .iter()
                            .map(|name| (name.name.clone(), name.name.clone()))
                    })
                    .collect();
                let struct_fields = structure
                    .into_iter()
                    .flat_map(|structure| &structure.fields)
                    .filter_map(|field| {
                        let typ = named_type(&field.typ)?;
                        let tags = field
                            .tag
                            .as_ref()
                            .map(|tag| struct_tag_keys(&tag.value))
                            .unwrap_or_default();
                        Some(field.name.iter().map(move |name| StructField {
                            name: name.name.clone(),
                            typ: typ.clone(),
                            tags: tags.clone(),
                        }))
                    })
                    .flatten()
                    .collect();
                out.push(ClassEntry {
                    name: spec.name.name.clone(),
                    is_struct: structure.is_some(),
                    struct_fields,
                    attr_params,
                    ..Default::default()
                });
            }
        }
    }
    out
}

fn struct_tag_keys(raw: &str) -> Vec<String> {
    let tag = unquote(raw);
    let bytes = tag.as_bytes();
    let mut keys = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b':'
            && bytes[index] != b'"'
        {
            index += 1;
        }
        if start == index || bytes.get(index) != Some(&b':') || bytes.get(index + 1) != Some(&b'"')
        {
            break;
        }
        keys.push(tag[start..index].to_string());
        index += 2;
        while index < bytes.len() {
            match bytes[index] {
                b'\\' => index = (index + 2).min(bytes.len()),
                b'"' => {
                    index += 1;
                    break;
                }
                _ => index += 1,
            }
        }
    }
    keys
}

pub(super) fn declared_type_names(file: &File) -> HashSet<String> {
    collect_classes(file)
        .into_iter()
        .map(|class| class.name)
        .collect()
}

pub(super) fn named_type_ref(
    imports: &Imports,
    repo_types: &HashSet<String>,
    fact_file: &str,
    typ: &str,
) -> Option<TypeRef> {
    match typ.split_once('.') {
        Some((pkg, name)) => imports.get(pkg).map(|path| TypeRef::External {
            path: format!("{path}.{name}"),
        }),
        None if repo_types.contains(typ) => Some(TypeRef::Repo {
            file: fact_file.to_string(),
            name: typ.to_string(),
        }),
        None => None,
    }
}

pub(super) fn go_dispatch_contracts(
    file: &File,
    imports: &Imports,
    package: &str,
) -> Vec<DispatchContract> {
    let mut contracts = Vec::new();
    for decl in &file.decl {
        let Declaration::Type(decl) = decl else {
            continue;
        };
        for spec in &decl.specs {
            let Expression::TypeInterface(interface) = &spec.typ else {
                continue;
            };
            let mut methods: Vec<_> = interface
                .methods
                .list
                .iter()
                .filter_map(|field| field.name.first().map(|name| name.name.clone()))
                .collect();
            let mut method_signatures: Vec<_> = interface
                .methods
                .list
                .iter()
                .filter_map(|field| {
                    let name = field.name.first()?.name.clone();
                    let Expression::TypeFunction(function) = &field.typ else {
                        return None;
                    };
                    go_dispatch_signature(function, imports, package)
                        .map(|signature| (name, signature))
                })
                .collect();
            methods.sort();
            methods.dedup();
            method_signatures.sort_by(|a, b| a.0.cmp(&b.0));
            method_signatures.dedup();
            if !methods.is_empty() {
                contracts.push(DispatchContract {
                    name: spec.name.name.clone(),
                    methods,
                    method_signatures,
                });
            }
        }
    }
    contracts.sort_by(|a, b| a.name.cmp(&b.name));
    contracts
}

fn go_dispatch_signatures(
    file: &File,
    imports: &Imports,
    package: &str,
) -> HashMap<String, DispatchSignature> {
    let mut signatures = HashMap::new();
    for decl in &file.decl {
        let Declaration::Function(function) = decl else {
            continue;
        };
        let Some(receiver) = &function.recv else {
            continue;
        };
        let Some(receiver) = receiver
            .list
            .first()
            .and_then(|field| base_type_ident(&field.typ))
        else {
            continue;
        };
        if let Some(signature) = go_dispatch_signature(&function.typ, imports, package) {
            signatures
                .entry(format!("{receiver}.{}", function.name.name))
                .or_insert(signature);
        }
    }
    signatures
}

fn go_return_types(
    file: &File,
    imports: &Imports,
    package: &str,
    fact_file: &str,
) -> HashMap<String, Vec<Option<TypeRef>>> {
    let mut out = HashMap::new();
    let mut init_ordinal = 0;
    for declaration in &file.decl {
        let Declaration::Function(function) = declaration else {
            continue;
        };
        let key = match &function.recv {
            Some(receiver) => {
                let Some(receiver) = receiver
                    .list
                    .first()
                    .and_then(|field| base_type_ident(&field.typ))
                else {
                    continue;
                };
                format!("{receiver}.{}", function.name.name)
            }
            None if function.name.name == "init" => {
                let key = format!("init#{init_ordinal}");
                init_ordinal += 1;
                key
            }
            None => function.name.name.clone(),
        };
        let Some(types) = go_signature_fields(&function.typ.result, imports, package) else {
            continue;
        };
        out.insert(
            key,
            types
                .into_iter()
                .map(|typ| {
                    let typ = typ.trim_start_matches('*');
                    let (owner, name) = typ.rsplit_once('.')?;
                    if owner == package {
                        Some(TypeRef::Repo {
                            file: fact_file.to_string(),
                            name: name.to_string(),
                        })
                    } else if owner.contains('/') {
                        Some(TypeRef::External {
                            path: typ.to_string(),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        );
    }
    out
}

fn go_dispatch_signature(
    function: &gosyn::ast::FuncType,
    imports: &Imports,
    package: &str,
) -> Option<DispatchSignature> {
    Some(DispatchSignature {
        params: go_signature_fields(&function.params, imports, package)?,
        results: go_signature_fields(&function.result, imports, package)?,
    })
}

fn go_signature_fields(
    fields: &gosyn::ast::FieldList,
    imports: &Imports,
    package: &str,
) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for field in &fields.list {
        let typ = go_signature_type(&field.typ, imports, package)?;
        for _ in 0..field.name.len().max(1) {
            out.push(typ.clone());
        }
    }
    Some(out)
}

fn go_signature_type(expr: &Expression, imports: &Imports, package: &str) -> Option<String> {
    match expr {
        Expression::Ident(ident) => Some(match ident.name.as_str() {
            "any" => "interface{}".to_string(),
            "byte" => "uint8".to_string(),
            "rune" => "int32".to_string(),
            "bool" | "complex64" | "complex128" | "error" | "float32" | "float64" | "int"
            | "int8" | "int16" | "int32" | "int64" | "string" | "uint" | "uint8" | "uint16"
            | "uint32" | "uint64" | "uintptr" => ident.name.clone(),
            _ => format!("{package}.{}", ident.name),
        }),
        Expression::Selector(selector) => {
            if let Expression::Ident(head) = &*selector.x
                && let Some(module) = imports.get(&head.name)
            {
                return Some(format!("{module}.{}", selector.sel.name));
            }
            Some(format!(
                "{}.{}",
                go_signature_type(&selector.x, imports, package)?,
                selector.sel.name
            ))
        }
        Expression::Star(star) => Some(format!(
            "*{}",
            go_signature_type(&star.right, imports, package)?
        )),
        Expression::TypePointer(pointer) => Some(format!(
            "*{}",
            go_signature_type(&pointer.typ, imports, package)?
        )),
        Expression::Paren(paren) => go_signature_type(&paren.expr, imports, package),
        Expression::Ellipsis(ellipsis) => Some(format!(
            "...{}",
            go_signature_type(ellipsis.elt.as_deref()?, imports, package)?
        )),
        Expression::TypeSlice(slice) => Some(format!(
            "[]{}",
            go_signature_type(&slice.typ, imports, package)?
        )),
        Expression::TypeArray(array) => Some(format!(
            "[{}]{}",
            go_signature_constant(&array.len, imports, package)?,
            go_signature_type(&array.typ, imports, package)?
        )),
        Expression::TypeMap(map) => Some(format!(
            "map[{}]{}",
            go_signature_type(&map.key, imports, package)?,
            go_signature_type(&map.val, imports, package)?
        )),
        Expression::TypeFunction(function) => {
            let signature = go_dispatch_signature(function, imports, package)?;
            Some(format!(
                "func({})({})",
                signature.params.join(","),
                signature.results.join(",")
            ))
        }
        Expression::TypeChannel(channel) => {
            let direction = match channel.dir {
                None => "chan ",
                Some(gosyn::ast::ChanMode::Recv) => "<-chan ",
                Some(gosyn::ast::ChanMode::Send) => "chan<- ",
            };
            Some(format!(
                "{direction}{}",
                go_signature_type(&channel.typ, imports, package)?
            ))
        }
        Expression::TypeInterface(interface) if interface.methods.list.is_empty() => {
            Some("interface{}".to_string())
        }
        Expression::Index(index) => Some(format!(
            "{}[{}]",
            go_signature_type(&index.left, imports, package)?,
            go_signature_type(&index.index, imports, package)?
        )),
        Expression::IndexList(index) => Some(format!(
            "{}[{}]",
            go_signature_type(&index.left, imports, package)?,
            index
                .indices
                .iter()
                .map(|item| go_signature_type(item, imports, package))
                .collect::<Option<Vec<_>>>()?
                .join(",")
        )),
        _ => None,
    }
}

fn go_dispatch_type_aliases(
    file: &File,
    imports: &Imports,
    package: &str,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for decl in &file.decl {
        let Declaration::Type(decl) = decl else {
            continue;
        };
        for spec in &decl.specs {
            if spec.alias
                && spec.params.list.is_empty()
                && let Some(target) = go_signature_type(&spec.typ, imports, package)
            {
                out.push((format!("{package}.{}", spec.name.name), target));
            }
        }
    }
    out.sort();
    out
}

fn go_signature_constant(expr: &Expression, imports: &Imports, package: &str) -> Option<String> {
    match expr {
        Expression::BasicLit(literal) => Some(literal.value.clone()),
        Expression::Ident(_) | Expression::Selector(_) => go_signature_type(expr, imports, package),
        _ => None,
    }
}

/// The class a returned expression unambiguously constructs: `&Type{...}` /
/// `Type{...}` (also `pkg.Type{...}`, as written).
pub(super) fn constructed_class(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Paren(p) => constructed_class(&p.expr),
        Expression::Operation(op) if op.y.is_none() => constructed_class(&op.x),
        Expression::CompositeLit(cl) => match &*cl.typ {
            Expression::Ident(id) => Some(id.name.clone()),
            Expression::Selector(sel) => match &*sel.x {
                Expression::Ident(pkg) => Some(format!("{}.{}", pkg.name, sel.sel.name)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// The type `new(T)` allocates. Go's predeclared `new` takes exactly one
/// argument and that argument is the type name a method call dispatches on.
pub(super) fn allocated_class(func: &Expression, args: &[Expression]) -> Option<String> {
    let Expression::Ident(name) = func else {
        return None;
    };
    if name.name != "new" || args.len() != 1 {
        return None;
    }
    match &args[0] {
        Expression::Ident(typ) => Some(typ.name.clone()),
        Expression::Selector(sel) => match &*sel.x {
            Expression::Ident(pkg) => Some(format!("{}.{}", pkg.name, sel.sel.name)),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn construction_site(expr: &Expression) -> Option<((usize, usize), String)> {
    match expr {
        Expression::Paren(p) => construction_site(&p.expr),
        Expression::Operation(op) if op.y.is_none() => construction_site(&op.x),
        Expression::Star(star) => construction_site(&star.right),
        Expression::CompositeLit(literal) => Some((literal.val.pos, constructed_class(expr)?)),
        _ => None,
    }
}

/// Per-return-tuple-index constructed classes, when every `return` in the body
/// (closures excluded) agrees. Empty when nothing is unambiguously constructed.
pub(super) fn returns_instances(body: &BlockStmt) -> Vec<Option<String>> {
    fn visit(block: &BlockStmt, merged: &mut Option<Vec<Option<String>>>) {
        for stmt in &block.list {
            visit_stmt(stmt, merged);
        }
    }
    fn visit_stmt(stmt: &Statement, merged: &mut Option<Vec<Option<String>>>) {
        match stmt {
            Statement::Return(r) => {
                let classes: Vec<Option<String>> = r.ret.iter().map(constructed_class).collect();
                match merged {
                    None => *merged = Some(classes),
                    Some(prev) => {
                        if prev.len() != classes.len() {
                            prev.clear();
                        } else {
                            for (p, c) in prev.iter_mut().zip(classes) {
                                if *p != c {
                                    *p = None;
                                }
                            }
                        }
                    }
                }
            }
            Statement::If(i) => {
                visit(&i.body, merged);
                if let Some(e) = &i.else_ {
                    visit_stmt(e, merged);
                }
            }
            Statement::For(f) => visit(&f.body, merged),
            Statement::Range(r) => visit(&r.body, merged),
            Statement::Block(b) => visit(b, merged),
            Statement::Switch(s) => {
                for clause in &s.block.body {
                    for st in clause.body.iter() {
                        visit_stmt(st, merged);
                    }
                }
            }
            _ => {}
        }
    }
    let mut merged = None;
    visit(body, &mut merged);
    let out = merged.unwrap_or_default();
    if out.iter().all(Option::is_none) {
        Vec::new()
    } else {
        out
    }
}

/// Per-return-tuple-index local name when every return agrees.
fn return_bindings(body: &BlockStmt) -> Vec<Option<String>> {
    #[derive(Clone)]
    enum Binding {
        Unseen,
        Named(String),
        Ambiguous,
    }

    fn visit(block: &BlockStmt, merged: &mut Option<Vec<Binding>>) {
        for stmt in &block.list {
            visit_stmt(stmt, merged);
        }
    }
    fn visit_stmt(stmt: &Statement, merged: &mut Option<Vec<Binding>>) {
        match stmt {
            Statement::Return(r) => {
                let prev = merged.get_or_insert_with(|| vec![Binding::Unseen; r.ret.len()]);
                if prev.len() != r.ret.len() {
                    prev.clear();
                    return;
                }
                for (old, expr) in prev.iter_mut().zip(&r.ret) {
                    let Expression::Ident(id) = expr else {
                        *old = Binding::Ambiguous;
                        continue;
                    };
                    if id.name == "nil" {
                        continue;
                    }
                    match old {
                        Binding::Unseen => *old = Binding::Named(id.name.clone()),
                        Binding::Named(name) if *name == id.name => {}
                        Binding::Named(_) | Binding::Ambiguous => {
                            *old = Binding::Ambiguous;
                        }
                    }
                }
            }
            Statement::If(i) => {
                visit(&i.body, merged);
                if let Some(e) = &i.else_ {
                    visit_stmt(e, merged);
                }
            }
            Statement::For(f) => visit(&f.body, merged),
            Statement::Range(r) => visit(&r.body, merged),
            Statement::Block(b) => visit(b, merged),
            Statement::Switch(s) => {
                for clause in &s.block.body {
                    for statement in clause.body.iter() {
                        visit_stmt(statement, merged);
                    }
                }
            }
            _ => {}
        }
    }

    let mut merged = None;
    visit(body, &mut merged);
    let result: Vec<Option<String>> = merged
        .unwrap_or_default()
        .into_iter()
        .map(|binding| match binding {
            Binding::Named(name) => Some(name),
            Binding::Unseen | Binding::Ambiguous => None,
        })
        .collect();
    if result.iter().all(Option::is_none) {
        Vec::new()
    } else {
        result
    }
}

fn extract_import_bindings(imports: &Imports) -> Vec<ImportBinding> {
    imports
        .iter()
        .map(|(local, path)| ImportBinding {
            local: local.clone(),
            module: path.clone(),
            imported: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Summary inference (parameterized effects, local calls inlined)

#[allow(clippy::too_many_arguments)]
pub(super) fn compute_summaries(
    source: &str,
    imports: &Imports,
    funcs: &HashMap<String, GoFunc>,
    dispatch_contracts: &[DispatchContract],
    package_file: Option<&File>,
    fact_file: &str,
    fact_scope: Option<&ScopeKey>,
    mut analysis_budget: Option<(&mut PlanBuilder, &crate::nest::Budget)>,
    value_limits: crate::ValueLimits,
) -> HashMap<String, Summary> {
    let condition_source = effinterp_proto::ConditionSource::new(source);
    let mut summaries: HashMap<String, Summary> =
        funcs.keys().map(|n| (n.clone(), Summary::pure())).collect();
    let mut ordered_funcs: Vec<_> = funcs.iter().collect();
    ordered_funcs.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    for _ in 0..MAX_SUMMARY_ITERS {
        let mut next = summaries.clone();
        let mut changed = false;
        for &(name, f) in &ordered_funcs {
            let _walk = crate::limits::summary_walk();
            let param_env: HashMap<String, ResourceExpr> = f
                .params
                .iter()
                .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
                .collect();
            let mut cap = Capture::default();
            let mut w = Walker {
                value_limits,
                source,
                condition_source: &condition_source,
                conditions: Vec::new(),
                out: Out::Capture(&mut cap),
                analysis_budget: analysis_budget
                    .as_mut()
                    .map(|(builder, budget)| (&mut **builder, *budget)),
                imports,
                funcs,
                summaries: &summaries,
                params: param_env,
                local_types: f.types.clone(),
                dispatch_contracts,
                scope: None,
                following: HashSet::from([name.clone()]),
                entered_callables: HashSet::new(),
                callback_roots: BTreeSet::new(),
                struct_fields: package_file.map(struct_field_types).unwrap_or_default(),
                package_constants: HashMap::new(),
                package_types: HashMap::new(),
                collect_edges: false,
                capture_external_effects: false,
                binds_next_call: Vec::new(),
                current_binds: Vec::new(),
                nodes: 0,
                max_nodes: crate::limits::invocation_node_limit(DEFAULT_MAX_GO_NODES),
                walk_depth: 0,
                truncated: false,
                fact_file: fact_file.to_string(),
                fact_scope: fact_scope.cloned(),
                fact_function: name.clone(),
                repo_types: package_file.map(declared_type_names).unwrap_or_default(),
                site_ordinal: 0,
                package_vars: HashSet::new(),
                local_origins: HashMap::new(),
                instance_aliases: HashMap::new(),
                construction_origins: HashMap::new(),
                bound_vars: HashSet::new(),
                local_vars: f.locals.clone(),
                channel_values: f
                    .params
                    .iter()
                    .map(|name| {
                        (
                            name.clone(),
                            ResourceExpr::Unresolved {
                                family: ResourceFamily::new("filesystem"),
                            },
                        )
                    })
                    .collect(),
                resource_values: HashMap::new(),
                values: f
                    .params
                    .iter()
                    .map(|name| (name.clone(), SemanticValue::parameter(name)))
                    .collect(),
                local_scopes: Vec::new(),
                pending_writes: Vec::new(),
                address_aliases: HashMap::new(),
                reassigned_scopes: Vec::new(),
                aliased_scopes: Vec::new(),
                called_scopes: Vec::new(),
                escaped_scopes: Vec::new(),
                control_applications: Vec::new(),
            };
            if let Some(file) = package_file {
                w.bind_package_state(file, PackageValues::Constants);
            }
            w.control_enter(&f.body);
            w.walk_block(&f.body);
            w.control_leave();
            let returns =
                (!cap.returns.is_empty()).then(|| join_branches(cap.returns.clone(), value_limits));
            let summary = Summary {
                control_flow: cap.flow,
                params: f.params.clone(),
                effects: cap.effects,
                effect_models: Vec::new(),
                transfers: cap.transfers,
                returns,
                boundaries: cap.boundaries,
                coverage: cap.coverage,
            };
            if next.get(name) != Some(&summary) {
                changed = true;
            }
            next.insert(name.clone(), summary);
        }
        summaries = next;
        if !changed {
            break;
        }
    }
    summaries
}

#[allow(clippy::too_many_arguments)]
fn collect_call_edges(
    source: &str,
    imports: &Imports,
    funcs: &HashMap<String, GoFunc>,
    summaries: &HashMap<String, Summary>,
    func: &GoFunc,
    package_file: Option<&File>,
    fact_file: &str,
    fact_scope: &ScopeKey,
    fact_function: &str,
    value_limits: crate::ValueLimits,
) -> (Vec<CallEdge>, BTreeMap<crate::control_flow::Span, u32>) {
    let _walk = crate::limits::summary_walk();
    let param_env: HashMap<String, ResourceExpr> = func
        .params
        .iter()
        .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
        .collect();
    let mut cap = Capture::default();
    let condition_source = effinterp_proto::ConditionSource::new(source);
    let mut w = Walker {
        value_limits,
        source,
        condition_source: &condition_source,
        conditions: Vec::new(),
        out: Out::Capture(&mut cap),
        analysis_budget: None,
        imports,
        funcs,
        summaries,
        params: param_env,
        local_types: func.types.clone(),
        dispatch_contracts: &[],
        scope: None,
        following: HashSet::new(),
        entered_callables: HashSet::new(),
        callback_roots: BTreeSet::new(),
        struct_fields: package_file.map(struct_field_types).unwrap_or_default(),
        package_constants: HashMap::new(),
        package_types: HashMap::new(),
        collect_edges: true,
        capture_external_effects: false,
        binds_next_call: Vec::new(),
        current_binds: Vec::new(),
        nodes: 0,
        max_nodes: crate::limits::invocation_node_limit(DEFAULT_MAX_GO_NODES),
        walk_depth: 0,
        truncated: false,
        fact_file: fact_file.to_string(),
        fact_scope: Some(fact_scope.clone()),
        fact_function: fact_function.to_string(),
        repo_types: package_file.map(declared_type_names).unwrap_or_default(),
        site_ordinal: 0,
        package_vars: HashSet::new(),
        local_origins: HashMap::new(),
        instance_aliases: HashMap::new(),
        construction_origins: HashMap::new(),
        bound_vars: HashSet::new(),
        local_vars: func.locals.clone(),
        channel_values: func
            .params
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    ResourceExpr::Unresolved {
                        family: ResourceFamily::new("filesystem"),
                    },
                )
            })
            .collect(),
        resource_values: HashMap::new(),
        values: func
            .params
            .iter()
            .map(|name| (name.clone(), SemanticValue::parameter(name)))
            .collect(),
        local_scopes: Vec::new(),
        pending_writes: Vec::new(),
        address_aliases: HashMap::new(),
        reassigned_scopes: Vec::new(),
        aliased_scopes: Vec::new(),
        called_scopes: Vec::new(),
        escaped_scopes: Vec::new(),
        control_applications: Vec::new(),
    };
    // Package bindings provide receiver typing inside every function.
    if let Some(file) = package_file {
        w.bind_package_state(file, PackageValues::Constants);
    }
    w.walk_block(&func.body);
    (cap.edges, cap.call_sites)
}

#[allow(clippy::too_many_arguments)]
fn collect_package_initializers(
    source: &str,
    imports: &Imports,
    funcs: &HashMap<String, GoFunc>,
    summaries: &HashMap<String, Summary>,
    file: &File,
    fact_file: &str,
    fact_scope: &ScopeKey,
    value_limits: crate::ValueLimits,
) -> (Capture, BTreeMap<String, SemanticValue>) {
    let _walk = crate::limits::summary_walk();
    let mut cap = Capture::default();
    let limits = crate::AnalysisLimits::default();
    let imported: Vec<_> = file
        .imports
        .iter()
        .filter(|import| !crate::external::is_go_stdlib(&unquote(&import.path.value)))
        .collect();
    let import_spans: Vec<_> = imported
        .iter()
        .map(|import| control::import_span(import))
        .collect();
    let bodies: Vec<_> = init_names(file)
        .iter()
        .filter_map(|name| funcs.get(name).map(|f| &f.body))
        .collect();
    cap.control.enter(
        source,
        true,
        Default::default(),
        0,
        0,
        None,
        ControlCaps {
            nodes: limits.max_causal_nodes,
            work: limits.max_causal_pairs,
        },
        |graph| control::build_program(graph, file, &import_spans, &bodies),
    );
    for import in imported {
        cap.control.register(
            source,
            true,
            control::import_span(import),
            SiteFacts {
                exit: Some(ControlExit::Import {
                    module: unquote(&import.path.value),
                }),
                ..SiteFacts::known(Vec::new())
            },
        );
    }
    let condition_source = effinterp_proto::ConditionSource::new(source);
    let mut w = Walker {
        value_limits,
        source,
        condition_source: &condition_source,
        conditions: Vec::new(),
        out: Out::Capture(&mut cap),
        analysis_budget: None,
        imports,
        funcs,
        summaries,
        params: HashMap::new(),
        local_types: HashMap::new(),
        dispatch_contracts: &[],
        scope: None,
        following: HashSet::new(),
        entered_callables: HashSet::new(),
        callback_roots: BTreeSet::new(),
        struct_fields: struct_field_types(file),
        package_constants: HashMap::new(),
        package_types: HashMap::new(),
        collect_edges: true,
        capture_external_effects: true,
        binds_next_call: Vec::new(),
        current_binds: Vec::new(),
        nodes: 0,
        max_nodes: crate::limits::invocation_node_limit(DEFAULT_MAX_GO_NODES),
        walk_depth: 0,
        truncated: false,
        fact_file: fact_file.to_string(),
        fact_scope: Some(fact_scope.clone()),
        fact_function: String::new(),
        repo_types: declared_type_names(file),
        site_ordinal: 0,
        package_vars: HashSet::new(),
        local_origins: HashMap::new(),
        instance_aliases: HashMap::new(),
        construction_origins: HashMap::new(),
        bound_vars: HashSet::new(),
        local_vars: HashSet::new(),
        channel_values: HashMap::new(),
        resource_values: HashMap::new(),
        values: HashMap::new(),
        local_scopes: Vec::new(),
        pending_writes: Vec::new(),
        address_aliases: HashMap::new(),
        reassigned_scopes: Vec::new(),
        aliased_scopes: Vec::new(),
        called_scopes: Vec::new(),
        escaped_scopes: Vec::new(),
        control_applications: Vec::new(),
    };
    w.walk_var_initializers(file);
    let values = w
        .package_vars
        .iter()
        .filter_map(|name| {
            w.values
                .get(name)
                .cloned()
                .map(|value| (name.clone(), value))
        })
        .collect();
    drop(w);
    (cap, values)
}

/// The package-level `var` names this file declares. A `const` is not one:
/// Go forbids assigning it, so its declared value is the package's value.
pub(super) fn package_var_names(file: &File) -> Vec<String> {
    file.decl
        .iter()
        .filter_map(|decl| match decl {
            Declaration::Variable(variable) => Some(variable),
            _ => None,
        })
        .flat_map(|variable| &variable.specs)
        .flat_map(|spec| &spec.name)
        .map(|id| id.name.clone())
        .collect()
}

/// What one walk of a body collects: the names it assigns that it does not
/// declare itself, and the calls it hands one of those names to.
#[derive(Default)]
struct Rebinds {
    names: BTreeSet<String>,
    sites: Vec<EscapeSite>,
    /// A local name -> the caller storage it addresses. Seeded with the
    /// parameters and receiver that hand this body the caller's own storage,
    /// and extended by every copy of one (`q := p`), so a write through the
    /// copy is recorded as a write through the original.
    aliases: HashMap<String, String>,
    /// The handed names whose storage leaves this body for somewhere the
    /// analysis cannot follow it: returned, stored in a composite literal, sent
    /// on a channel, or assigned to a name that is not a fresh local. The
    /// caller keeps a live second name for that storage after the call, so its
    /// exact view of the binding is as stale as a write through it would make
    /// it.
    escaped: HashSet<String>,
}

/// A call that hands a binding of the enclosing function to a callee, so a
/// write the callee performs reaches the enclosing function's caller too.
#[derive(Clone)]
struct EscapeSite {
    /// The callee as this file spells it, or `None` for a shape no name
    /// describes (a call result, an element, a literal).
    callee: Option<CalleeName>,
    /// The callee name is one the enclosing body declares, so it shadows the
    /// package function of that name and only a closure bound to it describes
    /// what the call does.
    callee_local: bool,
    /// Argument position -> the outer name handed over there.
    handed: Vec<(usize, String)>,
    /// The outer name the call runs a method on.
    receiver: Option<String>,
}

#[derive(Clone)]
enum CalleeName {
    Func(String),
    Method { recv: String, method: String },
}

/// Package-level names this file assigns somewhere other than their
/// declaration, so composition never substitutes a rebound variable's
/// initializer as the package's exact value. A name the enclosing function
/// declares itself (parameter, receiver, `:=`, `var`) shadows the package
/// variable and is not recorded.
fn collect_package_rebindings(file: &File) -> BTreeSet<String> {
    let mut out = Rebinds::default();
    for decl in &file.decl {
        match decl {
            Declaration::Function(fd) => {
                let Some(body) = &fd.body else { continue };
                let mut scope = function_locals(&fd.typ);
                if let Some(recv) = &fd.recv {
                    scope.extend(field_names(recv));
                }
                let mut scopes = vec![scope];
                rebindings_block(body, &mut scopes, &mut out, 0);
            }
            // `var handler = func() { target = "..." }`: the literal runs
            // wherever the value is called, and assigns the package name.
            Declaration::Variable(variable) => {
                for value in variable.specs.iter().flat_map(|spec| &spec.values) {
                    rebindings_expr(value, &mut Vec::new(), &mut out, 0);
                }
            }
            _ => {}
        }
    }
    out.names
}

/// What the statements of a block write, without ordering any of it: the
/// names they assign to a binding that already exists, the storage their
/// pointers name, and the names the function literals among them assign.
///
/// A callable this walk cannot place in program order — a deferred body, a
/// goroutine — is walked without every name in `names`, because none of those
/// writes is ordered against the moment it runs. `aliases` and `copies` give
/// that widening the pointers of the whole block instead of only the ones
/// bound above the statement, so `q := &p` below a `defer` still costs `p` its
/// value.
///
/// A write need not be an assignment the block states: Go hands a callee the
/// caller's own storage, so `mutate(&p)` and a method assigning through a
/// pointer receiver write as surely as `*q = v` does. `calls` keeps the calls
/// themselves, because what one writes is a question about the callee's body
/// and the values the walk holds, not about the block's text.
#[derive(Default)]
pub(super) struct BlockWrites {
    pub(super) names: HashSet<String>,
    /// `(pointer, target)` of every `&x` the block binds to a name.
    aliases: Vec<(String, String)>,
    /// `(destination, source)` of every plain copy, which addresses the same
    /// storage when the source turns out to be one of those pointers.
    copies: Vec<(String, String)>,
    /// Every call the block states, in whatever order it states them.
    pub(super) calls: Vec<gosyn::ast::Call>,
    /// Every callable the block hands to storage this walk does not follow.
    /// What one writes is a question about the file's own declarations — a
    /// method value writes its receiver only when the method assigns through
    /// it — so the callables are kept whole and resolved where the widening
    /// is applied, exactly as `calls` are.
    pub(super) callables: EscapedCallables,
}

impl BlockWrites {
    /// `q := &p` and `q := p` seen as text, in whatever order the block states
    /// them. The blank identifier names no storage: `_ = q` discards the
    /// pointer instead of keeping a second name for what it addresses.
    fn record_alias(&mut self, name: &str, value: Option<&Expression>) {
        let Some(value) = value else {
            return;
        };
        if name == "_" {
            return;
        }
        match addressed_name(value) {
            Some(target) if target != name => self.aliases.push((name.to_string(), target)),
            Some(_) => {}
            None => {
                if let Expression::Ident(source) = value {
                    self.copies.push((name.to_string(), source.name.clone()));
                }
            }
        }
    }

    /// The alias pairs a copy of a pointer adds, resolved until no copy adds
    /// another: `q := &p; r := q` puts `r` over `p`'s storage too.
    pub(super) fn alias_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = self.aliases.clone();
        let mut grew = true;
        while grew {
            grew = false;
            for (destination, source) in &self.copies {
                let targets: Vec<String> = pairs
                    .iter()
                    .filter(|(pointer, _)| pointer == source)
                    .map(|(_, target)| target.clone())
                    .collect();
                for target in targets {
                    let pair = (destination.clone(), target);
                    if pair.0 != pair.1 && !pairs.contains(&pair) {
                        pairs.push(pair);
                        grew = true;
                    }
                }
            }
        }
        pairs
    }
}

/// The names a statement list assigns to a binding that already exists: `=`,
/// `++`/`--`, and a `range` that assigns rather than declares. A callable this
/// walk cannot place in program order — a deferred body, a goroutine — reads
/// these names at a moment none of those writes is ordered against, so inside
/// it they hold no known value. Declarations are absent: a name only ever
/// declared keeps the one value it was given.
///
/// A write reached through a name counts as one: `c.Path = v`, `xs[i] = v` and
/// `*p = v` all replace part of what `c`, `xs` and `p` name, which the body
/// would otherwise read as it stood at the declaration.
///
/// A write a function literal of the block makes counts as one too: the walk
/// places no literal's body in program order either, so a name an immediately
/// invoked literal, a stored closure, or another deferred body assigns is no
/// more ordered against the read than a statement's own write is.
///
/// A write a callee makes through storage the block hands it counts as one as
/// well. An address the block gives to storage this walk does not follow —
/// a composite literal, a collection element — is recorded here as a name; a
/// direct call argument and a method receiver are left to the call itself,
/// whose `escaped_call_arguments` reads the callee's own write behaviour.
pub(super) fn reassigned_names(stmts: &[Statement], out: &mut BlockWrites, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let depth = depth + 1;
    for stmt in stmts {
        match stmt {
            Statement::Assign(assign) => {
                if assign.op != Operator::Define {
                    for target in &assign.left {
                        if let Some(name) = assignment_base_name(target) {
                            out.names.insert(name);
                        }
                    }
                }
                for (index, target) in assign.left.iter().enumerate() {
                    if let Expression::Ident(id) = target {
                        out.record_alias(&id.name, assign.right.get(index));
                    }
                }
                for (index, value) in assign.right.iter().enumerate() {
                    // `m[k] = &c` / `h.C = &c` store the address in storage no
                    // name of this walk addresses, exactly as in program order;
                    // only `p = &c` binds a tracked alias.
                    let exempt = matches!(assign.left.get(index), Some(Expression::Ident(_)));
                    stated_writes(value, exempt, out, depth);
                }
            }
            Statement::IncDec(incdec) => {
                if let Some(name) = assignment_base_name(&incdec.expr) {
                    out.names.insert(name);
                }
            }
            Statement::Declaration(DeclStmt::Variable(declaration)) => {
                for spec in &declaration.specs {
                    for (index, id) in spec.name.iter().enumerate() {
                        out.record_alias(&id.name, spec.values.get(index));
                    }
                    for value in &spec.values {
                        stated_writes(value, true, out, depth);
                    }
                }
            }
            Statement::Block(block) => reassigned_names(&block.list, out, depth),
            Statement::If(if_stmt) => {
                if let Some(init) = &if_stmt.init {
                    reassigned_names(std::slice::from_ref(init), out, depth);
                }
                stated_writes(&if_stmt.cond, true, out, depth);
                reassigned_names(&if_stmt.body.list, out, depth);
                if let Some(other) = &if_stmt.else_ {
                    reassigned_names(std::slice::from_ref(other), out, depth);
                }
            }
            Statement::For(for_stmt) => {
                for part in [&for_stmt.init, &for_stmt.cond, &for_stmt.post]
                    .into_iter()
                    .flatten()
                {
                    reassigned_names(std::slice::from_ref(part), out, depth);
                }
                reassigned_names(&for_stmt.body.list, out, depth);
            }
            Statement::Range(range) => {
                if !matches!(range.op, Some((_, Operator::Define)) | None) {
                    for target in [&range.key, &range.value].into_iter().flatten() {
                        if let Some(name) = assignment_base_name(target) {
                            out.names.insert(name);
                        }
                    }
                }
                stated_writes(&range.expr, true, out, depth);
                reassigned_names(&range.body.list, out, depth);
            }
            Statement::Switch(switch) => {
                if let Some(init) = &switch.init {
                    reassigned_names(std::slice::from_ref(init), out, depth);
                }
                if let Some(tag) = &switch.tag {
                    stated_writes(tag, true, out, depth);
                }
                for clause in &switch.block.body {
                    for value in &clause.list {
                        stated_writes(value, true, out, depth);
                    }
                    reassigned_names(&clause.body, out, depth);
                }
            }
            Statement::TypeSwitch(switch) => {
                // Its init and its `v := x.(type)` guard state writes where
                // they stand, exactly as a value switch's init and tag do.
                for part in [&switch.init, &switch.tag].into_iter().flatten() {
                    reassigned_names(std::slice::from_ref(part), out, depth);
                }
                for clause in &switch.block.body {
                    reassigned_names(&clause.body, out, depth);
                }
            }
            Statement::Select(select) => {
                for clause in &select.body.body {
                    if let Some(comm) = &clause.comm {
                        reassigned_names(std::slice::from_ref(comm), out, depth);
                    }
                    reassigned_names(&clause.body, out, depth);
                }
            }
            Statement::Label(labeled) => {
                reassigned_names(std::slice::from_ref(&labeled.stmt), out, depth)
            }
            Statement::Expr(expr) => stated_writes(&expr.expr, true, out, depth),
            Statement::Go(go) => stated_call(&go.call, out, depth),
            Statement::Defer(defer) => stated_call(&defer.call, out, depth),
            Statement::Send(send) => {
                stated_writes(&send.chan, true, out, depth);
                // A channel carries the address to a receiver neither walk
                // follows, as in program order.
                stated_writes(&send.value, false, out, depth);
            }
            Statement::Return(ret) => {
                for value in &ret.ret {
                    stated_writes(value, true, out, depth);
                }
            }
            _ => {}
        }
    }
}

/// What one expression of the block states, without ordering any of it: the
/// outer names its function literals assign, the bindings whose address it
/// hands to storage this walk does not follow, and the calls it makes.
///
/// The address forms are marked exactly as the in-order walk marks them — a
/// direct call argument is exempt, and so is the whole expression wherever
/// the walk binds it to a name it tracks (`p := &x`) — so a pointer nothing
/// writes through still leaves the name it addresses exact. Where the in-order
/// walk lets the whole expression escape instead, because it hands the address
/// to storage no name of the walk addresses (`m[k] = &x`, `ch <- &x`), the
/// caller passes `exempt` as false and the address counts here too.
fn stated_writes(expr: &Expression, exempt: bool, out: &mut BlockWrites, depth: u32) {
    let mut escaped = Vec::new();
    escaped_address_names(expr, exempt, &mut escaped, depth);
    out.names.extend(escaped);
    escaped_callables(expr, exempt, &mut out.callables, depth);
    closure_writes(expr, out, depth);
}

/// The same for the call of a `go` or `defer` statement, whose func and
/// arguments are evaluated where the statement stands.
fn stated_call(call: &gosyn::ast::Call, out: &mut BlockWrites, depth: u32) {
    let mut escaped = Vec::new();
    escaped_address_names(&call.func, true, &mut escaped, depth);
    escaped_callables(&call.func, true, &mut out.callables, depth);
    for argument in &call.args {
        escaped_address_names(argument, true, &mut escaped, depth);
        escaped_callables(argument, true, &mut out.callables, depth);
    }
    out.names.extend(escaped);
    closure_writes_call(call, out, depth);
}

/// The outer names the function literals of an expression assign, and the
/// bindings they hand to storage or to a callee. Such a literal runs where this
/// walk cannot place it — immediately, at a later call through the name it is
/// stored under, or inside a callee — so a body that itself runs out of order
/// is no more ordered against its writes than against the block's own.
fn closure_writes(expr: &Expression, out: &mut BlockWrites, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let depth = depth + 1;
    match expr {
        // The names its own nested literals assign are already part of this.
        Expression::FuncLit(literal) => {
            out.names.extend(assigned_outer_names(
                &literal.body,
                function_locals(&literal.typ),
            ));
            // The literal states writes of its own, and every way it hands an
            // enclosing binding away reaches that binding just as the block's
            // own text does: a callee it hands the address to, an address it
            // puts in storage this walk does not follow, and a pointer it binds
            // to a name of its own and writes through.
            let mut inner = BlockWrites::default();
            reassigned_names(&literal.body.list, &mut inner, depth);
            out.calls.append(&mut inner.calls);
            out.names.extend(inner.names);
            out.aliases.append(&mut inner.aliases);
            out.copies.append(&mut inner.copies);
            out.callables.merge(&inner.callables);
        }
        Expression::Call(call) => closure_writes_call(call, out, depth),
        Expression::Paren(paren) => closure_writes(&paren.expr, out, depth),
        Expression::Star(star) => closure_writes(&star.right, out, depth),
        Expression::Selector(selector) => closure_writes(&selector.x, out, depth),
        Expression::Operation(operation) => {
            closure_writes(&operation.x, out, depth);
            if let Some(right) = &operation.y {
                closure_writes(right, out, depth);
            }
        }
        Expression::Index(index) => {
            closure_writes(&index.left, out, depth);
            closure_writes(&index.index, out, depth);
        }
        Expression::IndexList(index) => {
            closure_writes(&index.left, out, depth);
            for argument in &index.indices {
                closure_writes(argument, out, depth);
            }
        }
        Expression::Slice(slice) => {
            closure_writes(&slice.left, out, depth);
            for index in slice.index.iter().flatten() {
                closure_writes(index, out, depth);
            }
        }
        Expression::TypeAssert(assert) => closure_writes(&assert.left, out, depth),
        Expression::Ellipsis(ellipsis) => {
            if let Some(element) = &ellipsis.elt {
                closure_writes(element, out, depth);
            }
        }
        Expression::Range(range) => closure_writes(&range.right, out, depth),
        Expression::List(values) => {
            for value in values {
                closure_writes(value, out, depth);
            }
        }
        Expression::CompositeLit(literal) => closure_writes_literal(&literal.val, out, depth),
        _ => {}
    }
}

fn closure_writes_call(call: &gosyn::ast::Call, out: &mut BlockWrites, depth: u32) {
    out.calls.push(call.clone());
    closure_writes(&call.func, out, depth);
    for argument in &call.args {
        closure_writes(argument, out, depth);
    }
}

fn closure_writes_literal(literal: &gosyn::ast::LiteralValue, out: &mut BlockWrites, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    for element in &literal.values {
        for part in [element.key.as_ref(), Some(&element.val)]
            .into_iter()
            .flatten()
        {
            match part {
                Element::Expr(value) => closure_writes(value, out, depth + 1),
                Element::LitValue(nested) => closure_writes_literal(nested, out, depth + 1),
            }
        }
    }
}

fn rebindings_block(
    block: &BlockStmt,
    scopes: &mut Vec<HashSet<String>>,
    out: &mut Rebinds,
    depth: u32,
) {
    rebindings_stmts(&block.list, scopes, out, depth);
}

fn rebindings_stmts(
    stmts: &[Statement],
    scopes: &mut Vec<HashSet<String>>,
    out: &mut Rebinds,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    scopes.push(HashSet::new());
    for stmt in stmts {
        rebindings_stmt(stmt, scopes, out, depth + 1);
    }
    scopes.pop();
}

fn rebindings_stmt(
    stmt: &Statement,
    scopes: &mut Vec<HashSet<String>>,
    out: &mut Rebinds,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    match stmt {
        Statement::Assign(assign) => {
            for value in &assign.right {
                rebindings_expr(value, scopes, out, depth);
            }
            for (index, target) in assign.left.iter().enumerate() {
                if assign.op == Operator::Define {
                    if let Expression::Ident(id) = target {
                        record_alias(&id.name, assign.right.get(index), out);
                    }
                    declare_rebinding_scope(target, scopes);
                } else {
                    record_rebinding(target, scopes, out);
                    rebindings_expr(target, scopes, out, depth);
                    // `g = p` / `h.C = p` puts the storage somewhere this body
                    // does not own; `q := p` binds a fresh local, which
                    // `record_alias` follows instead.
                    if let Some(value) = assign.right.get(index) {
                        record_escaped_storage(value, out, depth);
                    }
                }
            }
        }
        Statement::IncDec(incdec) => record_rebinding(&incdec.expr, scopes, out),
        Statement::Declaration(DeclStmt::Variable(d)) => {
            for spec in &d.specs {
                for value in &spec.values {
                    rebindings_expr(value, scopes, out, depth);
                }
                for (index, id) in spec.name.iter().enumerate() {
                    record_alias(&id.name, spec.values.get(index), out);
                    declare_local(&id.name, scopes);
                }
            }
        }
        Statement::Declaration(DeclStmt::Const(d)) => {
            for spec in &d.specs {
                for value in &spec.values {
                    rebindings_expr(value, scopes, out, depth);
                }
                for id in &spec.name {
                    declare_local(&id.name, scopes);
                }
            }
        }
        Statement::Declaration(DeclStmt::Type(_)) | Statement::Empty(_) => {}
        Statement::Block(block) => rebindings_block(block, scopes, out, depth),
        Statement::If(if_stmt) => {
            scopes.push(HashSet::new());
            if let Some(init) = &if_stmt.init {
                rebindings_stmt(init, scopes, out, depth + 1);
            }
            rebindings_expr(&if_stmt.cond, scopes, out, depth);
            rebindings_block(&if_stmt.body, scopes, out, depth);
            if let Some(other) = &if_stmt.else_ {
                rebindings_stmt(other, scopes, out, depth + 1);
            }
            scopes.pop();
        }
        Statement::For(for_stmt) => {
            scopes.push(HashSet::new());
            for part in [&for_stmt.init, &for_stmt.cond, &for_stmt.post]
                .into_iter()
                .flatten()
            {
                rebindings_stmt(part, scopes, out, depth + 1);
            }
            rebindings_block(&for_stmt.body, scopes, out, depth);
            scopes.pop();
        }
        Statement::Range(range) => {
            scopes.push(HashSet::new());
            rebindings_expr(&range.expr, scopes, out, depth);
            for target in [&range.key, &range.value].into_iter().flatten() {
                match range.op {
                    Some((_, Operator::Define)) => declare_rebinding_scope(target, scopes),
                    // `for _, f = range xs`: the loop assigns an existing name.
                    Some(_) => record_rebinding(target, scopes, out),
                    None => {}
                }
            }
            rebindings_block(&range.body, scopes, out, depth);
            scopes.pop();
        }
        Statement::Switch(switch) => {
            scopes.push(HashSet::new());
            if let Some(init) = &switch.init {
                rebindings_stmt(init, scopes, out, depth + 1);
            }
            if let Some(tag) = &switch.tag {
                rebindings_expr(tag, scopes, out, depth);
            }
            for clause in &switch.block.body {
                for value in &clause.list {
                    rebindings_expr(value, scopes, out, depth);
                }
                rebindings_stmts(&clause.body, scopes, out, depth);
            }
            scopes.pop();
        }
        Statement::TypeSwitch(switch) => {
            scopes.push(HashSet::new());
            for part in [&switch.init, &switch.tag].into_iter().flatten() {
                rebindings_stmt(part, scopes, out, depth + 1);
            }
            for clause in &switch.block.body {
                rebindings_stmts(&clause.body, scopes, out, depth);
            }
            scopes.pop();
        }
        Statement::Select(select) => {
            for clause in &select.body.body {
                scopes.push(HashSet::new());
                if let Some(comm) = &clause.comm {
                    rebindings_stmt(comm, scopes, out, depth + 1);
                }
                rebindings_stmts(&clause.body, scopes, out, depth);
                scopes.pop();
            }
        }
        Statement::Label(labeled) => rebindings_stmt(&labeled.stmt, scopes, out, depth + 1),
        Statement::Go(go) => rebindings_call(&go.call, scopes, out, depth),
        Statement::Defer(defer) => rebindings_call(&defer.call, scopes, out, depth),
        Statement::Expr(expr) => rebindings_expr(&expr.expr, scopes, out, depth),
        Statement::Send(send) => {
            rebindings_expr(&send.chan, scopes, out, depth);
            rebindings_expr(&send.value, scopes, out, depth);
            record_escaped_storage(&send.value, out, depth);
        }
        Statement::Return(ret) => {
            for value in &ret.ret {
                rebindings_expr(value, scopes, out, depth);
                record_escaped_storage(value, out, depth);
            }
        }
        Statement::Branch(_) => {}
    }
}

fn rebindings_call(
    call: &gosyn::ast::Call,
    scopes: &mut Vec<HashSet<String>>,
    out: &mut Rebinds,
    depth: u32,
) {
    record_escape_site(call, scopes, out);
    rebindings_expr(&call.func, scopes, out, depth);
    for arg in &call.args {
        rebindings_expr(arg, scopes, out, depth);
    }
}

/// Record what a call hands to its callee: the outer names passed as bare
/// arguments or as `&x`, and an outer name the call runs a method on. Both are
/// the caller's own storage when the callee writes through them.
fn record_escape_site(call: &gosyn::ast::Call, scopes: &[HashSet<String>], out: &mut Rebinds) {
    let (callee, receiver) = match &*call.func {
        Expression::Ident(id) => (Some(CalleeName::Func(id.name.clone())), None),
        Expression::Selector(selector) => match &*selector.x {
            Expression::Ident(base) if !declared_in_scopes(&base.name, scopes) => (
                Some(CalleeName::Method {
                    recv: base.name.clone(),
                    method: selector.sel.name.clone(),
                }),
                Some(base.name.clone()),
            ),
            _ => (None, None),
        },
        _ => (None, None),
    };
    let handed: Vec<(usize, String)> = call
        .args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            handed_over_name(argument, scopes).map(|name| (index, name))
        })
        .collect();
    if handed.is_empty() && receiver.is_none() {
        return;
    }
    let callee_local = match &callee {
        Some(CalleeName::Func(name)) => declared_in_scopes(name, scopes),
        _ => false,
    };
    out.sites.push(EscapeSite {
        callee,
        callee_local,
        handed,
        receiver,
    });
}

/// The outer binding an argument hands over: `x` or `&x` on a name no
/// enclosing scope of this body declares.
fn handed_over_name(argument: &Expression, scopes: &[HashSet<String>]) -> Option<String> {
    let inner = match argument {
        Expression::Paren(paren) => return handed_over_name(&paren.expr, scopes),
        Expression::Operation(operation)
            if operation.op == Operator::And && operation.y.is_none() =>
        {
            &*operation.x
        }
        other => other,
    };
    let Expression::Ident(id) = inner else {
        return None;
    };
    (!declared_in_scopes(&id.name, scopes)).then(|| id.name.clone())
}

/// Descends into function literals, whose bodies assign package names wherever
/// the literal is later called.
fn rebindings_expr(
    expr: &Expression,
    scopes: &mut Vec<HashSet<String>>,
    out: &mut Rebinds,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    match expr {
        Expression::FuncLit(literal) => {
            scopes.push(function_locals(&literal.typ));
            rebindings_block(&literal.body, scopes, out, depth + 1);
            scopes.pop();
        }
        Expression::Call(call) => rebindings_call(call, scopes, out, depth + 1),
        Expression::Paren(paren) => rebindings_expr(&paren.expr, scopes, out, depth + 1),
        Expression::Star(star) => rebindings_expr(&star.right, scopes, out, depth + 1),
        Expression::Selector(selector) => rebindings_expr(&selector.x, scopes, out, depth + 1),
        Expression::Operation(operation) => {
            rebindings_expr(&operation.x, scopes, out, depth + 1);
            if let Some(right) = &operation.y {
                rebindings_expr(right, scopes, out, depth + 1);
            }
        }
        Expression::Index(index) => {
            rebindings_expr(&index.left, scopes, out, depth + 1);
            rebindings_expr(&index.index, scopes, out, depth + 1);
        }
        Expression::IndexList(index) => {
            rebindings_expr(&index.left, scopes, out, depth + 1);
            for argument in &index.indices {
                rebindings_expr(argument, scopes, out, depth + 1);
            }
        }
        Expression::Slice(slice) => {
            rebindings_expr(&slice.left, scopes, out, depth + 1);
            for index in slice.index.iter().flatten() {
                rebindings_expr(index, scopes, out, depth + 1);
            }
        }
        Expression::TypeAssert(assert) => rebindings_expr(&assert.left, scopes, out, depth + 1),
        Expression::Ellipsis(ellipsis) => {
            if let Some(element) = &ellipsis.elt {
                rebindings_expr(element, scopes, out, depth + 1);
            }
        }
        Expression::Range(range) => rebindings_expr(&range.right, scopes, out, depth + 1),
        Expression::List(values) => {
            for value in values {
                rebindings_expr(value, scopes, out, depth + 1);
            }
        }
        Expression::CompositeLit(literal) => {
            // A struct, slice, or map literal keeps whatever storage it is
            // given, and the walk does not follow what holds the literal.
            record_escaped_literal(&literal.val, out, depth + 1);
            rebindings_literal(&literal.val, scopes, out, depth + 1)
        }
        _ => {}
    }
}

fn rebindings_literal(
    literal: &gosyn::ast::LiteralValue,
    scopes: &mut Vec<HashSet<String>>,
    out: &mut Rebinds,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    for element in &literal.values {
        for part in [element.key.as_ref(), Some(&element.val)]
            .into_iter()
            .flatten()
        {
            match part {
                Element::Expr(value) => rebindings_expr(value, scopes, out, depth + 1),
                Element::LitValue(nested) => rebindings_literal(nested, scopes, out, depth + 1),
            }
        }
    }
}

/// `x = ...` on a name no enclosing scope declares assigns a package name.
///
/// A write reached THROUGH a name (`pkg.Value = ...`, `cfg.Field = ...`,
/// `*p = ...`, `xs[i] = ...`) is recorded twice: as the qualified name it
/// assigns, which is the form a write from another package takes, and as the
/// base name, whose declaration no longer describes what it holds.
fn record_rebinding(target: &Expression, scopes: &[HashSet<String>], out: &mut Rebinds) {
    if let Expression::Selector(selector) = target
        && let Expression::Ident(base) = &*selector.x
        && !declared_in_scopes(&base.name, scopes)
    {
        out.names
            .insert(format!("{}.{}", base.name, selector.sel.name));
    }
    let Some(name) = assignment_base_name(target) else {
        return;
    };
    if !declared_in_scopes(&name, scopes) {
        out.names.insert(name);
        return;
    }
    // A write THROUGH a local that addresses the caller's storage (`q := p;
    // q.Path = v`) assigns what the original names; rebinding the local itself
    // (`q = other`) assigns only the copy.
    if !matches!(target, Expression::Ident(_))
        && let Some(storage) = out.aliases.get(&name).cloned()
    {
        out.names.insert(storage);
    }
}

/// Record the bindings an expression hands to storage this body's caller
/// cannot see the end of: `return p`, `Holder{C: p}`, `ch <- p`, `g = p`. The
/// caller of such a body keeps a pointer it cannot follow, so the argument it
/// handed over is no longer exactly what it was.
///
/// A field read (`p.Path`) hands over the field's value rather than the
/// storage, so it names nothing.
fn record_escaped_storage(expr: &Expression, out: &mut Rebinds, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let depth = depth + 1;
    let escaped = |name: String, out: &mut Rebinds| {
        if let Some(storage) = out.aliases.get(&name).cloned() {
            out.escaped.insert(storage);
        }
        out.escaped.insert(name);
    };
    match expr {
        Expression::Ident(id) => escaped(id.name.clone(), out),
        Expression::Paren(paren) => record_escaped_storage(&paren.expr, out, depth),
        Expression::Operation(operation)
            if operation.op == Operator::And && operation.y.is_none() =>
        {
            if let Some(name) = assignment_base_name(&operation.x) {
                escaped(name, out);
            }
        }
        Expression::Operation(operation) => {
            record_escaped_storage(&operation.x, out, depth);
            if let Some(right) = &operation.y {
                record_escaped_storage(right, out, depth);
            }
        }
        // A callee may keep what it is handed and return it on.
        Expression::Call(call) => {
            for argument in &call.args {
                record_escaped_storage(argument, out, depth);
            }
        }
        Expression::List(values) => {
            for value in values {
                record_escaped_storage(value, out, depth);
            }
        }
        Expression::CompositeLit(literal) => record_escaped_literal(&literal.val, out, depth),
        _ => {}
    }
}

fn record_escaped_literal(literal: &gosyn::ast::LiteralValue, out: &mut Rebinds, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    for element in &literal.values {
        match &element.val {
            Element::Expr(value) => record_escaped_storage(value, out, depth + 1),
            Element::LitValue(nested) => record_escaped_literal(nested, out, depth + 1),
        }
    }
}

/// `q := p` copies a name that addresses the caller's storage, so the copy
/// addresses it too. A copy of anything else is a value Go duplicates.
fn record_alias(name: &str, value: Option<&Expression>, out: &mut Rebinds) {
    let Some(Expression::Ident(source)) = value else {
        return;
    };
    if let Some(storage) = out.aliases.get(&source.name).cloned() {
        out.aliases.insert(name.to_string(), storage);
    }
}

fn declared_in_scopes(name: &str, scopes: &[HashSet<String>]) -> bool {
    scopes.iter().any(|scope| scope.contains(name))
}

/// The name an assignment target is reached through: `x`, `x.f`, `x[i]`, `*x`.
///
/// The parser builds a dereference in an expression position as a unary `Star`
/// operation, not as `Expression::Star` (which it reserves for pointer types),
/// so `*p = v` and `(*p).f = v` are only recognized through the operation arm.
pub(super) fn assignment_base_name(target: &Expression) -> Option<String> {
    match target {
        Expression::Ident(id) => Some(id.name.clone()),
        Expression::Selector(selector) => assignment_base_name(&selector.x),
        Expression::Index(index) => assignment_base_name(&index.left),
        Expression::IndexList(index) => assignment_base_name(&index.left),
        Expression::Star(star) => assignment_base_name(&star.right),
        Expression::Paren(paren) => assignment_base_name(&paren.expr),
        Expression::TypeAssert(assertion) => assignment_base_name(&assertion.left),
        Expression::Operation(operation)
            if operation.op == Operator::Star && operation.y.is_none() =>
        {
            assignment_base_name(&operation.x)
        }
        _ => None,
    }
}

/// The binding `&x`, `&x.f`, `&x[i]` addresses.
pub(super) fn addressed_name(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Paren(paren) => addressed_name(&paren.expr),
        Expression::Operation(operation)
            if operation.op == Operator::And && operation.y.is_none() =>
        {
            assignment_base_name(&operation.x)
        }
        _ => None,
    }
}

/// The bindings whose address an expression hands to storage the walk does not
/// track. `exempt` marks the two positions the walk does follow: the whole
/// expression (`p := &x` binds a tracked alias) and a direct call argument
/// (the call's own write analysis decides it); everything nested below either
/// one escapes.
pub(super) fn escaped_address_names(
    expr: &Expression,
    exempt: bool,
    out: &mut Vec<String>,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let depth = depth + 1;
    let nested = |expr: &Expression, out: &mut Vec<String>| {
        escaped_address_names(expr, false, out, depth);
    };
    match expr {
        Expression::Operation(operation)
            if operation.op == Operator::And && operation.y.is_none() =>
        {
            if !exempt
                && let Some(name) = assignment_base_name(&operation.x)
                && !out.contains(&name)
            {
                out.push(name);
            }
            nested(&operation.x, out);
        }
        Expression::Paren(paren) => escaped_address_names(&paren.expr, exempt, out, depth),
        Expression::Call(call) => {
            nested(&call.func, out);
            for argument in &call.args {
                escaped_address_names(argument, true, out, depth);
            }
        }
        Expression::Operation(operation) => {
            nested(&operation.x, out);
            if let Some(right) = &operation.y {
                nested(right, out);
            }
        }
        Expression::Star(star) => nested(&star.right, out),
        Expression::Selector(selector) => nested(&selector.x, out),
        Expression::Index(index) => {
            nested(&index.left, out);
            nested(&index.index, out);
        }
        Expression::IndexList(index) => {
            nested(&index.left, out);
            for argument in &index.indices {
                nested(argument, out);
            }
        }
        Expression::Slice(slice) => {
            nested(&slice.left, out);
            for index in slice.index.iter().flatten() {
                nested(index, out);
            }
        }
        Expression::TypeAssert(assertion) => nested(&assertion.left, out),
        Expression::Ellipsis(ellipsis) => {
            if let Some(element) = &ellipsis.elt {
                nested(element, out);
            }
        }
        Expression::Range(range) => nested(&range.right, out),
        Expression::List(values) => {
            for value in values {
                nested(value, out);
            }
        }
        Expression::CompositeLit(literal) => escaped_address_literal(&literal.val, out, depth),
        _ => {}
    }
}

fn escaped_address_literal(literal: &gosyn::ast::LiteralValue, out: &mut Vec<String>, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    for element in &literal.values {
        for part in [element.key.as_ref(), Some(&element.val)]
            .into_iter()
            .flatten()
        {
            match part {
                Element::Expr(value) => escaped_address_names(value, false, out, depth + 1),
                Element::LitValue(nested) => escaped_address_literal(nested, out, depth + 1),
            }
        }
    }
}

/// The callables an expression hands to storage the walk stops following, with
/// what each one may write of the caller's own bindings.
#[derive(Default)]
pub(super) struct EscapedCallables {
    /// The outer names the escaping function literals assign.
    pub(super) closure_writes: Vec<String>,
    /// `(receiver, method)` of a method taken as a value instead of called.
    pub(super) method_values: Vec<(String, String)>,
    /// The plain names handed to that storage, each of which may hold a
    /// closure this file registered.
    pub(super) named_values: Vec<String>,
}

impl EscapedCallables {
    /// Take on everything another expression of the same block handed over.
    pub(super) fn merge(&mut self, other: &EscapedCallables) {
        self.closure_writes
            .extend(other.closure_writes.iter().cloned());
        self.method_values
            .extend(other.method_values.iter().cloned());
        self.named_values.extend(other.named_values.iter().cloned());
    }
}

/// A function literal captures the storage of every outer name its body
/// assigns, and a method value captures its receiver's, so both hold what `&x`
/// holds: a second name for the caller's storage. The walk follows exactly two
/// positions — a literal bound to a plain name, whose later `f()` `call_local`
/// applies, and a direct call argument, which `walk_call` decides once it knows
/// whether it entered the literal — and `exempt` marks them. A callable
/// anywhere else may run where nothing here can see it, so what it writes is
/// stale from that point on — including a plain name holding a closure this
/// file registered, which reaches its body only when it is called by that
/// name. A method value is never followed: no call through the name it is
/// bound to reaches the method body.
pub(super) fn escaped_callables(
    expr: &Expression,
    exempt: bool,
    out: &mut EscapedCallables,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let depth = depth + 1;
    let nested = |expr: &Expression, out: &mut EscapedCallables| {
        escaped_callables(expr, false, out, depth);
    };
    match expr {
        Expression::FuncLit(literal) => {
            if exempt {
                return;
            }
            // A literal nested in this body escapes where that body stores it,
            // which the walk of that body decides; the names this one assigns
            // already cover what its own nested literals write.
            for name in assigned_outer_names(&literal.body, function_locals(&literal.typ)) {
                if !out.closure_writes.contains(&name) {
                    out.closure_writes.push(name);
                }
            }
        }
        Expression::Ident(ident) => {
            // A name carries whatever closure this file bound to it, which
            // `escape_callables` resolves; a name holding anything else says
            // nothing about the caller's bindings.
            if exempt {
                return;
            }
            if !out.named_values.contains(&ident.name) {
                out.named_values.push(ident.name.clone());
            }
        }
        Expression::Paren(paren) => escaped_callables(&paren.expr, exempt, out, depth),
        Expression::Call(call) => {
            // The target of a call is invoked, not stored: an immediately
            // invoked literal is walked, and a method call's receiver write is
            // `escaped_call_arguments`' business.
            match &*call.func {
                // A name this file registered a closure under is applied by
                // `call_local` where the call runs, so it is followed, not
                // escaped.
                Expression::FuncLit(_) | Expression::Ident(_) => {}
                Expression::Selector(selector) => nested(&selector.x, out),
                other => nested(other, out),
            }
            for argument in &call.args {
                escaped_callables(argument, true, out, depth);
            }
        }
        Expression::Selector(selector) => {
            if let Expression::Ident(base) = &*selector.x {
                out.method_values
                    .push((base.name.clone(), selector.sel.name.clone()));
            }
            nested(&selector.x, out);
        }
        Expression::Operation(operation) => {
            nested(&operation.x, out);
            if let Some(right) = &operation.y {
                nested(right, out);
            }
        }
        Expression::Star(star) => nested(&star.right, out),
        Expression::Index(index) => {
            nested(&index.left, out);
            nested(&index.index, out);
        }
        Expression::IndexList(index) => {
            nested(&index.left, out);
            for argument in &index.indices {
                nested(argument, out);
            }
        }
        Expression::Slice(slice) => {
            nested(&slice.left, out);
            for index in slice.index.iter().flatten() {
                nested(index, out);
            }
        }
        Expression::TypeAssert(assertion) => nested(&assertion.left, out),
        Expression::Ellipsis(ellipsis) => {
            if let Some(element) = &ellipsis.elt {
                nested(element, out);
            }
        }
        Expression::Range(range) => nested(&range.right, out),
        Expression::List(values) => {
            for value in values {
                nested(value, out);
            }
        }
        Expression::CompositeLit(literal) => escaped_callables_literal(&literal.val, out, depth),
        _ => {}
    }
}

fn escaped_callables_literal(
    literal: &gosyn::ast::LiteralValue,
    out: &mut EscapedCallables,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    for element in &literal.values {
        for part in [element.key.as_ref(), Some(&element.val)]
            .into_iter()
            .flatten()
        {
            match part {
                Element::Expr(value) => escaped_callables(value, false, out, depth + 1),
                Element::LitValue(nested) => escaped_callables_literal(nested, out, depth + 1),
            }
        }
    }
}

/// The names a function body assigns that it does not declare itself: the
/// bindings a closure writes in its enclosing scope, and the arguments a callee
/// writes through its parameters.
pub(super) fn assigned_outer_names(
    body: &BlockStmt,
    declared: HashSet<String>,
) -> BTreeSet<String> {
    let mut out = Rebinds::default();
    let mut scopes = vec![declared];
    rebindings_block(body, &mut scopes, &mut out, 0);
    out.names
}

/// What a body writes of the storage its caller handed it: the parameters and
/// the receiver it assigns through directly, and the calls that hand one of
/// them on, which `resolve_escaping_writes` follows into their callees.
struct BodyWrites {
    through: Vec<bool>,
    receiver: bool,
    escapes: Vec<EscapeSite>,
}

fn body_writes(
    body: &BlockStmt,
    params: &[String],
    receiver: Option<&str>,
    handed_storage: &HashSet<String>,
) -> BodyWrites {
    let mut out = Rebinds {
        aliases: handed_storage
            .iter()
            .map(|name| (name.clone(), name.clone()))
            .collect(),
        ..Rebinds::default()
    };
    let mut scopes = vec![HashSet::new()];
    rebindings_block(body, &mut scopes, &mut out, 0);
    let own: HashSet<&str> = params.iter().map(String::as_str).chain(receiver).collect();
    // Storage that leaves the body counts with storage the body assigns: in
    // both cases the caller's exact view of the argument does not survive the
    // call.
    BodyWrites {
        through: params
            .iter()
            .map(|param| out.names.contains(param) || out.escaped.contains(param))
            .collect(),
        receiver: receiver
            .is_some_and(|name| out.names.contains(name) || out.escaped.contains(name)),
        escapes: out
            .sites
            .into_iter()
            .filter_map(|site| {
                let site = EscapeSite {
                    callee: site.callee,
                    callee_local: site.callee_local,
                    handed: site
                        .handed
                        .into_iter()
                        .filter(|(_, name)| own.contains(name.as_str()))
                        .collect(),
                    receiver: site.receiver.filter(|name| own.contains(name.as_str())),
                };
                (!site.handed.is_empty() || site.receiver.is_some()).then_some(site)
            })
            .collect(),
    }
}

fn declare_rebinding_scope(target: &Expression, scopes: &mut [HashSet<String>]) {
    if let Expression::Ident(id) = target {
        declare_local(&id.name, scopes);
    }
}

fn declare_local(name: &str, scopes: &mut [HashSet<String>]) {
    if let Some(scope) = scopes.last_mut() {
        scope.insert(name.to_string());
    }
}

/// Declared struct fields retain the imported receiver type behind `repo.db`.
pub(super) fn struct_field_types(file: &File) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for declaration in &file.decl {
        if let Declaration::Type(declaration) = declaration {
            for spec in &declaration.specs {
                if let Expression::TypeStruct(structure) = &spec.typ {
                    for field in &structure.fields {
                        if let Some(typ) = named_type(&field.typ) {
                            for name in &field.name {
                                out.insert(
                                    format!("{}.{}", spec.name.name, name.name),
                                    typ.clone(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Cobra command literals register callbacks even when this file never executes the command.
pub(super) fn cobra_registrations(
    file: &File,
    imports: &Imports,
    funcs: &mut HashMap<String, GoFunc>,
    fact_file: &str,
    max_bytes: u64,
) -> (
    Vec<crate::Registration>,
    BTreeSet<String>,
    Option<&'static str>,
) {
    let mut bytes_left = max_bytes;
    enum Node<'a> {
        Expr(&'a Expression),
        Stmt(&'a Statement),
        Block(&'a BlockStmt),
        Literal(&'a gosyn::ast::LiteralValue),
        Shadow(&'a gosyn::ast::Ident, usize),
    }
    let mut stack = Vec::new();
    for declaration in &file.decl {
        match declaration {
            Declaration::Variable(declaration) => {
                for spec in &declaration.specs {
                    stack.extend(spec.values.iter().map(Node::Expr));
                }
            }
            Declaration::Function(function) => {
                if let Some(body) = &function.body {
                    stack.push(Node::Block(body));
                }
            }
            _ => {}
        }
    }
    let mut shadowed: Vec<(String, usize, usize)> = Vec::new();
    let package_shadows = package_var_names(file);
    let mut registrations = Vec::new();
    let mut roots = BTreeSet::new();
    while let Some(node) = stack.pop() {
        match node {
            Node::Block(block) => {
                for statement in block.list.iter().rev() {
                    let bindings: Vec<&gosyn::ast::Ident> = match statement {
                        Statement::Assign(assign) if assign.op == Operator::Define => assign
                            .left
                            .iter()
                            .filter_map(|target| match target {
                                Expression::Ident(name) => Some(name),
                                _ => None,
                            })
                            .collect(),
                        Statement::Declaration(DeclStmt::Variable(declaration)) => declaration
                            .specs
                            .iter()
                            .flat_map(|spec| &spec.name)
                            .collect(),
                        Statement::Declaration(DeclStmt::Const(declaration)) => declaration
                            .specs
                            .iter()
                            .flat_map(|spec| &spec.name)
                            .collect(),
                        Statement::Declaration(DeclStmt::Type(declaration)) => {
                            declaration.specs.iter().map(|spec| &spec.name).collect()
                        }
                        _ => Vec::new(),
                    };
                    for binding in bindings {
                        if imports.contains_key(&binding.name) {
                            stack.push(Node::Shadow(binding, block.pos.1));
                        }
                    }
                    stack.push(Node::Stmt(statement));
                }
            }
            Node::Shadow(binding, end) => shadowed.push((binding.name.clone(), binding.pos, end)),
            Node::Literal(literal) => {
                for field in &literal.values {
                    if let Some(key) = &field.key {
                        match key {
                            Element::Expr(expr) => stack.push(Node::Expr(expr)),
                            Element::LitValue(value) => stack.push(Node::Literal(value)),
                        }
                    }
                    match &field.val {
                        Element::Expr(expr) => stack.push(Node::Expr(expr)),
                        Element::LitValue(value) => stack.push(Node::Literal(value)),
                    }
                }
            }
            Node::Expr(expr) => match expr {
                Expression::CompositeLit(literal) => {
                    if let Some(typ) = constructed_class(expr)
                        && let Some((pkg, "Command")) = typ.split_once('.')
                        && imports
                            .get(pkg)
                            .is_some_and(|path| path == "github.com/spf13/cobra")
                        && !package_shadows.iter().any(|name| name == pkg)
                        && !funcs.values().any(|function| {
                            function.body.pos.0 <= literal.val.pos.0
                                && function.body.pos.1 >= literal.val.pos.1
                                && function.locals.contains(pkg)
                        })
                        && !shadowed.iter().any(|(name, start, end)| {
                            name == pkg && *start <= literal.val.pos.0 && *end >= literal.val.pos.1
                        })
                    {
                        let mut selected_handlers = Vec::new();
                        let mut primary = None;
                        let mut name = None;
                        let mut unresolved = vec!["parent_command_and_inherited_hooks".to_string()];
                        for field in &literal.val.values {
                            let Some(Element::Expr(Expression::Ident(key))) = &field.key else {
                                continue;
                            };
                            if key.name == "Use" {
                                if let Element::Expr(value) = &field.val {
                                    name = string_of(value).and_then(|value| {
                                        value.split_whitespace().next().map(str::to_string)
                                    });
                                }
                            } else if is_callback_field(&key.name) {
                                let handler = match &field.val {
                                    Element::Expr(Expression::Ident(name))
                                        if name.name != "nil"
                                            && !funcs.values().any(|function| {
                                                function.body.pos.0 <= literal.val.pos.0
                                                    && function.body.pos.1 >= literal.val.pos.1
                                                    && function.locals.contains(&name.name)
                                            })
                                            && (!package_shadows.contains(&name.name)
                                                || funcs.contains_key(&name.name)) =>
                                    {
                                        Some(name.name.clone())
                                    }
                                    Element::Expr(Expression::FuncLit(literal)) => {
                                        register_func_literal(literal, funcs);
                                        Some(literal_function_name(literal))
                                    }
                                    _ => None,
                                };
                                if let Some(handler) = handler {
                                    roots.insert(handler.clone());
                                    if matches!(key.name.as_str(), "Run" | "RunE") {
                                        primary = Some(handler.clone());
                                    }
                                    if !selected_handlers.contains(&handler) {
                                        selected_handlers.push(handler);
                                    }
                                } else {
                                    unresolved.push("dynamic_hook".into());
                                }
                            }
                        }
                        if let Some(primary_handler) = primary {
                            if name.is_none() {
                                unresolved.push("dynamic_registration".into());
                            }
                            let owner = funcs
                                .iter()
                                .filter(|(_, function)| {
                                    function.body.pos.0 <= literal.val.pos.0
                                        && function.body.pos.1 >= literal.val.pos.1
                                })
                                .min_by_key(|(name, function)| {
                                    (function.body.pos.1 - function.body.pos.0, *name)
                                })
                                .map(|(name, _)| name.clone())
                                .or_else(|| {
                                    file.decl
                                        .iter()
                                        .filter_map(|declaration| match declaration {
                                            Declaration::Variable(variable) => {
                                                Some(&variable.specs)
                                            }
                                            _ => None,
                                        })
                                        .flatten()
                                        .flat_map(|spec| spec.values.iter().zip(&spec.name))
                                        .filter_map(|(value, name)| {
                                            let start = value.pos();
                                            (start <= literal.val.pos.0)
                                                .then(|| (start, name.name.clone()))
                                        })
                                        .max_by_key(|(start, _)| *start)
                                        .map(|(_, name)| name)
                                })
                                .unwrap_or_else(|| file.pkg_name.name.clone());
                            let registration = crate::Registration {
                                kind: crate::RegistrationKind::Command { name },
                                file: fact_file.to_string(),
                                owner,
                                primary_handler,
                                selected_handlers,
                                spans: vec![(expr.pos() as u32, literal.val.pos.1 as u32)],
                                unresolved,
                            };
                            if let Err(limit) = crate::registration::charge_registration(
                                &mut bytes_left,
                                &registration,
                            ) {
                                return (registrations, roots, Some(limit));
                            }
                            registrations.push(registration);
                        }
                    }
                    stack.push(Node::Literal(&literal.val));
                }
                Expression::FuncLit(literal) => stack.push(Node::Block(&literal.body)),
                Expression::Call(call) => {
                    stack.push(Node::Expr(&call.func));
                    stack.extend(call.args.iter().map(Node::Expr));
                }
                Expression::Paren(paren) => stack.push(Node::Expr(&paren.expr)),
                Expression::Operation(operation) => {
                    stack.push(Node::Expr(&operation.x));
                    if let Some(right) = &operation.y {
                        stack.push(Node::Expr(right));
                    }
                }
                Expression::Star(star) => stack.push(Node::Expr(&star.right)),
                Expression::Selector(selector) => stack.push(Node::Expr(&selector.x)),
                Expression::Index(index) => {
                    stack.push(Node::Expr(&index.left));
                    stack.push(Node::Expr(&index.index));
                }
                Expression::IndexList(index) => {
                    stack.push(Node::Expr(&index.left));
                    stack.extend(index.indices.iter().map(Node::Expr));
                }
                Expression::Slice(slice) => {
                    stack.push(Node::Expr(&slice.left));
                    stack.extend(slice.index.iter().flatten().map(|index| Node::Expr(index)));
                }
                Expression::TypeAssert(assertion) => stack.push(Node::Expr(&assertion.left)),
                Expression::List(list) => stack.extend(list.iter().map(Node::Expr)),
                _ => {}
            },
            Node::Stmt(stmt) => match stmt {
                Statement::Assign(assign) => stack.extend(assign.right.iter().map(Node::Expr)),
                Statement::Declaration(DeclStmt::Variable(declaration)) => {
                    for spec in &declaration.specs {
                        stack.extend(spec.values.iter().map(Node::Expr));
                    }
                }
                Statement::Expr(expr) => stack.push(Node::Expr(&expr.expr)),
                Statement::Return(ret) => stack.extend(ret.ret.iter().map(Node::Expr)),
                Statement::Block(block) => stack.push(Node::Block(block)),
                Statement::If(branch) => {
                    stack.push(Node::Block(&branch.body));
                    stack.push(Node::Expr(&branch.cond));
                    if let Some(init) = &branch.init {
                        stack.push(Node::Stmt(init));
                    }
                    if let Some(other) = &branch.else_ {
                        stack.push(Node::Stmt(other));
                    }
                }
                Statement::For(loop_) => {
                    stack.push(Node::Block(&loop_.body));
                    for part in [&loop_.init, &loop_.cond, &loop_.post]
                        .into_iter()
                        .flatten()
                    {
                        stack.push(Node::Stmt(part));
                    }
                }
                Statement::Range(loop_) => {
                    stack.push(Node::Block(&loop_.body));
                    stack.push(Node::Expr(&loop_.expr));
                }
                Statement::Go(go) => {
                    stack.push(Node::Expr(&go.call.func));
                    stack.extend(go.call.args.iter().map(Node::Expr));
                }
                Statement::Defer(defer) => {
                    stack.push(Node::Expr(&defer.call.func));
                    stack.extend(defer.call.args.iter().map(Node::Expr));
                }
                Statement::Label(label) => stack.push(Node::Stmt(&label.stmt)),
                Statement::Select(select) => {
                    for clause in &select.body.body {
                        if let Some(comm) = &clause.comm {
                            stack.push(Node::Stmt(comm));
                        }
                        stack.extend(clause.body.iter().map(Node::Stmt));
                    }
                }
                Statement::TypeSwitch(switch) => {
                    for part in [&switch.init, &switch.tag].into_iter().flatten() {
                        stack.push(Node::Stmt(part));
                    }
                    for clause in &switch.block.body {
                        stack.extend(clause.body.iter().map(Node::Stmt));
                    }
                }
                Statement::Send(send) => {
                    stack.push(Node::Expr(&send.chan));
                    stack.push(Node::Expr(&send.value));
                }
                Statement::Switch(switch) => {
                    if let Some(init) = &switch.init {
                        stack.push(Node::Stmt(init));
                    }
                    if let Some(tag) = &switch.tag {
                        stack.push(Node::Expr(tag));
                    }
                    for clause in &switch.block.body {
                        stack.extend(clause.list.iter().map(Node::Expr));
                        stack.extend(clause.body.iter().map(Node::Stmt));
                    }
                }
                _ => {}
            },
        }
    }
    (registrations, roots, None)
}
