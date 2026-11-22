//! Go call resolution from lexical bindings, imports, and receiver types.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
};
use gosyn::ast::Expression;
use gosyn::token::Operator;

use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::{CallableValue, SemanticValueKind};

use super::GO_DOMAINS;
use super::control::call_span;
use super::summary::{GoFunc, allocated_class, constructed_class, returns_instances, unambiguous};
use super::walker::GoWalker;

/// Go predeclared functions and type-conversion names a bare call can target
/// without naming repo code.
pub(super) const GO_BUILTINS: [&str; 34] = [
    "make", "len", "cap", "append", "new", "delete", "copy", "close", "panic", "recover", "print",
    "println", "min", "max", "clear", "complex", "real", "imag", "string", "bool", "byte", "rune",
    "error", "any", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32",
    "uint64",
];

/// A call target classified using only the current file and its imports.
pub(super) enum GoCallee {
    Pkg {
        path: String,
        method: String,
        /// The imported package's local qualifier as written (`ghcmd`), used to
        /// form the `pkg.Func` call edge the repo layer resolves via imports.
        local: String,
    },
    Local(String),
    /// A bare call defined in no local function: may live in a sibling file of
    /// the same package. The repo layer resolves or drops it.
    MaybeSibling(String),
    /// A call through a local binding (`handler := makeHandler(); handler()`,
    /// or a function-typed parameter). Only the value bound to that name may
    /// resolve it; the name itself belongs to the local scope.
    Dynamic(String),
    /// A method call on a local variable (`h.CreateTempFile()`), dispatched at
    /// composition time through the receiver's constructor-typed class.
    Method {
        recv: String,
        method: String,
    },
    Unknown,
}

/// The call a method's receiver is, through `&`, `*` and parens:
/// `NewExecutor().Run(...)`, `(&newCfg()).Save()`.
fn receiver_call(expr: &Expression) -> Option<&gosyn::ast::Call> {
    match expr {
        Expression::Call(call) => Some(call),
        Expression::Paren(paren) => receiver_call(&paren.expr),
        Expression::Star(star) => receiver_call(&star.right),
        Expression::Operation(operation) if operation.y.is_none() => receiver_call(&operation.x),
        _ => None,
    }
}

pub(super) fn go_callee_name(mut expression: &Expression) -> String {
    let mut suffix = Vec::new();
    for _ in 0..MAX_WALK_DEPTH {
        match expression {
            Expression::Ident(name) => {
                return format!(
                    "{}{}",
                    name.name,
                    suffix.into_iter().rev().collect::<String>()
                );
            }
            Expression::Selector(selector) => {
                suffix.push(format!(".{}", selector.sel.name));
                expression = &selector.x;
            }
            Expression::Call(call) => {
                suffix.push("()".to_string());
                expression = &call.func;
            }
            Expression::Paren(paren) => expression = &paren.expr,
            Expression::Star(star) => expression = &star.right,
            Expression::Index(index) => {
                suffix.push("[?]".to_string());
                expression = &index.left;
            }
            _ => break,
        }
    }
    "<dynamic>".to_string()
}

impl GoWalker<'_, '_> {
    /// Assignment provenance: a composite literal, a copy of an already-typed
    /// local, or an address of one types the destination for later method
    /// dispatch.
    pub(super) fn bind_go_receiver_type(&mut self, left: &Expression, right: &Expression) {
        let Expression::Ident(id) = left else {
            return;
        };
        let alias = match right {
            Expression::Ident(src) if self.local_types.contains_key(&src.name) => {
                Some(self.go_receiver_value(&src.name))
            }
            _ => None,
        };
        let ty = constructed_class(right).or_else(|| self.assigned_class(right));
        if let Some(ty) = ty {
            self.local_types.insert(id.name.clone(), ty);
        }
        match alias {
            Some(instance) => {
                self.instance_aliases.insert(id.name.clone(), instance);
            }
            None => {
                self.instance_aliases.remove(&id.name);
            }
        }
    }

    /// The function a bare call name reaches, when this file binds exactly one
    /// body to it.
    pub(super) fn named_go_function(&self, name: &str) -> Option<&GoFunc> {
        unambiguous(self.funcs, name)
    }

    /// The declared or assigned receiver type. Interface implementation sets
    /// are repository facts resolved by the linker, not selected per file.
    pub(super) fn go_receiver_type(&self, recv: &str) -> Option<String> {
        self.local_types.get(recv).cloned().or_else(|| {
            let (base, field) = recv.split_once('.')?;
            let typ = self.local_types.get(base)?;
            self.struct_fields.get(&format!("{typ}.{field}")).cloned()
        })
    }

    /// `NewExecutor().Run(cmd)` runs a method on a value no name holds, so the
    /// selector resolves to nothing and the call is silent. Binding the
    /// constructor's result to a synthetic local makes the method dispatch
    /// exactly as `e := NewExecutor(); e.Run(cmd)` does: the constructor's edge
    /// types that local, and the method's edge carries it as the receiver.
    /// A chained standard-library call (`exec.Command(...).Run()`) is left
    /// alone: the inner call is what the engine models.
    pub(super) fn bind_chained_receiver(&mut self, func: &Expression) -> Option<String> {
        let Expression::Selector(selector) = func else {
            return None;
        };
        let inner = receiver_call(&selector.x)?;
        let target = match self.resolve_go_callee(&inner.func) {
            GoCallee::Local(name) | GoCallee::MaybeSibling(name) => Some(name),
            // A constructor in another package of this repository or in a
            // dependency: this file cannot name its returned type, but the
            // package that declares it does, so composition types the result.
            GoCallee::Pkg { path, .. } if !crate::external::is_go_stdlib(&path) => None,
            _ => return None,
        };
        let (line, column) = call_span(inner);
        let recv = format!("$recv#{line}:{column}");
        let class = target
            .as_deref()
            .and_then(|target| self.named_go_function(target))
            .and_then(|function| {
                returns_instances(&function.body)
                    .into_iter()
                    .next()
                    .flatten()
            });
        self.local_vars.insert(recv.clone());
        self.bound_vars.insert(recv.clone());
        match class {
            Some(class) => {
                self.local_types.insert(recv.clone(), class);
            }
            None => {
                self.local_types.remove(&recv);
            }
        }
        Some(recv)
    }

    /// The type a call to a function of this file constructs, when every
    /// `return` in its body agrees on one.
    fn returned_instance(&self, func: &Expression) -> Option<String> {
        let target = match self.resolve_go_callee(func) {
            GoCallee::Local(name) | GoCallee::MaybeSibling(name) => name,
            _ => return None,
        };
        returns_instances(&self.named_go_function(&target)?.body)
            .into_iter()
            .next()
            .flatten()
    }

    /// The type an assigned expression names for later method dispatch, when
    /// no composite literal states one: a copy of an already-typed local, the
    /// local an address points at (`s := &b` dispatches on `b`'s type), an
    /// allocation (`s := new(Box)`), or a constructor of this file
    /// (`e := NewExecutor()`).
    pub(super) fn assigned_class(&self, right: &Expression) -> Option<String> {
        match right {
            Expression::Paren(paren) => self.assigned_class(&paren.expr),
            Expression::Operation(operation)
                if operation.op == Operator::And && operation.y.is_none() =>
            {
                self.assigned_class(&operation.x)
            }
            Expression::Ident(src) => self.local_types.get(&src.name).cloned(),
            Expression::Call(call) => allocated_class(&call.func, &call.args)
                .or_else(|| self.sql_constructor(&call.func))
                .or_else(|| self.returned_instance(&call.func)),
            _ => None,
        }
    }

    fn sql_constructor(&self, func: &Expression) -> Option<String> {
        match self.resolve_go_callee(func) {
            GoCallee::Pkg {
                path,
                method,
                local,
            } if path == "database/sql" && matches!(method.as_str(), "Open" | "OpenDB") => {
                Some(format!("{local}.DB"))
            }
            GoCallee::Method { recv, method }
                if self.go_receiver_import_path(&recv).as_deref() == Some("database/sql") =>
            {
                let typ = self.go_receiver_type(&recv)?;
                let (pkg, base) = typ.split_once('.')?;
                match (base, method.as_str()) {
                    ("DB", "Begin" | "BeginTx") | ("Conn", "BeginTx") => Some(format!("{pkg}.Tx")),
                    ("DB", "Conn") => Some(format!("{pkg}.Conn")),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub(super) fn go_receiver_method_key(&self, recv: &str, method: &str) -> Option<String> {
        self.go_method_key(&self.go_receiver_type(recv)?, method)
    }

    /// The declaration key a method call on a value of this type dispatches to,
    /// when this file declares that method.
    pub(super) fn go_method_key(&self, typ: &str, method: &str) -> Option<String> {
        let base = typ.rsplit('.').next().unwrap_or(typ);
        let key = format!("{base}.{method}");
        self.funcs.contains_key(&key).then_some(key)
    }

    pub(super) fn unresolved_interface(&mut self, recv: &str, method: &str, node: ProvenanceRef) {
        let Some(typ) = self.local_types.get(recv) else {
            return;
        };
        if !self
            .dispatch_contracts
            .iter()
            .any(|contract| contract.name == *typ && contract.methods.iter().any(|m| m == method))
        {
            return;
        }
        self.out_boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_INTERFACE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: GO_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!(
                "interface {typ} method {method:?} requires repository dispatch"
            )),
        });
    }

    /// The import path of the package that declares a method receiver's type
    /// (`var once sync.Once`), which makes `once.Do(...)` that package's call.
    pub(super) fn go_receiver_import_path(&self, recv: &str) -> Option<String> {
        let typ = self.go_receiver_type(recv)?;
        let (local, _) = typ.split_once('.')?;
        self.imports.get(local).cloned()
    }

    /// Resolve a Go callee with local bindings shadowing same-named package functions.
    pub(super) fn resolve_go_callee(&self, func: &Expression) -> GoCallee {
        match func {
            Expression::Ident(id) => {
                // A symbol names a local binding, never a callable this file or
                // its package declares, so only a callable value names a target.
                let bound = self
                    .values
                    .get(&id.name)
                    .and_then(|value| match &value.kind {
                        SemanticValueKind::Callable(CallableValue::Function { name }) => {
                            Some(name.as_str())
                        }
                        _ => None,
                    });
                // A local variable or parameter shadows every package and
                // sibling symbol spelled the same way.
                let shadowed = self.local_vars.contains(&id.name);
                if let Some((local, method)) = bound.and_then(|name| name.split_once('.'))
                    && let Some(path) = self.imports.get(local)
                {
                    GoCallee::Pkg {
                        path: path.clone(),
                        method: method.to_string(),
                        local: local.to_string(),
                    }
                } else if !self.collect_edges
                    && self.fact_scope.is_none()
                    && bound.is_some_and(|name| {
                        name.contains('.') && self.named_go_function(name).is_some()
                    })
                {
                    GoCallee::Dynamic(id.name.clone())
                } else if let Some(name) = bound
                    && self.named_go_function(name).is_some()
                {
                    GoCallee::Local(name.to_string())
                } else if let Some(name) = bound {
                    GoCallee::MaybeSibling(name.to_string())
                } else if shadowed {
                    GoCallee::Dynamic(id.name.clone())
                } else if self.named_go_function(&id.name).is_some() {
                    GoCallee::Local(id.name.clone())
                } else if !GO_BUILTINS.contains(&id.name.as_str()) {
                    // Not defined in this file, not a builtin/conversion, not
                    // a builtin: a candidate for a same-package sibling file
                    // or a callable parameter resolved by composition.
                    GoCallee::MaybeSibling(id.name.clone())
                } else {
                    GoCallee::Unknown
                }
            }
            Expression::Selector(sel) => {
                if let Expression::Ident(pkg) = &*sel.x {
                    if let Some(path) = self.imports.get(&pkg.name) {
                        return GoCallee::Pkg {
                            path: path.clone(),
                            method: sel.sel.name.clone(),
                            local: pkg.name.clone(),
                        };
                    }
                    // A method on a local variable — dispatchable only if the
                    // composer can type the receiver from a constructor.
                    return GoCallee::Method {
                        recv: pkg.name.clone(),
                        method: sel.sel.name.clone(),
                    };
                }
                // A method on a freshly constructed package type —
                // `(&net.Dialer{}).DialContext(...)` — resolves through the
                // literal's qualified type as `Type.Method`.
                if let Some((local, path, typ)) = self.composite_pkg_type(&sel.x) {
                    return GoCallee::Pkg {
                        path,
                        method: format!("{typ}.{}", sel.sel.name),
                        local,
                    };
                }
                if let Expression::Selector(receiver) = &*sel.x
                    && let Expression::Ident(base) = &*receiver.x
                {
                    return GoCallee::Method {
                        recv: format!("{}.{}", base.name, receiver.sel.name),
                        method: sel.sel.name.clone(),
                    };
                }
                GoCallee::Unknown
            }
            Expression::Paren(p) => self.resolve_go_callee(&p.expr),
            Expression::Index(index)
                if !self.collect_edges
                    && self.fact_scope.is_none()
                    && matches!(self.resolve_go_callee(&index.left), GoCallee::Dynamic(_)) =>
            {
                GoCallee::Dynamic(go_callee_name(&index.left))
            }
            Expression::Index(index) => self.resolve_go_callee(&index.left),
            Expression::IndexList(index) => self.resolve_go_callee(&index.left),
            _ => GoCallee::Unknown,
        }
    }

    /// The imported package and type name of a composite literal receiver
    /// (`&net.Dialer{}` through `&`, `*`, parens): (local qualifier, import
    /// path, type name).
    fn composite_pkg_type(&self, expr: &Expression) -> Option<(String, String, String)> {
        match expr {
            Expression::Paren(p) => self.composite_pkg_type(&p.expr),
            Expression::Operation(op) if op.y.is_none() => self.composite_pkg_type(&op.x),
            Expression::Star(s) => self.composite_pkg_type(&s.right),
            Expression::CompositeLit(cl) => {
                if let Expression::Selector(sel) = &*cl.typ
                    && let Expression::Ident(pkg) = &*sel.x
                {
                    let path = self.imports.get(&pkg.name)?;
                    return Some((pkg.name.clone(), path.clone(), sel.sel.name.clone()));
                }
                None
            }
            _ => None,
        }
    }
}
