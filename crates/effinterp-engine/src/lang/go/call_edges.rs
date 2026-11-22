//! Go call edges and construction sites recorded for repository composition.

use effinterp_proto::ResourceExpr;
use gosyn::ast::{Element, Expression};

use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::module_summary::{CallEdge, call_results};
use crate::{
    ObjectIdentity, SemanticValue, SemanticValueKind, ValueArgument, ValueOrigin, merge_arguments,
    positional_arguments,
};

use super::MAX_SUMMARY_ITEMS;
use super::call_resolution::GO_BUILTINS;
use super::semantic_values::GO_PREDECLARED_VALUES;
use super::summary::{construction_site, is_callback_field, literal_function_name};
use super::walk_output::GoWalkOutput;
use super::walker::GoWalker;

impl GoWalker<'_, '_> {
    pub(super) fn next_go_site_origin(&mut self) -> ValueOrigin {
        let origin = ValueOrigin::Site {
            file: self.fact_file.clone(),
            function: self.fact_function.clone(),
            ordinal: self.site_ordinal,
            result_index: 0,
        };
        self.site_ordinal += 1;
        origin
    }

    pub(super) fn record_construction(&mut self, name: &str, value: &Expression) {
        if !self.collect_edges {
            return;
        }
        let Some((site, class)) = construction_site(value) else {
            return;
        };
        let origin = if let Some(origin) = self.construction_origins.get(&site) {
            origin.clone()
        } else {
            let origin = self.next_go_site_origin();
            self.construction_origins.insert(site, origin.clone());
            origin
        };
        let ty = self.go_type_ref(&class);
        let mut arguments = self.seed_fn_args(value);
        merge_arguments(&mut arguments, self.struct_field_args(value));
        if self.local_vars.contains(name) || !self.package_vars.contains(name) {
            self.local_origins.insert(name.to_string(), origin.clone());
        }
        if let GoWalkOutput::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(CallEdge {
                condition: effinterp_proto::Condition::compose(&self.conditions),
                call_site: Some(self.condition_source.call_site(&(self.site_ordinal,))),
                callee: class,
                arguments,
                results: call_results(vec![(0, name.to_string())], Some(origin), ty),
                ..Default::default()
            });
        }
    }

    pub(super) fn record_declared_construction(&mut self, name: &str, class: &str) {
        if !self.collect_edges || name == "_" || GO_BUILTINS.contains(&class) {
            return;
        }
        let origin = self.next_go_site_origin();
        let ty = self.go_type_ref(class);
        if self.local_vars.contains(name) || !self.package_vars.contains(name) {
            self.local_origins.insert(name.to_string(), origin.clone());
        }
        if let GoWalkOutput::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(CallEdge {
                condition: effinterp_proto::Condition::compose(&self.conditions),
                call_site: Some(self.condition_source.call_site(&(self.site_ordinal,))),
                callee: class.to_string(),
                results: call_results(vec![(0, name.to_string())], Some(origin), ty),
                ..Default::default()
            });
        }
    }

    pub(super) fn record_declared_origin(&mut self, name: &str, class: &str) {
        if !self.collect_edges || name == "_" || GO_BUILTINS.contains(&class) {
            return;
        }
        let origin = self.next_go_site_origin();
        self.local_origins.insert(name.to_string(), origin);
    }

    fn seed_fn_args(&self, expr: &Expression) -> Vec<ValueArgument> {
        let literal = match expr {
            Expression::Paren(p) => return self.seed_fn_args(&p.expr),
            Expression::Operation(op) if op.y.is_none() => return self.seed_fn_args(&op.x),
            Expression::Star(star) => return self.seed_fn_args(&star.right),
            Expression::CompositeLit(literal) => &literal.val,
            _ => return Vec::new(),
        };
        let mut out = Vec::new();
        self.collect_seed_fn_args(literal, &mut out, 0);
        out
    }

    fn struct_field_args(&self, expr: &Expression) -> Vec<ValueArgument> {
        let literal = match expr {
            Expression::Paren(paren) => return self.struct_field_args(&paren.expr),
            Expression::Operation(operation) if operation.y.is_none() => {
                return self.struct_field_args(&operation.x);
            }
            Expression::Star(star) => return self.struct_field_args(&star.right),
            Expression::CompositeLit(literal) => &literal.val,
            _ => return Vec::new(),
        };
        literal
            .values
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                let name = match field.key.as_ref()? {
                    Element::Expr(Expression::Ident(id)) => id.name.clone(),
                    _ => return None,
                };
                if is_callback_field(&name) {
                    return None;
                }
                let instance = match &field.val {
                    Element::Expr(Expression::Ident(id))
                        if !GO_PREDECLARED_VALUES.contains(&id.name.as_str()) =>
                    {
                        self.go_argument_value(&id.name)
                    }
                    _ => return None,
                };
                Some(ValueArgument {
                    name: Some(name),
                    index,
                    value: instance,
                })
            })
            .collect()
    }

    fn collect_seed_fn_args(
        &self,
        literal: &gosyn::ast::LiteralValue,
        out: &mut Vec<ValueArgument>,
        depth: u32,
    ) {
        if depth >= MAX_WALK_DEPTH || out.len() >= MAX_SUMMARY_ITEMS {
            return;
        }
        for field in &literal.values {
            let callback = (|| {
                let key = match field.key.as_ref()? {
                    Element::Expr(Expression::Ident(id)) => id.name.clone(),
                    _ => return None,
                };
                if !is_callback_field(&key) {
                    return None;
                }
                let func = match &field.val {
                    Element::Expr(Expression::Ident(id)) => id.name.clone(),
                    Element::Expr(Expression::FuncLit(literal)) => {
                        let name = literal_function_name(literal);
                        if !self.funcs.contains_key(&name) {
                            return None;
                        }
                        name
                    }
                    _ => return None,
                };
                Some(ValueArgument {
                    name: Some(key),
                    index: 0,
                    value: SemanticValue::callable(func),
                })
            })();
            if let Some(callback) = callback {
                out.push(callback);
            }
            match &field.val {
                Element::Expr(Expression::CompositeLit(nested)) => {
                    self.collect_seed_fn_args(&nested.val, out, depth + 1)
                }
                Element::LitValue(nested) => self.collect_seed_fn_args(nested, out, depth + 1),
                _ => {}
            }
        }
    }

    pub(super) fn go_call_value_arguments(&mut self, args: &[Expression]) -> Vec<ValueArgument> {
        args.iter()
            .enumerate()
            .filter_map(|(index, arg)| {
                let value = match arg {
                    Expression::Ident(id) if GO_PREDECLARED_VALUES.contains(&id.name.as_str()) => {
                        return None;
                    }
                    Expression::Ident(id) if self.named_go_function(&id.name).is_some() => {
                        SemanticValue::callable(&id.name)
                    }
                    Expression::Ident(id)
                        if self.package_vars.contains(&id.name)
                            && !self.local_vars.contains(&id.name) =>
                    {
                        self.go_argument_value(&id.name)
                    }
                    Expression::Ident(id) => self
                        .values
                        .get(&id.name)
                        .cloned()
                        .unwrap_or_else(|| self.go_argument_value(&id.name)),
                    _ => self
                        .record_inline_construction(arg)
                        .or_else(|| self.go_semantic_value(arg))?,
                };
                if matches!(&value.kind, SemanticValueKind::Literal(_)) {
                    return None;
                }
                Some(ValueArgument {
                    name: None,
                    index,
                    value,
                })
            })
            .collect()
    }

    fn go_argument_value(&self, name: &str) -> SemanticValue {
        if self.params.contains_key(name) {
            SemanticValue::object(ObjectIdentity::Parameter {
                name: name.to_string(),
                fallback: self.go_receiver_type(name),
            })
        } else {
            self.go_receiver_value(name)
        }
    }

    pub(super) fn record_inline_construction(
        &mut self,
        expr: &Expression,
    ) -> Option<SemanticValue> {
        if !self.collect_edges {
            return None;
        }
        let (site, name) = construction_site(expr)?;
        let (origin, emit) = if let Some(origin) = self.construction_origins.get(&site) {
            (origin.clone(), false)
        } else {
            let origin = self.next_go_site_origin();
            self.construction_origins.insert(site, origin.clone());
            (origin, true)
        };
        let ty = self.go_type_ref(&name);
        let mut arguments = self.seed_fn_args(expr);
        merge_arguments(&mut arguments, self.struct_field_args(expr));
        let edge = CallEdge {
            callee: name.clone(),
            arguments,
            results: call_results(Vec::new(), Some(origin.clone()), ty.clone()),
            ..Default::default()
        };
        if emit
            && let GoWalkOutput::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(edge);
        }
        Some(
            SemanticValue::object(ObjectIdentity::Class {
                name,
                constructor: Vec::new(),
            })
            .with_origin(Some(origin))
            .with_type(ty),
        )
    }

    /// Record a Go call edge for repository composition with the current result bindings and writes.
    pub(super) fn record_go_call_edge(
        &mut self,
        callee: &str,
        args: Vec<ResourceExpr>,
        obj_args: Vec<ValueArgument>,
        origin: Option<ValueOrigin>,
    ) {
        self.push_edge(callee, args, obj_args, origin, false);
    }

    /// The call edge of a bare name: its arguments, plus the value bound to
    /// the name itself when this file knows one.
    pub(super) fn record_go_bare_call_edge(
        &mut self,
        name: &str,
        call: &gosyn::ast::Call,
        origin: Option<ValueOrigin>,
        dynamic: bool,
    ) {
        let arg_exprs: Vec<ResourceExpr> = call
            .args
            .iter()
            .map(|a| self.go_filesystem_resource(a))
            .collect();
        let mut obj_args = self.go_call_value_arguments(&call.args);
        // A symbol names a local binding, which composition can only resolve by
        // name — and that name belongs to the local scope, not the package.
        if let Some(value) = self.values.get(name).filter(|value| {
            !matches!(&value.kind, SemanticValueKind::Symbol(symbol)
                if self.local_vars.contains(symbol))
        }) {
            obj_args.push(ValueArgument {
                name: Some("$callee".to_string()),
                index: usize::MAX,
                value: value.clone(),
            });
        }
        self.push_edge(name, arg_exprs, obj_args, origin, dynamic);
    }

    /// A call through a locally bound name: composition may follow the value
    /// bound to it, but must never resolve the name against the package.
    pub(super) fn record_go_dynamic_call_edge(
        &mut self,
        callee: &str,
        args: Vec<ResourceExpr>,
        obj_args: Vec<ValueArgument>,
        origin: Option<ValueOrigin>,
    ) {
        self.push_edge(callee, args, obj_args, origin, true);
    }

    fn push_edge(
        &mut self,
        callee: &str,
        args: Vec<ResourceExpr>,
        obj_args: Vec<ValueArgument>,
        origin: Option<ValueOrigin>,
        dynamic_target: bool,
    ) {
        let binds = std::mem::take(&mut self.current_binds);
        let writes = std::mem::take(&mut self.pending_writes);
        let origin = origin.unwrap_or_else(|| self.next_go_site_origin());
        let mut arguments = positional_arguments(args);
        merge_arguments(&mut arguments, obj_args);
        if let GoWalkOutput::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(CallEdge {
                condition: effinterp_proto::Condition::compose(&self.conditions),
                call_site: Some(self.condition_source.call_site(&(self.site_ordinal,))),
                callee: callee.to_string(),
                arguments,
                results: call_results(binds, Some(origin), None),
                dynamic_target,
                writes,
                ..Default::default()
            });
        }
    }
}
