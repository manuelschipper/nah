//! Go semantic values recovered from expressions and bindings.

use std::collections::BTreeMap;

use gosyn::ast::{Element, Expression};
use gosyn::token::Operator;

use crate::{
    CallableValue, ObjectIdentity, SemanticValue, SemanticValueKind, TypeRef, ValueArgument,
    join_branches,
};

use super::call_resolution::GoCallee;
use super::model::string_of;
use super::summary::{
    constructed_class, is_callback_field, is_str_lit, literal_function_name, named_type_ref,
    unquote_go_string,
};
use super::walker::GoWalker;

pub(super) const GO_PREDECLARED_VALUES: [&str; 4] = ["nil", "true", "false", "iota"];

/// The exact value an object holds under `name`, whether it was assigned as a
/// property or supplied as a named field of the composite literal that built it.
pub(super) fn exact_go_property_value(
    value: &SemanticValue,
    name: &str,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    // A branch that reassigns a field joins the objects into a union, and the
    // read is exact when every alternative answers it: the field holds one of a
    // finite set, which stays explicit instead of collapsing to an opaque
    // property the walk can no longer see a callable in.
    if let SemanticValueKind::Union(alternatives) = &value.kind {
        let values = alternatives
            .iter()
            .map(|alternative| exact_go_property_value(alternative, name, value_limits))
            .collect::<Option<Vec<_>>>()?;
        return Some(join_branches(values, value_limits));
    }
    let SemanticValueKind::Object(object) = &value.kind else {
        return None;
    };
    if let Some(property) = object.properties.get(name) {
        return Some(property.clone());
    }
    let ObjectIdentity::Class { constructor, .. } = &object.identity else {
        return None;
    };
    constructor
        .iter()
        .find(|argument| argument.name.as_deref() == Some(name))
        .map(|argument| argument.value.clone())
}

impl GoWalker<'_, '_> {
    pub(super) fn bind_go_semantic_value(&mut self, left: &Expression, right: &Expression) {
        if !self.collect_edges
            && self.fact_scope.is_none()
            && let Expression::Selector(selector) = left
            && let Expression::Ident(base) = &*selector.x
            && self.package_vars.contains(&base.name)
            && is_callback_field(&selector.sel.name)
        {
            match right {
                Expression::Ident(name) if self.named_go_function(&name.name).is_some() => {
                    self.callback_roots.insert(name.name.clone());
                }
                Expression::FuncLit(literal) => {
                    self.callback_roots.insert(literal_function_name(literal));
                }
                _ => {}
            }
        }
        match left {
            Expression::Ident(name) if name.name != "_" => {
                let value = match right {
                    Expression::FuncLit(_) if self.named_go_function(&name.name).is_some() => {
                        Some(SemanticValue::callable(&name.name))
                    }
                    Expression::Call(call) => self
                        .deferred_callback_value(call)
                        .or_else(|| self.go_semantic_value(right)),
                    _ => self.go_semantic_value(right),
                }
                .or_else(|| {
                    matches!(right, Expression::Call(_)).then(|| SemanticValue::symbol(&name.name))
                });
                if let Some(value) = value {
                    self.values.insert(name.name.clone(), value);
                } else {
                    self.values.remove(&name.name);
                }
            }
            Expression::Selector(selector) => {
                let Expression::Ident(base) = &*selector.x else {
                    return;
                };
                let Some(value) = self.go_semantic_value(right) else {
                    return;
                };
                if let Some(base) = self.values.get_mut(&base.name)
                    && let SemanticValueKind::Object(object) = &mut base.kind
                {
                    object.properties.insert(selector.sel.name.clone(), value);
                }
            }
            _ => {}
        }
    }

    /// Recover a Go semantic value, keeping symbolic bindings available to call and resource recovery.
    pub(super) fn go_semantic_value(&self, expr: &Expression) -> Option<SemanticValue> {
        match expr {
            Expression::BasicLit(literal) if is_str_lit(literal) => {
                Some(SemanticValue::literal(unquote_go_string(&literal.value)))
            }
            Expression::Ident(ident) => self.values.get(&ident.name).cloned().or_else(|| {
                if self.named_go_function(&ident.name).is_some() {
                    Some(SemanticValue::callable(&ident.name))
                } else if self.local_vars.contains(&ident.name) {
                    Some(SemanticValue::symbol(&ident.name))
                } else if !GO_PREDECLARED_VALUES.contains(&ident.name.as_str())
                    && let Some(scope) = &self.fact_scope
                {
                    Some(SemanticValue::object(ObjectIdentity::ModuleBinding {
                        scope: scope.clone(),
                        name: ident.name.clone(),
                    }))
                } else {
                    None
                }
            }),
            Expression::Paren(paren) => self.go_semantic_value(&paren.expr),
            Expression::Operation(operation) if operation.y.is_none() => {
                self.go_semantic_value(&operation.x)
            }
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                // Keep the additive spine iterative because generated Go can be thousands deep.
                let mut expressions: Vec<&Expression> =
                    vec![operation.y.as_ref().unwrap().as_ref(), operation.x.as_ref()];
                let mut parts = Vec::new();
                while let Some(expression) = expressions.pop() {
                    match expression {
                        Expression::Paren(paren) => expressions.push(paren.expr.as_ref()),
                        Expression::Operation(operation)
                            if operation.op == Operator::Add && operation.y.is_some() =>
                        {
                            expressions.push(operation.y.as_ref().unwrap().as_ref());
                            expressions.push(operation.x.as_ref());
                        }
                        _ => parts.push(self.go_semantic_value(expression)?),
                    }
                }
                if parts.iter().any(|value| {
                    matches!(
                        &value.kind,
                        SemanticValueKind::Environment(_) | SemanticValueKind::Join(_)
                    ) || matches!(
                        &value.kind,
                        SemanticValueKind::Unresolved { family, .. } if family == "environment"
                    )
                }) {
                    Some(SemanticValue::new(SemanticValueKind::Join(parts)))
                } else {
                    None
                }
            }
            Expression::Star(star) => self.go_semantic_value(&star.right),
            Expression::Selector(selector) => {
                if let Expression::Ident(package) = &*selector.x
                    && (self.imports.contains_key(&package.name)
                        || self
                            .named_go_function(&format!("{}.{}", package.name, selector.sel.name))
                            .is_some())
                {
                    let name = format!("{}.{}", package.name, selector.sel.name);
                    return Some(if self.fact_scope.is_none() {
                        SemanticValue::callable(name)
                    } else {
                        SemanticValue::symbol(name)
                    });
                }
                if let Expression::Ident(receiver) = &*selector.x
                    && let Some(value) = self.values.get(&receiver.name).and_then(|value| {
                        exact_go_property_value(value, &selector.sel.name, self.value_limits)
                    })
                {
                    return Some(value);
                }
                if let Expression::Ident(receiver) = &*selector.x
                    && self.fact_function.split_once('.').is_some_and(|(typ, _)| {
                        self.go_receiver_type(&receiver.name).as_deref() == Some(typ)
                    })
                {
                    return Some(SemanticValue::parameter(&selector.sel.name));
                }
                let base = match &*selector.x {
                    Expression::Ident(ident) => {
                        // An object whose field this walk knows exactly answers
                        // the read exactly, so a callable stored in a struct
                        // stays reachable when it is passed on.
                        if let Some(property) = self.values.get(&ident.name).and_then(|value| {
                            exact_go_property_value(value, &selector.sel.name, self.value_limits)
                        }) {
                            return Some(property);
                        }
                        self.go_receiver_value(&ident.name)
                    }
                    expression => self.go_semantic_value(expression)?,
                };
                Some(SemanticValue::new(SemanticValueKind::Property {
                    base: Box::new(base),
                    name: selector.sel.name.clone(),
                }))
            }
            Expression::Index(index) => {
                let value = self.go_semantic_value(&index.left)?;
                if let Expression::BasicLit(key) = &*index.index
                    && is_str_lit(key)
                    && let SemanticValueKind::Collection { properties, .. } = &value.kind
                {
                    return properties.get(&unquote_go_string(&key.value)).cloned();
                }
                let index = match &*index.index {
                    Expression::BasicLit(literal) => literal.value.parse::<usize>().ok()?,
                    _ => return None,
                };
                match value.kind {
                    SemanticValueKind::Collection { elements, .. } => elements.get(index).cloned(),
                    _ => None,
                }
            }
            Expression::CompositeLit(literal) => {
                if matches!(&*literal.typ, Expression::TypeMap(_)) {
                    let properties = literal
                        .val
                        .values
                        .iter()
                        .filter_map(|field| {
                            let Some(Element::Expr(key)) = &field.key else {
                                return None;
                            };
                            let Element::Expr(value) = &field.val else {
                                return None;
                            };
                            Some((string_of(key)?, self.go_semantic_value(value)?))
                        })
                        .collect();
                    return Some(SemanticValue::new(SemanticValueKind::Collection {
                        elements: Vec::new(),
                        properties,
                    }));
                }
                if matches!(
                    &*literal.typ,
                    Expression::TypeSlice(_) | Expression::TypeArray(_)
                ) {
                    return Some(self.collection_value(&literal.val));
                }
                let name = constructed_class(expr)?;
                let arguments = literal
                    .val
                    .values
                    .iter()
                    .enumerate()
                    .filter_map(|(index, field)| {
                        let value = match &field.val {
                            Element::Expr(value) => self.go_semantic_value(value)?,
                            Element::LitValue(value) => self.collection_value(value),
                        };
                        let name = match field.key.as_ref() {
                            Some(Element::Expr(Expression::Ident(name))) => Some(name.name.clone()),
                            _ => None,
                        };
                        Some(ValueArgument { name, index, value })
                    })
                    .collect();
                Some(
                    SemanticValue::object(ObjectIdentity::Class {
                        name: name.clone(),
                        constructor: arguments,
                    })
                    .with_type(self.go_type_ref(&name)),
                )
            }
            Expression::FuncLit(literal) => {
                if self.fact_scope.is_none() {
                    Some(
                        SemanticValue::new(SemanticValueKind::Callable(CallableValue::Closure {
                            name: literal_function_name(literal),
                            captures: self
                                .values
                                .iter()
                                .map(|(name, value)| (name.clone(), value.clone()))
                                .collect(),
                        }))
                        .canonicalize(self.value_limits),
                    )
                } else {
                    Some(SemanticValue::callable(literal_function_name(literal)))
                }
            }
            Expression::Call(call) => {
                if let GoCallee::Pkg { path, method, .. } = self.resolve_go_callee(&call.func)
                    && path == "os"
                    && matches!(method.as_str(), "Getenv" | "LookupEnv")
                {
                    return Some(
                        call.args
                            .first()
                            .and_then(string_of)
                            .filter(|name| !name.is_empty())
                            .map(|name| SemanticValue::new(SemanticValueKind::Environment(name)))
                            .unwrap_or_else(|| SemanticValue::unresolved("environment")),
                    );
                }
                if self.fact_scope.is_none()
                    && let GoCallee::Local(name) = self.resolve_go_callee(&call.func)
                    && let Some(summary) = self.summaries.get(&name)
                    && let Some(value) = &summary.returns
                {
                    let bindings = summary
                        .params
                        .iter()
                        .zip(&call.args)
                        .filter_map(|(name, arg)| {
                            Some((name.clone(), self.go_semantic_value(arg)?))
                        })
                        .collect();
                    return Some(crate::substitute_value(value, &bindings, self.value_limits));
                }
                if matches!(&*call.func, Expression::Ident(ident) if ident.name == "append") {
                    let mut elements = Vec::new();
                    for argument in &call.args {
                        let value = self.go_semantic_value(argument)?;
                        match value.kind {
                            SemanticValueKind::Collection {
                                elements: nested, ..
                            } => elements.extend(nested),
                            _ => elements.push(value),
                        }
                    }
                    return Some(SemanticValue::new(SemanticValueKind::Collection {
                        elements,
                        properties: BTreeMap::new(),
                    }));
                }
                None
            }
            _ => None,
        }
    }

    fn collection_value(&self, literal: &gosyn::ast::LiteralValue) -> SemanticValue {
        SemanticValue::new(SemanticValueKind::Collection {
            elements: literal
                .values
                .iter()
                .filter_map(|element| match &element.val {
                    Element::Expr(value) => self.go_semantic_value(value),
                    Element::LitValue(value) => Some(self.collection_value(value)),
                })
                .collect(),
            properties: BTreeMap::new(),
        })
    }

    pub(super) fn go_receiver_value(&self, recv: &str) -> SemanticValue {
        if let Some((base, attr)) = recv.split_once('.') {
            let receiver_type = self
                .fact_function
                .split_once('.')
                .map(|(receiver, _)| receiver);
            if receiver_type
                .is_some_and(|receiver| self.go_receiver_type(base).as_deref() == Some(receiver))
            {
                return SemanticValue::object(ObjectIdentity::ReceiverProperty(attr.to_string()));
            }
            return SemanticValue::object(ObjectIdentity::LocalProperty {
                name: base.to_string(),
                property: attr.to_string(),
            });
        }
        if self.bound_vars.contains(recv) {
            return SemanticValue::object(ObjectIdentity::Local {
                name: recv.to_string(),
                fallback: self.go_receiver_type(recv),
            });
        }
        if self.params.contains_key(recv) && !self.fact_function.starts_with("func#") {
            return SemanticValue::object(ObjectIdentity::Parameter {
                name: recv.to_string(),
                fallback: self.go_receiver_type(recv),
            });
        }
        if let Some(instance) = self.instance_aliases.get(recv) {
            return instance.clone();
        }
        let typ = self.go_receiver_type(recv);
        if !self.local_vars.contains(recv)
            && !GO_PREDECLARED_VALUES.contains(&recv)
            && (self.package_vars.contains(recv)
                || (self.fact_scope.is_some() && typ.is_none() && !self.params.contains_key(recv)))
            && let Some(scope) = &self.fact_scope
        {
            return SemanticValue::object(ObjectIdentity::ModuleBinding {
                scope: scope.clone(),
                name: recv.to_string(),
            })
            .with_type(typ.as_deref().and_then(|ty| self.go_type_ref(ty)));
        }
        match typ {
            Some(typ) => SemanticValue::object(ObjectIdentity::Class {
                name: typ,
                constructor: Vec::new(),
            })
            .with_origin(self.local_origins.get(recv).cloned())
            .with_type(
                self.go_receiver_type(recv)
                    .as_deref()
                    .and_then(|ty| self.go_type_ref(ty)),
            ),
            None => SemanticValue::object(ObjectIdentity::Local {
                name: recv.to_string(),
                fallback: None,
            }),
        }
    }

    pub(super) fn go_type_ref(&self, typ: &str) -> Option<TypeRef> {
        named_type_ref(self.imports, &self.repo_types, &self.fact_file, typ)
    }
}
