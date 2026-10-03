//! Python static containers: the values of statically listed lists, tuples,
//! dicts, comprehensions and finite generators, and the resources or instances
//! a loop over them visits.

use std::collections::HashSet;

use effinterp_proto::ResourceExpr;
use rustpython_parser::ast;
use rustpython_parser::ast::{Expr, Stmt};

use crate::summary::{is_resolvable, substitute_resource_expr};
use crate::value::unresolved_resource;
use crate::{SemanticValue, positional_arguments};

use super::resolve::str_literal;
use super::{
    PythonWalker, StaticContainer, StaticResource, bind_python_arguments, callee_written,
    expression_uses_name, int_literal, model,
};

impl PythonWalker<'_, '_> {
    pub(super) fn collection_item(&self, expr: &Expr) -> Option<ResourceExpr> {
        let Expr::Subscript(subscript) = expr else {
            return None;
        };
        let Expr::Name(name) = subscript.value.as_ref() else {
            return None;
        };
        match self.collections.get(name.id.as_str())? {
            StaticContainer::Sequence(values) => values
                .get(int_literal(&subscript.slice)? as usize)
                .map(|value| value.resource.clone()),
            StaticContainer::Mapping(values) => values
                .get(&str_literal(&subscript.slice)?)
                .map(|value| value.resource.clone()),
        }
    }

    pub(super) fn invalidate_collection(&mut self, name: &str) {
        // Containers may share nested mutable values even when their outer shapes differ.
        self.modeled_values
            .retain(|_, value| !matches!(value, model::ModeledValue::BuiltinData));
        if let Some(instances) = self.instance_sequences.remove(name) {
            self.instance_sequences
                .retain(|_, candidate| candidate != &instances);
        }
        self.deferred_containers.remove(name);
        let Some(value) = self.collections.remove(name) else {
            return;
        };
        self.collections.retain(|_, candidate| candidate != &value);
    }

    pub(super) fn static_container(&self, expr: &Expr) -> Option<StaticContainer> {
        let sequence = |elts: &[Expr]| {
            if elts.len() > self.nest.limits.value_limits().max_cardinality {
                return None;
            }
            elts.iter()
                .map(|expr| {
                    let resource = if let Some(value) = str_literal(expr) {
                        ResourceExpr::Literal { value }
                    } else {
                        let resource = self.resolve_fs(expr);
                        if !is_resolvable(&resource) {
                            return None;
                        }
                        resource
                    };
                    Some(StaticResource {
                        resource,
                        is_path: self.is_path_value(expr),
                    })
                })
                .collect::<Option<Vec<_>>>()
                .map(StaticContainer::Sequence)
        };
        match expr {
            Expr::List(list) => sequence(&list.elts),
            Expr::Tuple(tuple) => sequence(&tuple.elts),
            Expr::Set(set) => sequence(&set.elts),
            Expr::Dict(dict) => {
                if dict.values.len() > self.nest.limits.value_limits().max_cardinality {
                    return None;
                }
                let mut values = std::collections::HashMap::new();
                for (key, value) in dict.keys.iter().zip(&dict.values) {
                    let key = str_literal(key.as_ref()?)?;
                    let resource = str_literal(value)
                        .map(|value| ResourceExpr::Literal { value })
                        .unwrap_or_else(|| self.resolve_fs(value));
                    if !is_resolvable(&resource) {
                        return None;
                    }
                    values.insert(
                        key,
                        StaticResource {
                            resource,
                            is_path: self.is_path_value(value),
                        },
                    );
                }
                Some(StaticContainer::Mapping(values))
            }
            Expr::ListComp(comprehension) => self
                .static_comprehension_values(&comprehension.elt, &comprehension.generators)
                .map(StaticContainer::Sequence),
            Expr::SetComp(comprehension) => self
                .static_comprehension_values(&comprehension.elt, &comprehension.generators)
                .map(StaticContainer::Sequence),
            Expr::GeneratorExp(comprehension) => self
                .static_comprehension_values(&comprehension.elt, &comprehension.generators)
                .map(StaticContainer::Sequence),
            Expr::Call(call)
                if matches!(
                    callee_written(&call.func).as_deref(),
                    Some("list" | "tuple" | "set")
                ) =>
            {
                let value = call.args.first()?;
                self.static_resources(value)
                    .or_else(|| self.static_iter_resources(value))
                    .map(StaticContainer::Sequence)
            }
            Expr::Name(name) => self.collections.get(name.id.as_str()).cloned(),
            _ => None,
        }
    }

    pub(super) fn static_comprehension_values(
        &self,
        element: &Expr,
        generators: &[ast::Comprehension],
    ) -> Option<Vec<StaticResource>> {
        let [generator] = generators else {
            return None;
        };
        if !generator.ifs.is_empty() {
            return None;
        }
        let Expr::Name(target) = &generator.target else {
            return None;
        };
        let target_name = target.id.to_string();
        let target_names = HashSet::from([target_name.clone()]);
        let element_uses_target = expression_uses_name(element, &target_names);
        let mut scope = self.var_scope.clone();
        self.static_resources(&generator.iter)?
            .into_iter()
            .map(|value| {
                let target_is_path = value.is_path;
                scope.insert(target_name.clone(), value.resource);
                let resource = substitute_resource_expr(&self.fs_resource(element), &scope);
                is_resolvable(&resource).then_some(StaticResource {
                    resource,
                    is_path: match element {
                        Expr::Name(name) if name.id.as_str() == target_name => target_is_path,
                        _ if element_uses_target => false,
                        _ => self.is_path_value(element),
                    },
                })
            })
            .collect()
    }

    pub(super) fn static_sequence(&self, expr: &Expr) -> Option<Vec<ResourceExpr>> {
        self.static_resources(expr)
            .map(|values| values.into_iter().map(|value| value.resource).collect())
    }

    pub(super) fn static_resources(&self, expr: &Expr) -> Option<Vec<StaticResource>> {
        if let Some(model::ModeledValue::Temporary { resource, kind }) = self.modeled_value(expr)
            && kind == "tempfile.mkstemp"
        {
            return Some(vec![
                StaticResource {
                    resource: unresolved_resource("process"),
                    is_path: false,
                },
                StaticResource {
                    resource,
                    is_path: false,
                },
            ]);
        }
        match self.static_container(expr)? {
            StaticContainer::Sequence(values) => Some(values),
            StaticContainer::Mapping(_) => None,
        }
    }

    pub(super) fn static_iter_resources(&self, expr: &Expr) -> Option<Vec<StaticResource>> {
        if let Some(values) = self.static_resources(expr) {
            return Some(values);
        }
        let Expr::Call(call) = expr else {
            return None;
        };
        let name = self.local_callee(&call.func)?;
        let def = self
            .defs
            .iter()
            .find(|def| def.name == name && def.is_generator)?;
        let arguments = positional_arguments(call.args.iter().map(|arg| self.resolve_value(arg)));
        let bindings = bind_python_arguments(&def.params, def.positional_param_count, &arguments);
        let mut scope = self.consts.clone();
        scope.extend(
            bindings
                .into_iter()
                .map(|(name, value)| (name, value.lower_resource())),
        );
        let mut values = Vec::new();
        self.collect_generator_values(&def.body, &mut scope, &mut values)?;
        Some(
            values
                .into_iter()
                .map(|resource| StaticResource {
                    resource,
                    is_path: false,
                })
                .collect(),
        )
    }

    /// Constructor identities of a statically listed loop iterable, in AST order.
    pub(super) fn static_iter_instances(&self, iter: &Expr) -> Option<Vec<Option<SemanticValue>>> {
        let elts = match iter {
            Expr::Name(name) => return self.instance_sequences.get(name.id.as_str()).cloned(),
            Expr::List(list) => list.elts.as_slice(),
            Expr::Tuple(tuple) => tuple.elts.as_slice(),
            Expr::Set(set) => set.elts.as_slice(),
            _ => return None,
        };
        if elts.len() > self.nest.limits.value_limits().max_cardinality {
            return None;
        }
        Some(elts.iter().map(|expr| self.instance_value(expr)).collect())
    }

    pub(super) fn static_iter_values(&self, expr: &Expr) -> Option<Vec<ResourceExpr>> {
        self.static_iter_resources(expr)
            .map(|values| values.into_iter().map(|value| value.resource).collect())
    }

    pub(super) fn static_sequence_in_scope(
        &self,
        expr: &Expr,
        scope: &std::collections::HashMap<String, ResourceExpr>,
    ) -> Option<Vec<ResourceExpr>> {
        let elts = match expr {
            Expr::List(list) => &list.elts,
            Expr::Tuple(tuple) => &tuple.elts,
            Expr::Set(set) => &set.elts,
            Expr::Name(name) => {
                let StaticContainer::Sequence(values) = self.collections.get(name.id.as_str())?
                else {
                    return None;
                };
                return Some(values.iter().map(|value| value.resource.clone()).collect());
            }
            _ => return None,
        };
        if elts.len() > self.nest.limits.value_limits().max_cardinality {
            return None;
        }
        elts.iter()
            .map(|expr| {
                if let Some(value) = str_literal(expr) {
                    return Some(ResourceExpr::Literal { value });
                }
                let value = substitute_resource_expr(&self.fs_resource(expr), scope);
                is_resolvable(&value).then_some(value)
            })
            .collect()
    }

    /// Recover yielded resources only through statically finite generator
    /// paths. The boolean reports an encountered `return`, which terminates an
    /// enclosing finite loop as well as the current statement list.
    pub(super) fn collect_generator_values(
        &self,
        body: &[Stmt],
        scope: &mut std::collections::HashMap<String, ResourceExpr>,
        out: &mut Vec<ResourceExpr>,
    ) -> Option<bool> {
        for stmt in body {
            match stmt {
                Stmt::Expr(stmt) => match stmt.value.as_ref() {
                    Expr::Yield(yielded) => {
                        if let Some(expr) = &yielded.value {
                            let value = substitute_resource_expr(&self.fs_resource(expr), scope);
                            if !is_resolvable(&value) {
                                return None;
                            }
                            out.push(self.lower_fs_literal(value));
                        }
                    }
                    Expr::YieldFrom(yielded) => {
                        out.extend(
                            self.static_sequence_in_scope(&yielded.value, scope)?
                                .into_iter()
                                .map(|value| self.lower_fs_literal(value)),
                        );
                    }
                    _ => {}
                },
                Stmt::Assign(assign) => {
                    let [Expr::Name(name)] = assign.targets.as_slice() else {
                        return None;
                    };
                    let value = substitute_resource_expr(&self.fs_resource(&assign.value), scope);
                    if !is_resolvable(&value) {
                        return None;
                    }
                    scope.insert(name.id.to_string(), value);
                }
                Stmt::AnnAssign(assign) => {
                    let Expr::Name(name) = assign.target.as_ref() else {
                        return None;
                    };
                    let value = assign.value.as_deref()?;
                    let value = substitute_resource_expr(&self.fs_resource(value), scope);
                    if !is_resolvable(&value) {
                        return None;
                    }
                    scope.insert(name.id.to_string(), value);
                }
                Stmt::For(stmt) => {
                    let Expr::Name(target) = stmt.target.as_ref() else {
                        return None;
                    };
                    let values = self.static_sequence_in_scope(&stmt.iter, scope)?;
                    for value in values {
                        scope.insert(target.id.to_string(), value);
                        if self.collect_generator_values(&stmt.body, scope, out)? {
                            return Some(true);
                        }
                    }
                    if self.collect_generator_values(&stmt.orelse, scope, out)? {
                        return Some(true);
                    }
                }
                Stmt::With(stmt) => {
                    if self.collect_generator_values(&stmt.body, scope, out)? {
                        return Some(true);
                    }
                }
                Stmt::Return(_) => return Some(true),
                Stmt::Pass(_) => {}
                // A branch, unbounded loop, break, or other dynamic statement
                // cannot prove one finite sequence of yielded resources.
                _ => return None,
            }
            if out.len() > self.nest.limits.value_limits().max_cardinality {
                return None;
            }
        }
        Some(false)
    }
}
