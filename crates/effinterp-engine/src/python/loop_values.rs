//! Python loop values.
//! Known iterations bind their exact members, and unknown iterations can rebind anything the body writes.

use std::collections::BTreeSet;

use rustpython_parser::ast;
use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{Expr, Stmt};

use super::branch_join::BranchGuard;
use super::literal_values::int_literal;
use super::name_bindings::{rebound_body_names, rebound_target_names};
use super::{PythonWalker, model};

/// A literal that iterates at least once: a nonempty string or a container
/// display with at least one element and no unpacking.
fn literal_nonempty(iter: &Expr) -> bool {
    let elements = match iter {
        Expr::List(list) => &list.elts,
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::Set(set) => &set.elts,
        Expr::Dict(dict) => return dict.keys.iter().any(Option::is_some),
        Expr::Constant(constant) => {
            return matches!(&constant.value, ast::Constant::Str(text) if !text.is_empty());
        }
        _ => return false,
    };
    !elements.is_empty()
        && !elements
            .iter()
            .any(|element| matches!(element, Expr::Starred(_)))
}

impl PythonWalker<'_, '_> {
    pub(super) fn invalidate_loop_bindings(&mut self, body: &[Stmt]) {
        let mut names = rebound_body_names(body, false);
        names.extend(self.shared_vars.iter().cloned());
        // Mutable values can change through an alias on an earlier iteration.
        names.extend(
            self.modeled_values
                .iter()
                .filter(|(_, value)| {
                    matches!(
                        value,
                        model::ModeledValue::BuiltinData | model::ModeledValue::Request { .. }
                    )
                })
                .map(|(name, _)| name.clone()),
        );
        for name in names {
            self.invalidate_rebound_name(&name);
        }
    }

    /// Bind exact loop members when known, otherwise walk a conditional body with widened bindings.
    pub(super) fn walk_for(&mut self, target: &Expr, iter: &Expr, body: &[Stmt], orelse: &[Stmt]) {
        let zero_loop = self.enter_zero_loop(
            target,
            iter,
            body.iter().filter_map(|statement| match statement {
                Stmt::Expr(statement) => Some(statement.value.as_ref()),
                _ => None,
            }),
        );
        let before = self.capture.as_ref().map(|capture| capture.effects.len());
        let iterated = self.flow_deferred(iter);
        // In a summarized body a single loop target holds an element of
        // `iter`: an item of a list, a line of a file, a key of a dict.
        // Unpacked targets are not projected.
        let element = before.map(|before| match (target, iter) {
            (Expr::Name(_), Expr::Dict(dict)) => dict
                .keys
                .iter()
                .flatten()
                .flat_map(|key| self.carried_effects(key, before))
                .collect(),
            (Expr::Name(_), _) => self.carried_effects(iter, before),
            _ => Vec::new(),
        });
        let rebound = rebound_target_names(target);
        let prior_printed = self.printed_by(&rebound);
        let path_iter_resource = self.path_iter_resource(iter);
        let static_values = self.static_iter_resources(iter);
        let static_instances = self.static_iter_instances(iter);
        let loop_name = match target {
            Expr::Name(name) => Some(name.id.to_string()),
            _ => None,
        };
        let prior_classes = loop_name
            .as_ref()
            .and_then(|name| self.class_set_vars.remove(name));
        let prior_deferred = loop_name
            .as_ref()
            .and_then(|name| self.deferred_vars.remove(name));
        if let (Some(loop_name), Expr::Name(iter)) = (&loop_name, iter)
            && let Some(classes) = self.class_sets.get(iter.id.as_str())
        {
            self.class_set_vars
                .insert(loop_name.clone(), classes.clone());
        }
        if let (Some(loop_name), Expr::Name(iter)) = (&loop_name, iter)
            && let Some(calls) = self.deferred_containers.get(iter.id.as_str())
        {
            self.deferred_vars.insert(loop_name.clone(), calls.clone());
        }
        self.invalidate_loop_bindings(body);
        self.walk_assignment_target(target);
        self.invalidate_rebound_target(target);
        if let Some(loop_name) = &loop_name
            && let Some(receiver) = &path_iter_resource
        {
            self.clear_bound_receiver(loop_name);
            self.var_scope.insert(loop_name.clone(), receiver.clone());
            self.path_vars.insert(loop_name.clone());
            self.branch_mixed_path_vars.remove(loop_name);
            self.widened_vars.remove(loop_name);
        }
        if path_iter_resource.is_none() && (loop_name.is_none() || static_values.is_none()) {
            self.invalidate_rebound_target(target);
        }
        if let Some(element) = element {
            self.rebind_printed(&rebound, &element);
        }
        // Outside a summary the single loop target carries what `iter` does,
        // as a part of it rather than the same value.
        if let (Some(name), Some(iterated)) = (&loop_name, iterated) {
            let node = self.span_node(iter.range());
            let element = self.stage_writer.join_values(node, &[iterated]);
            self.flow_vars.insert(name.clone(), element);
        }

        if let Some(name) = &loop_name
            && let Some(values) = static_values
        {
            let instances = static_instances.unwrap_or_default();
            let prior_flow = self.flow_vars.clone();
            for (index, value) in values.into_iter().enumerate() {
                self.modeled_values.remove(name);
                self.clear_bound_receiver(name);
                self.widened_vars.remove(name);
                self.concatenated_vars.remove(name);
                self.unbounded_string_vars.remove(name);
                self.var_scope.insert(name.clone(), value.resource);
                if value.is_path {
                    self.path_vars.insert(name.clone());
                } else {
                    self.path_vars.remove(name);
                }
                self.branch_mixed_path_vars.remove(name);
                if let Some(instance) = instances.get(index).cloned().flatten() {
                    self.instance_vars.insert(name.clone(), instance);
                }
                self.walk_body(body);
            }
            self.flow_vars = prior_flow;
            self.walk_body(orelse);
        } else if let Some(name) = &loop_name
            && let Some(instances) = static_instances
            && instances.iter().any(Option::is_some)
        {
            let prior_flow = self.flow_vars.clone();
            for instance in instances {
                self.invalidate_rebound_name(name);
                if let Some(instance) = instance {
                    self.instance_vars.insert(name.clone(), instance);
                }
                self.walk_body(body);
            }
            self.flow_vars = prior_flow;
            self.walk_body(orelse);
        } else {
            self.walk_branches(
                &[(body, None, None), (orelse, None, None)],
                Some(BranchGuard::selection(
                    iter.range(),
                    effinterp_proto::ConditionKind::Loop,
                    false,
                )),
            );
        }

        if let Some(loop_name) = loop_name {
            self.class_set_vars.remove(&loop_name);
            if let Some(prior) = prior_classes {
                self.class_set_vars.insert(loop_name.clone(), prior);
            }
            self.deferred_vars.remove(&loop_name);
            if let Some(prior) = prior_deferred {
                self.deferred_vars.insert(loop_name, prior);
            }
        }
        // After the loop the target may still hold its prior value, unless a
        // nonempty literal proves the loop ran and no enclosing branch can be
        // skipped.
        if !literal_nonempty(iter) || self.capture_conditional() {
            self.restore_printed(prior_printed);
        }
        for call in zero_loop {
            self.zero_loop_calls.remove(&call);
        }
    }

    /// Record the calls among `every_pass` (the expressions a loop evaluates
    /// on each pass) when the loop variable iterates a literal integer
    /// sequence holding 0: `(0, 1, 2)`, `[0, 1, 2]`, `range(stop)`,
    /// `range(0, stop)` or `range(0, stop, step)`. Returns the recorded keys.
    fn enter_zero_loop<'e>(
        &mut self,
        target: &Expr,
        iter: &Expr,
        every_pass: impl Iterator<Item = &'e Expr>,
    ) -> Vec<u32> {
        let Expr::Name(name) = target else {
            return Vec::new();
        };
        let holds_zero = match iter {
            Expr::Tuple(ast::ExprTuple { elts, .. }) | Expr::List(ast::ExprList { elts, .. }) => {
                elts.iter().all(|element| int_literal(element).is_some())
                    && elts.iter().any(|element| int_literal(element) == Some(0))
            }
            // `range(stop)` starts at 0, as a literal start of 0 does; a
            // positive step keeps it the first value.
            Expr::Call(call) => {
                let positive = |value: &Expr| int_literal(value).is_some_and(|value| value > 0);
                self.imports.resolve_callee(&call.func).as_deref() == Some("range")
                    && call.keywords.is_empty()
                    && match call.args.as_slice() {
                        [stop] => positive(stop),
                        [start, stop] => int_literal(start) == Some(0) && positive(stop),
                        [start, stop, step] => {
                            int_literal(start) == Some(0) && positive(stop) && positive(step)
                        }
                        _ => false,
                    }
            }
            _ => false,
        };
        if !holds_zero {
            return Vec::new();
        }
        every_pass
            .filter_map(|expression| match expression {
                Expr::Call(call) => Some(u32::from(call.range().start())),
                _ => None,
            })
            .filter(|call| {
                self.zero_loop_calls
                    .insert(*call, name.id.to_string())
                    .is_none()
            })
            .collect()
    }

    /// Bind comprehension targets locally and restore outer bindings when iteration ends.
    pub(super) fn walk_comprehension(
        &mut self,
        element: &Expr,
        value: Option<&Expr>,
        generators: &[ast::Comprehension],
    ) -> bool {
        // A filter decides which passes evaluate the element.
        let unfiltered = generators.iter().all(|generator| generator.ifs.is_empty());
        let zero_loops: Vec<_> = generators
            .iter()
            .filter(|_| unfiltered)
            .flat_map(|generator| {
                self.enter_zero_loop(
                    &generator.target,
                    &generator.iter,
                    std::iter::once(element).chain(value),
                )
            })
            .collect();
        let walked = self.walk_comprehension_values(element, value, generators);
        for call in zero_loops {
            self.zero_loop_calls.remove(&call);
        }
        walked
    }

    /// Walk a comprehension once per statically known value of its single
    /// generator's iterable, with the loop variable bound to that value. Any
    /// other shape is walked untracked.
    fn walk_comprehension_values(
        &mut self,
        element: &Expr,
        value: Option<&Expr>,
        generators: &[ast::Comprehension],
    ) -> bool {
        let [generator] = generators else {
            return self.walk_untracked_comprehension(element, value, generators);
        };
        let Expr::Name(target) = &generator.target else {
            return self.walk_untracked_comprehension(element, value, generators);
        };
        let Some(values) = self.static_resources(&generator.iter) else {
            return self.walk_untracked_comprehension(element, value, generators);
        };
        self.walk_expr(&generator.iter);
        let name = target.id.to_string();
        let prior = self.var_scope.get(&name).cloned();
        let prior_path = self.path_vars.contains(&name);
        let prior_branch_mixed_path = self.branch_mixed_path_vars.contains(&name);
        let prior_concatenated = self.concatenated_vars.contains(&name);
        let prior_unbounded_string = self.unbounded_string_vars.contains(&name);
        let prior_widened = self.widened_vars.contains(&name);
        let prior_instance = self.instance_vars.get(&name).cloned();
        let prior_bound = self.bound_vars.contains(&name);
        let prior_receiver_rebinding = self.receiver_rebindings.contains(&name);
        let prior_modeled = self.modeled_values.remove(&name);
        let mut prior_imports = self.imports.clone();
        self.imports.shadow(&name);
        for item in values {
            self.modeled_values.remove(&name);
            self.clear_bound_receiver(&name);
            self.widened_vars.remove(&name);
            self.concatenated_vars.remove(&name);
            self.unbounded_string_vars.remove(&name);
            self.var_scope.insert(name.clone(), item.resource);
            if item.is_path {
                self.path_vars.insert(name.clone());
            } else {
                self.path_vars.remove(&name);
            }
            self.branch_mixed_path_vars.remove(&name);
            for condition in &generator.ifs {
                self.walk_expr(condition);
            }
            self.walk_expr(element);
            if let Some(value) = value {
                self.walk_expr(value);
            }
        }
        prior_imports.namespace_mutated |= self.imports.namespace_mutated;
        self.imports = prior_imports;
        self.modeled_values.remove(&name);
        if let Some(value) = prior_modeled {
            self.modeled_values.insert(name.clone(), value);
        }
        match prior {
            Some(value) => {
                self.var_scope.insert(name.clone(), value);
            }
            None => {
                self.var_scope.remove(&name);
            }
        }
        if prior_path {
            self.path_vars.insert(name.clone());
        } else {
            self.path_vars.remove(&name);
        }
        if prior_branch_mixed_path {
            self.branch_mixed_path_vars.insert(name.clone());
        } else {
            self.branch_mixed_path_vars.remove(&name);
        }
        if prior_widened {
            self.widened_vars.insert(name.clone());
        } else {
            self.widened_vars.remove(&name);
        }
        if prior_concatenated {
            self.concatenated_vars.insert(name.clone());
        } else {
            self.concatenated_vars.remove(&name);
        }
        if prior_unbounded_string {
            self.unbounded_string_vars.insert(name.clone());
        } else {
            self.unbounded_string_vars.remove(&name);
        }
        match prior_instance {
            Some(instance) => {
                self.instance_vars.insert(name.clone(), instance);
            }
            None => {
                self.instance_vars.remove(&name);
            }
        }
        if prior_bound {
            self.bound_vars.insert(name.clone());
        } else {
            self.bound_vars.remove(&name);
        }
        if prior_receiver_rebinding {
            self.receiver_rebindings.insert(name);
        } else {
            self.receiver_rebindings.remove(&name);
        }
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        true
    }

    fn walk_untracked_comprehension(
        &mut self,
        element: &Expr,
        value: Option<&Expr>,
        generators: &[ast::Comprehension],
    ) -> bool {
        let mut prior_imports = self.imports.clone();
        let names: BTreeSet<_> = generators
            .iter()
            .flat_map(|generator| rebound_target_names(&generator.target))
            .collect();
        let prior: Vec<_> = names
            .into_iter()
            .map(|name| {
                (
                    name.clone(),
                    self.var_scope.get(&name).cloned(),
                    self.modeled_values.get(&name).cloned(),
                    self.path_vars.contains(&name),
                    self.branch_mixed_path_vars.contains(&name),
                    self.widened_vars.contains(&name),
                    self.concatenated_vars.contains(&name),
                    self.unbounded_string_vars.contains(&name),
                    self.instance_vars.get(&name).cloned(),
                    self.bound_vars.contains(&name),
                    self.receiver_rebindings.contains(&name),
                )
            })
            .collect();
        for generator in generators {
            self.walk_expr(&generator.iter);
            self.walk_assignment_target(&generator.target);
            self.invalidate_rebound_target(&generator.target);
            for condition in &generator.ifs {
                self.walk_expr(condition);
            }
        }
        self.walk_expr(element);
        if let Some(value) = value {
            self.walk_expr(value);
        }
        prior_imports.namespace_mutated |= self.imports.namespace_mutated;
        self.imports = prior_imports;
        for (
            name,
            resource,
            modeled,
            path,
            branch_mixed_path,
            widened,
            concatenated,
            unbounded_string,
            instance,
            bound,
            receiver_rebinding,
        ) in prior
        {
            self.modeled_values.remove(&name);
            if let Some(value) = modeled {
                self.modeled_values.insert(name.clone(), value);
            }
            match resource {
                Some(resource) => {
                    self.var_scope.insert(name.clone(), resource);
                }
                None => {
                    self.var_scope.remove(&name);
                }
            }
            if path {
                self.path_vars.insert(name.clone());
            } else {
                self.path_vars.remove(&name);
            }
            if branch_mixed_path {
                self.branch_mixed_path_vars.insert(name.clone());
            } else {
                self.branch_mixed_path_vars.remove(&name);
            }
            if widened {
                self.widened_vars.insert(name.clone());
            } else {
                self.widened_vars.remove(&name);
            }
            if concatenated {
                self.concatenated_vars.insert(name.clone());
            } else {
                self.concatenated_vars.remove(&name);
            }
            if unbounded_string {
                self.unbounded_string_vars.insert(name.clone());
            } else {
                self.unbounded_string_vars.remove(&name);
            }
            match instance {
                Some(instance) => {
                    self.instance_vars.insert(name.clone(), instance);
                }
                None => {
                    self.instance_vars.remove(&name);
                }
            }
            if bound {
                self.bound_vars.insert(name.clone());
            } else {
                self.bound_vars.remove(&name);
            }
            if receiver_rebinding {
                self.receiver_rebindings.insert(name);
            } else {
                self.receiver_rebindings.remove(&name);
            }
        }
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        true
    }
}
