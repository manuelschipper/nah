//! Python branch joins.
//! Each arm starts from the same bindings, and their join retains only values supported by the alternatives.

use std::collections::{BTreeSet, HashSet};

use rustpython_parser::ast::{Expr, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;

use crate::value::unresolved_resource;

use super::PythonWalker;

/// The construct that selects which arm `walk_branches` executes.
#[derive(Clone, Copy)]
pub(super) struct BranchGuard {
    pub(super) range: TextRange,
    pub(super) kind: effinterp_proto::ConditionKind,
    pub(super) boolean: bool,
    /// How many leading arms run unconditionally, matching the other frontends:
    /// a `try` body always executes, and only its handlers are selected.
    pub(super) unguarded_arms: usize,
}

impl BranchGuard {
    /// One construct selects exactly one arm, so every arm is guarded.
    pub(super) fn selection(
        range: TextRange,
        kind: effinterp_proto::ConditionKind,
        boolean: bool,
    ) -> Self {
        Self {
            range,
            kind,
            boolean,
            unguarded_arms: 0,
        }
    }

    /// A `try` statement: arm 0 is its body and each later arm is one handler
    /// selected by an exception the analysis does not resolve.
    pub(super) fn exception_handlers(range: TextRange) -> Self {
        Self {
            range,
            kind: effinterp_proto::ConditionKind::UnresolvedExecution,
            boolean: false,
            unguarded_arms: 1,
        }
    }
}

impl PythonWalker<'_, '_> {
    /// Walk the alternative bodies of a conditionally-executed construct (an
    /// `if`'s arms, a loop body, the arms of a `try`) so a def-use binding
    /// created or killed inside does not leak past the join as the same
    /// value. A variable a branch assigns has no single producer at the join —
    /// the branch may not have run, or a sibling branch may assign it
    /// differently — so after it the variable holds a join of what every arm
    /// left in it. Each arm starts from the pre-construct binding
    /// state (arms are alternatives); within-arm producer→consumer edges still
    /// form during the walk. Resource and container bindings survive only when
    /// every arm produces the same exact value. A receiver or call-result
    /// binding introduced in one arm may survive untouched alternatives, but
    /// any explicit rebinding drops it.
    pub(super) fn walk_branches(
        &mut self,
        branches: &[(&[Stmt], Option<&str>, Option<&Expr>)],
        guard: Option<BranchGuard>,
    ) {
        let entry_flow = self.flow_vars.clone();
        let entry_vars = self.var_scope.clone();
        let entry_path_vars = self.path_vars.clone();
        let entry_branch_mixed_path_vars = self.branch_mixed_path_vars.clone();
        let entry_concatenated = self.concatenated_vars.clone();
        let entry_unbounded_strings = self.unbounded_string_vars.clone();
        let entry_widened = self.widened_vars.clone();
        let entry_collections = self.collections.clone();
        let entry_instance_sequences = self.instance_sequences.clone();
        let mut instance_sequence_states = Vec::new();
        let entry_sessions = self.sessions.clone();
        let entry_modeled = self.modeled_values.clone();
        let mut modeled_states = Vec::new();
        let entry_instances = self.instance_vars.clone();
        let entry_instance_attr_rebindings = self.instance_attr_rebindings.clone();
        let entry_bound = self.bound_vars.clone();
        let entry_receiver_rebindings = self.receiver_rebindings.clone();
        let entry_deferred_containers = self.deferred_containers.clone();
        let entry_deferred_vars = self.deferred_vars.clone();
        let entry_cwd = (self.cwd.clone(), self.chdir.clone());
        let mut cwd_states = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        let mut var_states = Vec::new();
        let mut path_var_states = Vec::new();
        let mut branch_mixed_path_var_states = Vec::new();
        let mut concatenated_states = Vec::new();
        let mut unbounded_string_states = Vec::new();
        let mut widened_states = Vec::new();
        let mut flow_states = Vec::new();
        let mut collection_states = Vec::new();
        let mut session_states = Vec::new();
        let mut instance_states = Vec::new();
        let mut instance_attr_rebinding_states = Vec::new();
        let mut bound_states = Vec::new();
        let mut receiver_rebinding_states = Vec::new();
        let mut deferred_container_states = Vec::new();
        let mut deferred_var_states = Vec::new();
        for (arm, (body, rebound_path, test)) in branches.iter().enumerate() {
            self.flow_vars = entry_flow.clone();
            self.var_scope = entry_vars.clone();
            self.path_vars = entry_path_vars.clone();
            self.branch_mixed_path_vars = entry_branch_mixed_path_vars.clone();
            self.concatenated_vars = entry_concatenated.clone();
            self.unbounded_string_vars = entry_unbounded_strings.clone();
            self.widened_vars = entry_widened.clone();
            self.collections = entry_collections.clone();
            self.instance_sequences = entry_instance_sequences.clone();
            self.sessions = entry_sessions.clone();
            self.modeled_values = entry_modeled.clone();
            self.instance_vars = entry_instances.clone();
            self.instance_attr_rebindings = entry_instance_attr_rebindings.clone();
            self.bound_vars = entry_bound.clone();
            self.receiver_rebindings.clear();
            self.deferred_containers = entry_deferred_containers.clone();
            self.deferred_vars = entry_deferred_vars.clone();
            (self.cwd, self.chdir) = entry_cwd.clone();
            if let Some(name) = rebound_path {
                self.invalidate_rebound_name(name);
            }
            if let Some(test) = test {
                self.walk_expr(test);
            }
            let condition = guard
                .filter(|guard| arm >= guard.unguarded_arms)
                .map(|guard| {
                    self.builder.source_condition_path(
                        effinterp_proto::Condition::from_source_with_digest(
                            self.source,
                            self.condition_source.digest().to_string(),
                            effinterp_proto::ByteSpan {
                                start: guard.range.start().into(),
                                end: guard.range.end().into(),
                            },
                            guard.kind,
                            arm as u32,
                            branches.len().max(2) as u32,
                            true,
                            guard.boolean,
                        ),
                    )
                });
            let guarded = condition.is_some();
            if let Some(condition) = condition {
                self.builder.push_condition(condition);
            }
            self.walk_body(body);
            if guarded {
                self.builder.pop_condition();
            }
            if self.capture.is_none() {
                for name in self.flow_vars.keys().chain(entry_flow.keys()) {
                    if self.flow_vars.get(name) != entry_flow.get(name) && !touched.contains(name) {
                        touched.push(name.clone());
                    }
                }
                flow_states.push(self.flow_vars.clone());
            }
            var_states.push(self.var_scope.clone());
            path_var_states.push(self.path_vars.clone());
            branch_mixed_path_var_states.push(self.branch_mixed_path_vars.clone());
            concatenated_states.push(self.concatenated_vars.clone());
            unbounded_string_states.push(self.unbounded_string_vars.clone());
            widened_states.push(self.widened_vars.clone());
            collection_states.push(self.collections.clone());
            instance_sequence_states.push(self.instance_sequences.clone());
            session_states.push(self.sessions.clone());
            modeled_states.push(self.modeled_values.clone());
            instance_states.push(self.instance_vars.clone());
            instance_attr_rebinding_states.push(self.instance_attr_rebindings.clone());
            bound_states.push(self.bound_vars.clone());
            receiver_rebinding_states.push(self.receiver_rebindings.clone());
            deferred_container_states.push(self.deferred_containers.clone());
            deferred_var_states.push(self.deferred_vars.clone());
            cwd_states.push((self.cwd.clone(), self.chdir.clone()));
        }
        // Arms that leave the program in different directories leave it in an
        // unknown one.
        if cwd_states.iter().any(|state| *state != cwd_states[0]) {
            self.cwd = None;
            self.chdir = Some(unresolved_resource("filesystem"));
        }
        self.flow_vars = entry_flow;
        // A name an arm rebinds may hold what any arm left in it.
        let merged = branches
            .iter()
            .find_map(|(body, ..)| body.first())
            .map(|statement| statement.range());
        for name in touched {
            let mut stages = Vec::new();
            for stage in flow_states.iter().filter_map(|state| state.get(&name)) {
                if !stages.contains(stage) {
                    stages.push(*stage);
                }
            }
            match merged.and_then(|range| self.joined_value(range, &stages)) {
                Some(joined) => self.flow_vars.insert(name, joined),
                None => self.flow_vars.remove(&name),
            };
        }
        let mut all_var_names = BTreeSet::new();
        for state in &var_states {
            all_var_names.extend(state.keys().cloned());
        }
        self.var_scope = var_states
            .last()
            .cloned()
            .unwrap_or_else(|| entry_vars.clone());
        self.var_scope.retain(|name, value| {
            var_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.path_vars.clear();
        for state in &path_var_states {
            self.path_vars.extend(state.iter().cloned());
        }
        self.branch_mixed_path_vars.clear();
        for state in branch_mixed_path_var_states {
            self.branch_mixed_path_vars.extend(state);
        }
        for name in &self.path_vars {
            let entry_holds_non_path = !entry_path_vars.contains(name)
                && (entry_vars.contains_key(name)
                    || entry_receiver_rebindings.contains(name)
                    || self.current_function.as_ref().is_some_and(|function| {
                        self.defs
                            .iter()
                            .find(|def| def.name == function.as_str())
                            .is_some_and(|def| def.params.contains(name))
                    }));
            if path_var_states
                .iter()
                .zip(&receiver_rebinding_states)
                .any(|(paths, rebound)| {
                    !paths.contains(name) && (entry_holds_non_path || rebound.contains(name))
                })
            {
                self.branch_mixed_path_vars.insert(name.clone());
            }
        }
        self.concatenated_vars = concatenated_states
            .last()
            .cloned()
            .unwrap_or(entry_concatenated);
        self.concatenated_vars
            .retain(|name| concatenated_states.iter().all(|state| state.contains(name)));
        self.unbounded_string_vars.clear();
        for state in unbounded_string_states {
            self.unbounded_string_vars.extend(state);
        }
        self.widened_vars = entry_widened;
        for state in widened_states {
            self.widened_vars.extend(state);
        }
        for name in all_var_names {
            let mut values = var_states.iter().map(|state| state.get(&name));
            let first = values.next().flatten();
            if first.is_none() || values.any(|value| value != first) {
                self.widened_vars.insert(name);
            }
        }
        self.collections = collection_states.pop().unwrap_or(entry_collections);
        self.collections.retain(|name, value| {
            collection_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.instance_sequences = instance_sequence_states
            .pop()
            .unwrap_or(entry_instance_sequences);
        self.instance_sequences.retain(|name, value| {
            instance_sequence_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.modeled_values = modeled_states.pop().unwrap_or(entry_modeled);
        self.modeled_values.retain(|name, value| {
            modeled_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.sessions = session_states.pop().unwrap_or(entry_sessions);
        self.sessions.retain(|name, value| {
            session_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        let mut joined_instances = std::collections::HashMap::new();
        let mut ambiguous_instances = HashSet::new();
        for state in &instance_states {
            for (name, value) in state {
                match joined_instances.get(name) {
                    None => {
                        joined_instances.insert(name.clone(), value.clone());
                    }
                    Some(previous) if previous == value => {}
                    Some(_) => {
                        ambiguous_instances.insert(name.clone());
                    }
                }
            }
        }
        joined_instances.retain(|name, _| {
            !ambiguous_instances.contains(name)
                && instance_states
                    .iter()
                    .zip(&receiver_rebinding_states)
                    .all(|(state, rebound)| state.contains_key(name) || !rebound.contains(name))
        });
        self.instance_vars = joined_instances;
        self.instance_attr_rebindings.clear();
        for state in instance_attr_rebinding_states {
            for (name, attrs) in state {
                self.instance_attr_rebindings
                    .entry(name)
                    .or_default()
                    .extend(attrs);
            }
        }
        let mut joined_bound = entry_bound;
        for state in &bound_states {
            joined_bound.extend(state.iter().cloned());
        }
        joined_bound.retain(|name| {
            bound_states
                .iter()
                .zip(&receiver_rebinding_states)
                .all(|(state, rebound)| state.contains(name) || !rebound.contains(name))
        });
        self.bound_vars = joined_bound;
        self.receiver_rebindings = entry_receiver_rebindings;
        for state in receiver_rebinding_states {
            self.receiver_rebindings.extend(state);
        }
        self.deferred_containers = deferred_container_states
            .pop()
            .unwrap_or(entry_deferred_containers);
        self.deferred_containers.retain(|name, value| {
            deferred_container_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.deferred_vars = deferred_var_states.pop().unwrap_or(entry_deferred_vars);
        self.deferred_vars.retain(|name, value| {
            deferred_var_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
    }
}
