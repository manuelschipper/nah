//! Source-string state snapshots: the persistent binding environments the
//! effect visitor saves around function bodies and branches, their retained
//! state bytes charged to the analysis budget, and the restoration of
//! captured bindings a call changed.

use std::collections::HashSet;

use effinterp_proto::ResourceExpr;
use im::HashMap as PersistentHashMap;
use oxc_span::Span;

use super::aggregate_alias::{add_aggregate_alias, restore_aggregate_aliases};
use super::model;
use super::resolve::ParamEnv;
use super::{
    AggregateAliases, CallableBinding, CallableEnv, EffectVisitor, SourceStringNames,
    binding_is_within, binding_names_with_descendants,
};

#[derive(Clone)]
pub(super) struct SourceStringState {
    pub(super) param_env: ParamEnv,
    pub(super) source_env: ParamEnv,
    pub(super) unbounded_source_env: SourceStringNames,
    pub(super) definitely_nullish_env: SourceStringNames,
    pub(super) callable_env: CallableEnv,
    pub(super) aggregate_aliases: AggregateAliases,
}

impl SourceStringState {
    /// Entries a whole-environment scan of this state walks.
    pub(super) fn binding_entries(&self) -> u64 {
        (self.param_env.len()
            + self.source_env.len()
            + self.unbounded_source_env.len()
            + self.definitely_nullish_env.len()
            + self.callable_env.len()
            + self.aggregate_aliases.len()) as u64
    }
}

pub(super) fn callable_env_bytes(env: &CallableEnv) -> u64 {
    env.keys()
        .map(|key| crate::limits::NODE_BYTES + key.len() as u64)
        .sum()
}

pub(super) fn object_literal_bytes(bindings: &model::ObjectLiteralBindings) -> u64 {
    use crate::limits::NODE_BYTES;
    bindings
        .iter()
        .map(|(key, object)| {
            NODE_BYTES
                + key.len() as u64
                + object
                    .values
                    .keys()
                    .map(|name| NODE_BYTES + name.len() as u64)
                    .sum::<u64>()
                + object
                    .env_keys
                    .iter()
                    .map(|name| NODE_BYTES + name.as_ref().map_or(0, |name| name.len() as u64))
                    .sum::<u64>()
        })
        .sum()
}

/// Retained state bytes: the accounted bytes a retained source-string snapshot
/// adds over `charged`, the last snapshot already charged in full or by
/// difference. Entries equal to `charged`'s are shared by the persistent maps
/// and were paid for then, so the total charge covers every unique entry any
/// retained snapshot holds, under the same fixed schedule as plan values.
pub(super) fn retained_state_bytes(
    state: &SourceStringState,
    charged: Option<&SourceStringState>,
) -> u64 {
    use crate::limits::{NODE_BYTES, resource_bytes};
    let resource_entry =
        |key: &String, value: &ResourceExpr| NODE_BYTES + key.len() as u64 + resource_bytes(value);
    let name_entry = |name: &String| NODE_BYTES + name.len() as u64;
    changed_entry_bytes(
        &state.param_env,
        charged.map(|charged| &charged.param_env),
        resource_entry,
    ) + changed_entry_bytes(
        &state.source_env,
        charged.map(|charged| &charged.source_env),
        resource_entry,
    ) + changed_name_bytes(
        &state.unbounded_source_env,
        charged.map(|charged| &charged.unbounded_source_env),
        name_entry,
    ) + changed_name_bytes(
        &state.definitely_nullish_env,
        charged.map(|charged| &charged.definitely_nullish_env),
        name_entry,
    ) + changed_entry_bytes(
        &state.callable_env,
        charged.map(|charged| &charged.callable_env),
        |key, _| NODE_BYTES + key.len() as u64,
    ) + changed_entry_bytes(
        &state.aggregate_aliases,
        charged.map(|charged| &charged.aggregate_aliases),
        |key, targets| {
            NODE_BYTES
                + key.len() as u64
                + targets
                    .iter()
                    .map(|target| NODE_BYTES + target.len() as u64)
                    .sum::<u64>()
        },
    )
}

/// Bytes of the entries in `map` that `charged` lacks or holds with another value.
fn changed_entry_bytes<V: Clone + PartialEq>(
    map: &PersistentHashMap<String, V>,
    charged: Option<&PersistentHashMap<String, V>>,
    entry_bytes: impl Fn(&String, &V) -> u64,
) -> u64 {
    if charged.is_some_and(|charged| charged.ptr_eq(map)) {
        return 0;
    }
    map.iter()
        .filter(|(key, value)| charged.and_then(|charged| charged.get(*key)) != Some(*value))
        .map(|(key, value)| entry_bytes(key, value))
        .sum()
}

/// Bytes of the names in `names` that `charged` lacks.
fn changed_name_bytes(
    names: &SourceStringNames,
    charged: Option<&SourceStringNames>,
    name_bytes: impl Fn(&String) -> u64,
) -> u64 {
    if charged.is_some_and(|charged| charged.ptr_eq(names)) {
        return 0;
    }
    names
        .iter()
        .filter(|name| !charged.is_some_and(|charged| charged.contains(*name)))
        .map(name_bytes)
        .sum()
}

pub(super) fn changed_captured_bindings(
    budget: &crate::nest::Budget,
    entry: &SourceStringState,
    exit: &SourceStringState,
    local_names: &HashSet<String>,
    candidates: &HashSet<String>,
) -> HashSet<String> {
    if candidates.is_empty() {
        return HashSet::new();
    }
    budget.note_state_scan(entry.binding_entries() + exit.binding_entries());
    binding_names_with_descendants(
        candidates,
        entry
            .param_env
            .keys()
            .chain(exit.param_env.keys())
            .chain(entry.source_env.keys())
            .chain(exit.source_env.keys())
            .chain(entry.unbounded_source_env.iter())
            .chain(exit.unbounded_source_env.iter())
            .chain(entry.definitely_nullish_env.iter())
            .chain(exit.definitely_nullish_env.iter())
            .chain(entry.callable_env.keys())
            .chain(exit.callable_env.keys())
            .chain(entry.aggregate_aliases.keys())
            .chain(exit.aggregate_aliases.keys()),
    )
    .into_iter()
    .filter(|name| {
        !local_names
            .iter()
            .any(|local| binding_is_within(name, local))
            && (entry.param_env.get(name) != exit.param_env.get(name)
                || entry.source_env.get(name) != exit.source_env.get(name)
                || entry.unbounded_source_env.contains(name)
                    != exit.unbounded_source_env.contains(name)
                || entry.definitely_nullish_env.contains(name)
                    != exit.definitely_nullish_env.contains(name)
                || entry.callable_env.get(name) != exit.callable_env.get(name)
                || entry.aggregate_aliases.get(name) != exit.aggregate_aliases.get(name))
    })
    .collect()
}

pub(super) fn restore_source_string_state_names(
    budget: &crate::nest::Budget,
    state: &mut SourceStringState,
    source: &SourceStringState,
    names: &HashSet<String>,
) {
    budget.note_state_scan(state.binding_entries() + source.binding_entries());
    let names = binding_names_with_descendants(
        names,
        state
            .param_env
            .keys()
            .chain(state.source_env.keys())
            .chain(state.unbounded_source_env.iter())
            .chain(state.definitely_nullish_env.iter())
            .chain(source.param_env.keys())
            .chain(source.source_env.keys())
            .chain(source.unbounded_source_env.iter())
            .chain(source.definitely_nullish_env.iter())
            .chain(state.callable_env.keys())
            .chain(source.callable_env.keys()),
    );
    for name in &names {
        match source.param_env.get(name) {
            Some(resource) => {
                state.param_env.insert(name.clone(), resource.clone());
            }
            None => {
                state.param_env.remove(name);
            }
        }
        match source.source_env.get(name) {
            Some(resource) => {
                state.source_env.insert(name.clone(), resource.clone());
            }
            None => {
                state.source_env.remove(name);
            }
        }
        if source.unbounded_source_env.contains(name) {
            state.unbounded_source_env.insert(name.clone());
        } else {
            state.unbounded_source_env.remove(name);
        }
        if source.definitely_nullish_env.contains(name) {
            state.definitely_nullish_env.insert(name.clone());
        } else {
            state.definitely_nullish_env.remove(name);
        }
        match source.callable_env.get(name) {
            Some(binding) => {
                state.callable_env.insert(name.clone(), *binding);
            }
            None => {
                state.callable_env.remove(name);
            }
        }
    }
    restore_aggregate_aliases(
        &mut state.aggregate_aliases,
        &source.aggregate_aliases,
        &names,
    );
}

/// The effect visitor's snapshot, restore and join of its source-string state,
/// and the analysis budget charge for each snapshot it retains.
impl<'a> EffectVisitor<'_, 'a> {
    pub(super) fn restore_source_string_names(
        &mut self,
        state: &SourceStringState,
        names: &HashSet<String>,
    ) {
        if names.is_empty() {
            return;
        }
        self.nest.budget.note_state_scan(
            self.source_string_state().binding_entries() + state.binding_entries(),
        );
        let names = binding_names_with_descendants(
            names,
            self.param_env
                .keys()
                .chain(self.source_env.keys())
                .chain(self.unbounded_source_env.iter())
                .chain(self.definitely_nullish_env.iter())
                .chain(state.param_env.keys())
                .chain(state.source_env.keys())
                .chain(state.unbounded_source_env.iter())
                .chain(state.definitely_nullish_env.iter())
                .chain(self.callable_env.keys())
                .chain(state.callable_env.keys()),
        );
        for name in &names {
            match state.param_env.get(name) {
                Some(resource) => {
                    self.param_env.insert(name.clone(), resource.clone());
                }
                None => {
                    self.param_env.remove(name);
                }
            }
            match state.source_env.get(name) {
                Some(resource) => {
                    self.source_env.insert(name.clone(), resource.clone());
                }
                None => {
                    self.source_env.remove(name);
                }
            }
            if state.unbounded_source_env.contains(name) {
                self.unbounded_source_env.insert(name.clone());
            } else {
                self.unbounded_source_env.remove(name);
            }
            if state.definitely_nullish_env.contains(name) {
                self.definitely_nullish_env.insert(name.clone());
            } else {
                self.definitely_nullish_env.remove(name);
            }
            match state.callable_env.get(name) {
                Some(binding) => {
                    self.callable_env.insert(name.clone(), *binding);
                }
                None => {
                    self.callable_env.remove(name);
                }
            }
        }
        restore_aggregate_aliases(
            &mut self.aggregate_aliases,
            &state.aggregate_aliases,
            &names,
        );
        self.sync_module_source_strings();
    }

    pub(super) fn observe_state_budget(&mut self, span: Span) {
        if self.nest.budget.bytes_saturated() {
            self.builder
                .note_saturated_at("max_analysis_bytes", Some((span.start, span.end)));
            self.saturated = true;
        } else if self.nest.budget.cancelled() {
            self.saturated = true;
        }
    }

    pub(super) fn charge_state_bytes(&mut self, bytes: u64, span: Span) -> bool {
        self.observe_state_budget(span);
        if self.saturated {
            return false;
        }
        if !crate::nest::charge_analysis_bytes(
            self.builder,
            self.nest.budget,
            bytes,
            Some((span.start, span.end)),
        ) {
            self.saturated = true;
            return false;
        }
        true
    }

    /// Charge retained state bytes for `state` plus `extra_bytes`, and make
    /// `state` the snapshot later retained snapshots are charged against.
    pub(super) fn charge_retained_state(
        &mut self,
        state: &SourceStringState,
        extra_bytes: u64,
        span: Span,
    ) -> bool {
        let bytes = retained_state_bytes(state, self.charged_source_state.as_ref()) + extra_bytes;
        if !self.charge_state_bytes(bytes, span) {
            return false;
        }
        self.charged_source_state = Some(state.clone());
        true
    }

    pub(super) fn retain_exception_source_state(&mut self, span: Span) {
        if self.exception_source_states.is_empty() || self.saturated {
            return;
        }
        let state = self.source_string_state();
        if self.charge_retained_state(&state, 0, span) {
            self.exception_source_states.last_mut().unwrap().push(state);
        }
    }

    pub(super) fn retain_return_source_state(&mut self, span: Span) {
        if self.return_source_states.is_empty() || self.saturated {
            return;
        }
        let state = self.source_string_state();
        if self.charge_retained_state(&state, 0, span) {
            self.return_source_states.last_mut().unwrap().push(state);
        }
    }

    pub(super) fn source_string_state(&self) -> SourceStringState {
        SourceStringState {
            param_env: self.param_env.clone(),
            source_env: self.source_env.clone(),
            unbounded_source_env: self.unbounded_source_env.clone(),
            definitely_nullish_env: self.definitely_nullish_env.clone(),
            callable_env: self.callable_env.clone(),
            aggregate_aliases: self.aggregate_aliases.clone(),
        }
    }

    pub(super) fn restore_source_string_state(&mut self, state: SourceStringState) {
        self.param_env = state.param_env;
        self.source_env = state.source_env;
        self.unbounded_source_env = state.unbounded_source_env;
        self.definitely_nullish_env = state.definitely_nullish_env;
        self.callable_env = state.callable_env;
        self.aggregate_aliases = state.aggregate_aliases;
        self.sync_module_source_strings();
    }

    /// Join two possible source-string states. Divergent concatenations keep
    /// enough shape to reach sink lowering, but are marked unbounded so the
    /// sink emits a boundary instead of choosing one branch at full coverage.
    pub(super) fn join_source_string_states(
        &mut self,
        left: SourceStringState,
        right: SourceStringState,
        span: Span,
    ) {
        if self.saturated {
            return;
        }
        self.nest
            .budget
            .note_state_scan(left.binding_entries() + right.binding_entries());
        let names: HashSet<String> = left
            .param_env
            .keys()
            .chain(right.param_env.keys())
            .chain(left.source_env.keys())
            .chain(right.source_env.keys())
            .chain(left.unbounded_source_env.iter())
            .chain(right.unbounded_source_env.iter())
            .chain(left.definitely_nullish_env.iter())
            .chain(right.definitely_nullish_env.iter())
            .chain(left.callable_env.keys())
            .chain(right.callable_env.keys())
            .cloned()
            .collect();
        self.param_env = right.param_env;
        self.source_env = right.source_env;
        self.unbounded_source_env = right.unbounded_source_env;
        self.definitely_nullish_env = right.definitely_nullish_env;
        self.definitely_nullish_env
            .retain(|name| left.definitely_nullish_env.contains(name));
        self.callable_env = right.callable_env;
        self.aggregate_aliases = right.aggregate_aliases;
        for (name, targets) in left.aggregate_aliases {
            for target in targets {
                add_aggregate_alias(&mut self.aggregate_aliases, name.clone(), target);
            }
        }
        for name in names {
            let same_source = left.source_env.get(&name) == self.source_env.get(&name)
                && left.unbounded_source_env.contains(&name)
                    == self.unbounded_source_env.contains(&name);
            if !same_source {
                let concatenation = left
                    .source_env
                    .get(&name)
                    .or_else(|| self.source_env.get(&name))
                    .filter(|resource| matches!(resource, ResourceExpr::Join { .. }));
                let bytes = concatenation.map(crate::limits::resource_bytes);
                if let Some(bytes) = bytes
                    && !self.charge_state_bytes(bytes, span)
                {
                    return;
                }
                let concatenation = left
                    .source_env
                    .get(&name)
                    .or_else(|| self.source_env.get(&name))
                    .filter(|resource| matches!(resource, ResourceExpr::Join { .. }))
                    .cloned();
                self.source_env.remove(&name);
                if let Some(concatenation) = concatenation {
                    self.source_env.insert(name.clone(), concatenation);
                }
                self.unbounded_source_env.insert(name.clone());
                self.param_env.remove(&name);
            } else if left.param_env.get(&name) != self.param_env.get(&name) {
                self.param_env.remove(&name);
            }
            if left.callable_env.get(&name) != self.callable_env.get(&name) {
                self.callable_env.insert(name, CallableBinding::Unbounded);
            }
        }
        self.sync_module_source_strings();
    }

    pub(super) fn sync_module_source_strings(&mut self) {
        if self.function_depth == 0 {
            self.module_env.clone_from(&self.param_env);
            self.source_strings.clone_from(&self.source_env);
            self.unbounded_source_strings
                .clone_from(&self.unbounded_source_env);
            self.module_definitely_nullish_env
                .clone_from(&self.definitely_nullish_env);
            self.module_callable_env.clone_from(&self.callable_env);
            self.module_aggregate_aliases
                .clone_from(&self.aggregate_aliases);
        }
    }
}
