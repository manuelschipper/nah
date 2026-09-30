//! Source-string state snapshots: the persistent binding environments the
//! effect visitor saves around function bodies and branches, their retained
//! state bytes charged to the analysis budget, and the restoration of
//! captured bindings a call changed.

use std::collections::HashSet;

use effinterp_proto::ResourceExpr;
use im::HashMap as PersistentHashMap;

use super::aggregate_alias::restore_aggregate_aliases;
use super::model;
use super::resolve::ParamEnv;
use super::{
    AggregateAliases, CallableEnv, SourceStringNames, binding_is_within,
    binding_names_with_descendants,
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
