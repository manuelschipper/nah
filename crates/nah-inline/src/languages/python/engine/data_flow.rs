//! Python value provenance, argument binding, and abstract-state joins.

use super::*;

pub(super) fn argument_origins(arguments: &Arguments, state: &State) -> BTreeSet<usize> {
    let mut origins = BTreeSet::new();
    for value in arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
    {
        value_origins(value, state, &mut BTreeSet::new(), &mut origins);
    }
    origins
}

pub(super) fn value_origins(
    value: &Value,
    state: &State,
    visiting: &mut BTreeSet<usize>,
    origins: &mut BTreeSet<usize>,
) {
    match value {
        Value::Produced(values) => origins.extend(values),
        Value::Decoded(value) => value_origins(value, state, visiting, origins),
        Value::Cell(cell) if visiting.insert(*cell) => {
            if let Some(Cell::Sequence { values, .. }) = state.cells.get(*cell) {
                for value in values {
                    value_origins(value, state, visiting, origins);
                }
            }
            visiting.remove(cell);
        }
        _ => {}
    }
}

pub(super) fn sequence_values<'a>(value: &'a Value, state: &'a State) -> Option<&'a [Value]> {
    let Value::Cell(cell) = value else {
        return None;
    };
    match state.cells.get(*cell) {
        Some(Cell::Sequence { values, .. }) => Some(values),
        Some(Cell::Unknown) | None => None,
    }
}

pub(super) fn value_bytes(value: &Value) -> Option<usize> {
    match value {
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => {
            Some(value.len())
        }
        Value::Compiled { source, .. } => Some(source.len()),
        Value::Bytes(value) => Some(value.len()),
        Value::PathMethod { path, method } => path.len().checked_add(method.len()),
        Value::CellMethod { method, .. } => Some(method.len()),
        Value::StringMethod { value, method } => value.len().checked_add(method.len()),
        Value::BytesMethod { value, method } => value.len().checked_add(method.len()),
        Value::Decoded(value) => value_bytes(value),
        Value::DecodedMethod { value, method } => {
            value_bytes(value).and_then(|bytes| bytes.checked_add(method.len()))
        }
        Value::Unknown
        | Value::None
        | Value::Bool(_)
        | Value::Int(_)
        | Value::EmptyDictionary
        | Value::ImportRegistry
        | Value::ImportRegistryMutator(_)
        | Value::ImportRegistryRead(_)
        | Value::Cell(_)
        | Value::Module(_)
        | Value::ModuleMethod(_)
        | Value::Known(_)
        | Value::LocalFunction(_)
        | Value::Produced(_) => Some(0),
    }
}

pub(super) fn values_bytes(values: &[Value]) -> Option<usize> {
    values.iter().try_fold(0usize, |bytes, value| {
        value_bytes(value).and_then(|value| bytes.checked_add(value))
    })
}

pub(super) fn bind_arguments(parameters: &[Parameter], arguments: &Arguments) -> ArgumentBindings {
    if arguments.positional.len() > parameters.len() {
        return ArgumentBindings::Invalid;
    }
    let mut values = vec![None; parameters.len()];
    for (index, value) in arguments.positional.iter().enumerate() {
        values[index] = Some(value.clone());
    }
    let positions = parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| (parameter.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut keywords = BTreeSet::new();
    for (name, value) in &arguments.keywords {
        if !keywords.insert(name.as_str()) {
            return ArgumentBindings::Invalid;
        }
        let Some(index) = positions.get(name.as_str()).copied() else {
            return ArgumentBindings::Invalid;
        };
        if values[index].is_some() {
            return ArgumentBindings::Invalid;
        }
        values[index] = Some(value.clone());
    }
    if !arguments.complete {
        return ArgumentBindings::Incomplete;
    }
    let bindings = parameters
        .iter()
        .zip(values)
        .map(|(parameter, value)| {
            value
                .or_else(|| parameter.default.clone())
                .map(|value| (parameter.name.clone(), value))
        })
        .collect::<Option<Vec<_>>>();
    bindings.map_or(ArgumentBindings::Invalid, ArgumentBindings::Bound)
}

pub(super) fn invalidate_argument_cells(arguments: &Arguments, state: &mut State) -> bool {
    let contains_registry = arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
        .any(|value| contains_import_registry(value, state, &mut BTreeSet::new()));
    if contains_registry {
        invalidate_import_ownership(state);
    }
    for cell in arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
        .filter_map(|value| match value {
            Value::Cell(cell) => Some(*cell),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
    {
        if let Some(value) = state.cells.get_mut(cell) {
            *value = Cell::Unknown;
        }
    }
    let modules = arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
        .filter_map(|value| match value {
            Value::Module(module) => Some(*module),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for module in modules {
        invalidate_module(module, state);
    }
    contains_registry
}

pub(super) fn join_states(mut left: State, right: State) -> State {
    left.invalid_modules.extend(&right.invalid_modules);
    if left.cwd != right.cwd {
        left.cwd = NestedExecutionCwd::Unknown;
    }
    if left.ipython_shell != right.ipython_shell {
        left.ipython_shell = IpythonShell::Unknown;
    }
    let names = left
        .bindings
        .keys()
        .chain(right.bindings.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for name in names {
        let value = match (left.bindings.get(&name), right.bindings.get(&name)) {
            (Some(left_value), Some(right_value))
                if values_match(left_value, right_value, &left.functions, &right.functions) =>
            {
                left_value.clone()
            }
            (Some(left_value), Some(right_value)) => {
                join_distinct_values(left_value.clone(), right_value.clone())
            }
            _ => Value::Unknown,
        };
        left.bindings.insert(name, value);
    }
    let cells = left.cells.len().max(right.cells.len());
    left.cells.resize(cells, Cell::Unknown);
    for (index, cell) in left.cells.iter_mut().enumerate() {
        if !right.cells.get(index).is_some_and(|right_cell| {
            cells_match(cell, right_cell, &left.functions, &right.functions)
        }) {
            *cell = Cell::Unknown;
        }
    }
    left
}

pub(super) fn merge_branch_states(
    yes: State,
    yes_control: Control,
    no: State,
    no_control: Control,
) -> (State, Control) {
    if yes_control == Control::Next {
        return if no_control == Control::Next {
            (join_states(yes, no), Control::Next)
        } else {
            (yes, Control::Next)
        };
    }
    if no_control == Control::Next {
        return (no, Control::Next);
    }
    if yes_control == no_control {
        return (join_states(yes, no), yes_control);
    }
    match (yes_control, no_control) {
        (Control::Return(yes_value), Control::Return(no_value)) => (
            join_states(yes, no),
            Control::Return(join_values(yes_value, no_value)),
        ),
        (Control::Return(value), _) => (yes, Control::Return(value)),
        (_, Control::Return(value)) => (no, Control::Return(value)),
        (Control::Raise, _) => (yes, Control::Raise),
        (_, Control::Raise) => (no, Control::Raise),
        (Control::Break, _) => (join_states(yes, no), Control::Break),
        (_, Control::Break) => (join_states(yes, no), Control::Break),
        (Control::Continue, _) => (join_states(yes, no), Control::Continue),
        (_, Control::Continue) => (join_states(yes, no), Control::Continue),
        (Control::Diverge, Control::Diverge) => (join_states(yes, no), Control::Diverge),
        (Control::Next, _) | (_, Control::Next) => unreachable!(),
    }
}

pub(super) fn values_match(
    left: &Value,
    right: &Value,
    left_functions: &[LocalFunction],
    right_functions: &[LocalFunction],
) -> bool {
    match (left, right) {
        (Value::LocalFunction(left_index), Value::LocalFunction(right_index)) => {
            left_index == right_index
                && left_functions
                    .get(*left_index)
                    .is_some_and(|function| right_functions.get(*right_index) == Some(function))
        }
        _ => left == right,
    }
}

pub(super) fn cells_match(
    left: &Cell,
    right: &Cell,
    left_functions: &[LocalFunction],
    right_functions: &[LocalFunction],
) -> bool {
    match (left, right) {
        (Cell::Unknown, Cell::Unknown) => true,
        (
            Cell::Sequence {
                values: left,
                indexable: left_indexable,
            },
            Cell::Sequence {
                values: right,
                indexable: right_indexable,
            },
        ) if left_indexable == right_indexable => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| values_match(left, right, left_functions, right_functions))
        }
        _ => false,
    }
}
