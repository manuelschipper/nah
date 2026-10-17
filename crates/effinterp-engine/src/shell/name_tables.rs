//! Name tables: the aliases, hashed paths and functions that decide what a
//! command name runs, and how they join after `if`/`case` arms or an
//! `&&`/`||` operand left a name bound differently on different paths.

use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use super::function_definition::FnEntry;
use super::shell_env::ShellEnv;

/// Paths kept for one command name that branches bind differently; past this
/// the name keeps the last path's binding.
const MAX_PATH_BINDINGS: usize = 16;

/// Each path's binding for a command name that `if`/`case` arms or a
/// `&&`/`||` operand left different, with the condition selecting the path.
/// `None` is a path that left the name unbound.
pub(super) type PathBindings<T> = Vec<(T, Option<effinterp_proto::Condition>)>;

/// A function binding on one path, and whether `readonly -f` fixed it there.
pub(super) type FunctionBinding = (Option<Rc<FnEntry>>, bool);

/// The tables that decide what a command name runs, saved before a branch.
#[derive(Clone)]
pub(super) struct NameTables {
    aliases: HashMap<String, (String, u32)>,
    hashed: HashMap<String, String>,
    functions: HashMap<String, Rc<FnEntry>>,
    readonly_functions: BTreeSet<String>,
    alias_alternatives: HashMap<String, PathBindings<Option<(String, u32)>>>,
    hash_alternatives: HashMap<String, PathBindings<Option<String>>>,
    function_alternatives: HashMap<String, PathBindings<FunctionBinding>>,
}

impl ShellEnv {
    pub(super) fn name_tables(&self) -> NameTables {
        NameTables {
            aliases: self.aliases.clone(),
            hashed: self.hashed.clone(),
            functions: self.functions.clone(),
            readonly_functions: self.readonly_functions.clone(),
            alias_alternatives: self.alias_alternatives.clone(),
            hash_alternatives: self.hash_alternatives.clone(),
            function_alternatives: self.function_alternatives.clone(),
        }
    }

    pub(super) fn restore_name_tables(&mut self, tables: NameTables) {
        self.aliases = tables.aliases;
        self.hashed = tables.hashed;
        self.functions = tables.functions;
        self.readonly_functions = tables.readonly_functions;
        self.alias_alternatives = tables.alias_alternatives;
        self.hash_alternatives = tables.hash_alternatives;
        self.function_alternatives = tables.function_alternatives;
    }
}

/// Join the name tables the paths of a branch ended with. The environment
/// takes the last path's tables; a name the paths bind differently also
/// gets every path's binding under that path's condition.
pub(super) fn merge_name_tables(
    env: &mut ShellEnv,
    paths: Vec<(NameTables, Option<effinterp_proto::Condition>)>,
) {
    let Some((last, _)) = paths.last() else {
        return;
    };
    env.restore_name_tables(last.clone());
    merge_name_table(
        &paths,
        |tables| {
            tables
                .aliases
                .keys()
                .chain(tables.alias_alternatives.keys())
                .cloned()
                .collect()
        },
        |tables, name| tables.aliases.get(name).cloned(),
        |tables| &tables.alias_alternatives,
        |left, right| left == right,
        &mut env.alias_alternatives,
    );
    merge_name_table(
        &paths,
        |tables| {
            tables
                .hashed
                .keys()
                .chain(tables.hash_alternatives.keys())
                .cloned()
                .collect()
        },
        |tables, name| tables.hashed.get(name).cloned(),
        |tables| &tables.hash_alternatives,
        |left, right| left == right,
        &mut env.hash_alternatives,
    );
    merge_name_table(
        &paths,
        |tables| {
            tables
                .functions
                .keys()
                .chain(&tables.readonly_functions)
                .chain(tables.function_alternatives.keys())
                .cloned()
                .collect()
        },
        |tables, name| {
            (
                tables.functions.get(name).cloned(),
                tables.readonly_functions.contains(name),
            )
        },
        |tables| &tables.function_alternatives,
        |left, right| {
            left.1 == right.1
                && match (&left.0, &right.0) {
                    (Some(left), Some(right)) => Rc::ptr_eq(left, right),
                    (None, None) => true,
                    _ => false,
                }
        },
        &mut env.function_alternatives,
    );
}

/// Join one name table across the paths of a branch. A name every path binds
/// alike gets no entry in `merged`; otherwise each path's binding is kept
/// under that path's condition, unless there are more than
/// `MAX_PATH_BINDINGS` of them.
fn merge_name_table<T: Clone>(
    paths: &[(NameTables, Option<effinterp_proto::Condition>)],
    names: impl Fn(&NameTables) -> BTreeSet<String>,
    plain: impl Fn(&NameTables, &str) -> T,
    alternatives: impl Fn(&NameTables) -> &HashMap<String, PathBindings<T>>,
    same: impl Fn(&T, &T) -> bool,
    merged: &mut HashMap<String, PathBindings<T>>,
) {
    let names = paths
        .iter()
        .flat_map(|(tables, _)| names(tables))
        .collect::<BTreeSet<_>>();
    for name in names {
        let per_path = paths
            .iter()
            .map(|(tables, _)| {
                alternatives(tables)
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| vec![(plain(tables, &name), None)])
            })
            .collect::<Vec<_>>();
        let agree = per_path.windows(2).all(|pair| {
            pair[0].len() == pair[1].len()
                && pair[0]
                    .iter()
                    .zip(&pair[1])
                    .all(|(left, right)| same(&left.0, &right.0) && left.1 == right.1)
        });
        if agree {
            continue;
        }
        let bindings = per_path
            .into_iter()
            .zip(paths)
            .flat_map(|(bindings, (_, path))| {
                bindings.into_iter().map(move |(value, inner)| {
                    (
                        value,
                        effinterp_proto::Condition::compose(inner.iter().chain(path.iter())),
                    )
                })
            })
            .collect::<Vec<_>>();
        if bindings.len() <= MAX_PATH_BINDINGS {
            merged.insert(name, bindings);
        }
    }
}
