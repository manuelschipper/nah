//! Inherited options for each selectable command path.

use std::collections::{BTreeMap, BTreeSet};

use crate::{CommandDeclaration, FlagDeclaration, SubcommandDeclaration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOptionScope {
    /// Indices into successive subcommand declaration arrays; empty at the root.
    pub path: Vec<usize>,
    pub flags: Vec<FlagDeclaration>,
    /// Raw refusal checks can name sibling options. Only spellings with one
    /// declared arity can be scanned outside their selected path.
    pub scan_flags: Vec<FlagDeclaration>,
}

fn inherit(
    parent: &[FlagDeclaration],
    own: &[FlagDeclaration],
) -> Result<Vec<FlagDeclaration>, String> {
    let mut arities = BTreeMap::new();
    for flag in parent.iter().chain(own) {
        for name in &flag.names {
            if arities
                .insert(name, flag.takes_value)
                .is_some_and(|previous| previous != flag.takes_value)
            {
                return Err(format!("conflicting flag {name:?}"));
            }
        }
    }
    let mut flags = parent.to_vec();
    // A leaf owns aliases it redeclares, including their Boolean last-wins group.
    for flag in &mut flags {
        flag.names
            .retain(|name| !own.iter().any(|flag| flag.names.contains(name)));
    }
    flags.retain(|flag| !flag.names.is_empty());
    flags.extend_from_slice(own);
    Ok(flags)
}

pub fn command_option_scopes(
    command: &CommandDeclaration,
) -> Result<Vec<CommandOptionScope>, String> {
    fn visit(
        subcommands: &[SubcommandDeclaration],
        parent: &CommandOptionScope,
        scopes: &mut Vec<CommandOptionScope>,
    ) -> Result<(), String> {
        for (index, subcommand) in subcommands.iter().enumerate() {
            let mut path = parent.path.clone();
            path.push(index);
            let scope = CommandOptionScope {
                path,
                flags: inherit(&parent.flags, &subcommand.behavior.flags)?,
                scan_flags: Vec::new(),
            };
            visit(&subcommand.subcommands, &scope, scopes)?;
            scopes.push(scope);
        }
        Ok(())
    }
    let mut flags = inherit(&[], &command.behavior.flags)?;
    let mut inherited = flags.clone();
    for mode in &command.modes {
        flags = inherit(&flags, &mode.behavior.flags)?;
        if !mode.without_subcommand {
            inherited = inherit(&inherited, &mode.behavior.flags)?;
        }
    }
    let root = CommandOptionScope {
        path: Vec::new(),
        flags,
        scan_flags: Vec::new(),
    };
    let mut scopes = vec![root.clone()];
    let parent = CommandOptionScope {
        flags: inherited,
        ..root
    };
    visit(&command.subcommands, &parent, &mut scopes)?;
    fn declarations(command: &CommandDeclaration) -> Vec<&FlagDeclaration> {
        fn children(subcommands: &[SubcommandDeclaration]) -> Vec<&FlagDeclaration> {
            subcommands
                .iter()
                .flat_map(|subcommand| {
                    subcommand
                        .behavior
                        .flags
                        .iter()
                        .chain(children(&subcommand.subcommands))
                })
                .collect()
        }
        command
            .behavior
            .flags
            .iter()
            .chain(command.modes.iter().flat_map(|mode| &mode.behavior.flags))
            .chain(children(&command.subcommands))
            .collect()
    }
    let declared = declarations(command);
    let mut arities = BTreeMap::new();
    for flag in &declared {
        for name in &flag.names {
            arities
                .entry(name)
                .and_modify(|arity| {
                    if *arity != Some(flag.takes_value) {
                        *arity = None;
                    }
                })
                .or_insert(Some(flag.takes_value));
        }
    }
    for scope in &mut scopes {
        let active = scope
            .flags
            .iter()
            .flat_map(|flag| &flag.names)
            .collect::<BTreeSet<_>>();
        let retained = |name: &String| arities[name].is_some() && !active.contains(name);
        scope.scan_flags = declared
            .iter()
            .filter(|flag| flag.names.iter().any(retained))
            .map(|flag| {
                let mut flag = (*flag).clone();
                flag.names.retain(retained);
                flag
            })
            .chain(scope.flags.clone())
            .collect();
    }
    Ok(scopes)
}
