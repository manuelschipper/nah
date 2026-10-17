//! Launching shell options: what the shell that reads a script was started
//! with, read from the bash process that launched it or the script's `#!`
//! line. They decide whether aliases expand and whether `nocaseglob` is on
//! before the script's first `shopt`.

use std::collections::{BTreeSet, HashMap};

use effinterp_proto::{ResourceExpr, ResourceIdentity};

use crate::builder::{PlanBuilder, ScriptInterpreter};

use super::shell_env::VarEntry;

/// The program that launched this script and its arguments, or None when
/// there is none (the agent's own shell).
fn launching_program(builder: &PlanBuilder) -> Option<(&str, &[ResourceExpr])> {
    (0..builder.effects_len()).rev().find_map(|index| {
        let execution = builder.effect_execution(index)?;
        if builder.effect_operation(index) != Some("process.exec")
            || !builder.execution_is_within(execution, builder.current_execution())
        {
            return None;
        }
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable, argv, ..
            },
        } = builder.effect_resource(index)?
        else {
            return None;
        };
        Some((executable.as_str(), argv.as_slice()))
    })
}

/// The options of the bash process that launched this script, or None when
/// the nearest launch is another program or there is none (the agent's own
/// shell).
fn launching_bash_options(builder: &PlanBuilder) -> Option<&[ResourceExpr]> {
    launching_program(builder)
        .filter(|(executable, _)| *executable == "bash")
        .map(|(_, argv)| argv)
}

/// Whether the shell reading this script may start with the `set` option
/// `letter` (`name` after `-o`) on: the program that launched it names the
/// option before its script or `-c` string (`bash -x script`, `sh -ac '…'`,
/// `bash -o allexport`), or the inherited `SHELLOPTS` lists it. An option
/// word Nah cannot read may select it.
pub(super) fn inherited_set_option(
    builder: &PlanBuilder,
    vars: &HashMap<String, VarEntry>,
    letter: char,
    name: &str,
) -> bool {
    let listed = vars.get("SHELLOPTS").is_some_and(|entry| {
        entry
            .value
            .as_deref()
            .is_none_or(|value| value.split(':').any(|listed| listed == name))
    });
    let launched = || {
        let (_, argv) = launching_program(builder)?;
        let mut enabled = false;
        let mut words = argv.iter();
        while let Some(word) = words.next() {
            let ResourceExpr::Literal { value: option } = word else {
                return Some(true);
            };
            match option.as_str() {
                "--" | "-" => break,
                "--rcfile" | "--init-file" => {
                    words.next();
                }
                long if long.starts_with("--") => {}
                cluster if cluster.starts_with(['-', '+']) => {
                    let on = cluster.starts_with('-');
                    for flag in cluster[1..].chars() {
                        match flag {
                            flag if flag == letter => enabled = on,
                            'o' | 'O' => match words.next() {
                                Some(ResourceExpr::Literal { value }) => {
                                    if flag == 'o' && value == name {
                                        enabled = on;
                                    }
                                }
                                _ => return Some(true),
                            },
                            _ => {}
                        }
                    }
                    // The command string follows; later words are its
                    // arguments.
                    if cluster[1..].contains('c') {
                        break;
                    }
                }
                _ => break,
            }
        }
        Some(enabled)
    };
    listed || launched().unwrap_or(false)
}

/// Whether the shell reading this script expands aliases before any `shopt`,
/// and whether it is established to be bash, whose `shopt` can turn that
/// off. Bash expands none in a script unless it starts interactive, in POSIX
/// mode, with `-O expand_aliases`, or with `expand_aliases` in `BASHOPTS`.
/// Every other shell expands them, including the agent's own shell, whose
/// kind the runtime does not establish, and any shell Nah cannot name: that
/// reading is the more protective one.
pub(super) fn inherited_alias_mode(
    builder: &PlanBuilder,
    source: &str,
    vars: &HashMap<String, VarEntry>,
    unset: &BTreeSet<String>,
) -> (bool, bool) {
    let environment_lists = |name: &str, option: &str| {
        vars.get(name).is_some_and(|entry| {
            entry
                .value
                .as_deref()
                .is_none_or(|value| value.split(':').any(|listed| listed == option))
        })
    };
    // Bash keys POSIX mode on the variable being present, even when empty.
    let environment_enables = vars.contains_key("POSIXLY_CORRECT")
        && !unset.contains("POSIXLY_CORRECT")
        || environment_lists("SHELLOPTS", "posix")
        || environment_lists("BASHOPTS", "expand_aliases");
    let bash_options = match builder.script_interpreter() {
        ScriptInterpreter::Program("bash") => {
            Some(launching_bash_options(builder).map_or_else(Vec::new, <[_]>::to_vec))
        }
        // A script run by its path is read by the interpreter its `#!` line
        // names.
        ScriptInterpreter::Program(_) | ScriptInterpreter::Unknown => shebang_bash_options(source),
        ScriptInterpreter::Root | ScriptInterpreter::Unresolved => None,
    };
    match bash_options {
        Some(options) => (
            environment_enables || bash_starts_expanding_aliases(&options),
            true,
        ),
        None => (true, false),
    }
}

/// The options of a `#!` line naming bash, directly or through `env`.
fn shebang_bash_options(source: &str) -> Option<Vec<ResourceExpr>> {
    let line = source.strip_prefix("#!")?.lines().next()?;
    let mut words = line.split_whitespace();
    let mut program = words.next()?.rsplit('/').next()?;
    if program == "env" {
        program = words
            .by_ref()
            .find(|word| !word.starts_with('-') && !word.contains('='))?;
    }
    (program == "bash").then(|| {
        words
            .map(|word| ResourceExpr::Literal {
                value: word.to_string(),
            })
            .collect()
    })
}

/// Whether bash options turn alias expansion on: an interactive shell
/// (`-i`, including in a cluster such as `-ic`), POSIX mode (`--posix`,
/// `-o posix`) or `-O expand_aliases`. An option word Nah cannot read may
/// select any of them.
fn bash_starts_expanding_aliases(options: &[ResourceExpr]) -> bool {
    let (mut interactive, mut posix, mut expand_aliases) = (false, false, false);
    let mut words = options.iter();
    while let Some(word) = words.next() {
        let ResourceExpr::Literal { value: option } = word else {
            return true;
        };
        match option.as_str() {
            "--" | "-" => break,
            "--posix" => posix = true,
            "--rcfile" | "--init-file" => {
                words.next();
            }
            long if long.starts_with("--") => {}
            cluster if cluster.starts_with(['-', '+']) => {
                let on = cluster.starts_with('-');
                for letter in cluster[1..].chars() {
                    match letter {
                        'i' => interactive |= on,
                        'o' | 'O' => match words.next() {
                            Some(ResourceExpr::Literal { value }) => match (letter, value.as_str())
                            {
                                ('o', "posix") => posix = on,
                                ('O', "expand_aliases") => expand_aliases = on,
                                _ => {}
                            },
                            _ => return true,
                        },
                        _ => {}
                    }
                }
            }
            _ => break,
        }
    }
    interactive || posix || expand_aliases
}

/// Whether the launching bash turned `nocaseglob` on with `-O nocaseglob`
/// before the script's first line. A later `+O nocaseglob` turns it off again,
/// and an option word that is not literal leaves it off.
pub(super) fn inherited_nocaseglob(builder: &PlanBuilder) -> bool {
    launching_bash_options(builder).is_some_and(|argv| {
        let mut enabled = false;
        let mut position = 0;
        while position < argv.len() {
            let ResourceExpr::Literal { value: option } = &argv[position] else {
                return false;
            };
            if option == "-c" || option.starts_with("-c") && option.len() > 2 {
                break;
            }
            if matches!(option.as_str(), "-O" | "+O")
                && matches!(argv.get(position + 1), Some(ResourceExpr::Literal { value }) if value == "nocaseglob")
            {
                enabled = option == "-O";
                position += 2;
            } else {
                position += 1;
            }
        }
        enabled
    })
}
