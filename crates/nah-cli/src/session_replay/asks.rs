//! The deletes a call's `rm` asks about before making, for the facts
//! export's `asks`: each delete effect whose `rm`, as the plan's argv states
//! it after aliases and functions, prompts first, so the delete happens only
//! if the prompt is answered yes. Whether anything answers it is not stated.
//!
//! Only what GNU and BSD `rm` agree on is stated. The last of `-i`, `-I` and
//! `-f` decides: a last `-i` asks before each removal, and a last `-I`, with
//! no `-i` and more than three operands, asks once. `-I` over a recursive
//! delete of fewer operands, any long option (`--interactive=WHEN` is
//! GNU's), an option the two do not share, an option after an operand
//! (only GNU reads it), and a computed word where an option may stand are
//! left unstated.
//!
//! A supplied home profile of the call's shell can define an `rm` alias
//! that adds the option. Nah does not know whether the shell running the
//! call loads that file (a non-interactive one usually expands no alias), so
//! such an entry names the alias and its file, and holds only if the shell
//! loads it. A profile is read as shell commands (`commands.rs`): only an
//! `alias` command outside every block, subshell and function body, run
//! whatever precedes it, whose `rm=VALUE` operand is literal, defines it;
//! the last definition counts. One that is computed or conditional, an
//! `unalias` of it, or text that does not lex leaves the file's alias
//! unknown, and a file sourced from the profile is not read. An unknown
//! alias, or another profile's alias that would not ask, leaves the delete
//! unstated. The alias applies only where the call's own shell runs `rm`
//! spelled plainly: `\rm`, `'rm'`, `command rm`, a path such as `/bin/rm`,
//! a program that runs `rm` (`sudo`, `env`, `xargs`, `find -exec`, `bash
//! -c`), and a call that runs `alias` or `unalias` itself state no alias
//! entry. A later `-f` turns it off as it does when spelled.

mod commands;

use nah_proto::effinterp_proto::{
    CommandShell, Effect, Plan, ProvenanceKind, ResourceExpr, ResourceIdentity, Subject,
};
use serde::Serialize;

/// One delete `rm` asks about first.
#[derive(Serialize)]
pub(super) struct Ask {
    /// The delete effect's id in the plan.
    effect: String,
    /// `each`: before each removal; `once`: once before all of them.
    asks: &'static str,
    /// The argv word holding the option that decides it, or for an alias
    /// the word of its value.
    option: String,
    /// The profile alias that adds the option; absent where the call's own
    /// argv decides.
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<ProfileAlias>,
}

/// An alias for `rm` read from a supplied profile file.
#[derive(Clone, Serialize)]
struct ProfileAlias {
    name: &'static str,
    /// The profile file the alias was read from.
    file: String,
    /// Always `if-shell-loads-file`: Nah does not establish that it does.
    applies: &'static str,
}

/// The home profile files of each shell whose `rm` alias is read.
fn profile_files(shell: CommandShell) -> &'static [&'static str] {
    match shell {
        CommandShell::Bash => &[".bashrc", ".bash_profile", ".bash_aliases", ".profile"],
        CommandShell::Zsh => &[".zshrc", ".zshenv"],
        CommandShell::Unknown => &[
            ".bashrc",
            ".bash_profile",
            ".bash_aliases",
            ".profile",
            ".zshrc",
            ".zshenv",
        ],
    }
}

/// The deletes of `plan` its `rm` asks about first, in plan order, with
/// `profile` answering the supplied text of a file below `home`.
pub(super) fn asks(plan: &Plan, home: &str, profile: &dyn Fn(&str) -> Option<String>) -> Vec<Ask> {
    // The `rm` alias each of the shell's supplied profiles defines last.
    let (source, aliases) = match &plan.subject {
        Subject::Shell {
            source, context, ..
        } => {
            let aliases: Vec<(String, Option<Vec<String>>)> = profile_files(context.shell)
                .iter()
                .map(|name| format!("{}/{name}", home.trim_end_matches('/')))
                .filter_map(|file| {
                    let text = profile(&file)?;
                    Some((file, rm_alias(&text)?))
                })
                .collect();
            (source.as_str(), aliases)
        }
        _ => ("", Vec::new()),
    };
    plan.effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .filter_map(|delete| {
            // The `rm` that deletes runs in the delete's own execution.
            let mut runs = plan.effects.iter().filter(|effect| {
                effect.execution == delete.execution && effect.operation.as_str() == "process.exec"
            });
            let (Some(run), None) = (runs.next(), runs.next()) else {
                return None;
            };
            let ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } = &run.resource
            else {
                return None;
            };
            if executable.rsplit('/').next() != Some("rm") {
                return None;
            }
            let effect = serde_json::to_value(&delete.id).ok()?.as_str()?.to_owned();
            if let Some((asks, option)) = prompt(argv) {
                return Some(vec![Ask {
                    effect,
                    asks,
                    option,
                    alias: None,
                }]);
            }
            if aliases.is_empty() || sets_aliases(source) || !spelled_plainly(plan, run, source) {
                return None;
            }
            // Every file's alias must ask, whichever the shell loads last.
            aliases
                .iter()
                .map(|(file, words)| {
                    let words = words.as_ref()?;
                    let mut expanded: Vec<ResourceExpr> = words[1..]
                        .iter()
                        .map(|word| ResourceExpr::Literal {
                            value: word.clone(),
                        })
                        .collect();
                    expanded.extend(argv.iter().cloned());
                    let (asks, option) = prompt(&expanded)?;
                    Some(Ask {
                        effect: effect.clone(),
                        asks,
                        option,
                        alias: Some(ProfileAlias {
                            name: "rm",
                            file: file.clone(),
                            applies: "if-shell-loads-file",
                        }),
                    })
                })
                .collect()
        })
        .flatten()
        .collect()
}

/// Whether the call's own shell runs `run` with its head spelled `rm`, the
/// one spelling an alias replaces: its only source span is in the call's
/// text, no model launched it, and past any assignments its first word is
/// the bare `rm`.
fn spelled_plainly(plan: &Plan, run: &Effect, source: &str) -> bool {
    let mut pending: Vec<usize> = run.provenance.iter().map(|node| node.0 as usize).collect();
    let mut spans = std::collections::BTreeSet::new();
    while let Some(index) = pending.pop() {
        let Some(node) = plan.provenance.get(index) else {
            return false;
        };
        match &node.kind {
            ProvenanceKind::ModelApplication { .. } => return false,
            // A span with antecedents is in a nested shell's text.
            ProvenanceKind::SourceSpan { .. } if !node.antecedents.is_empty() => return false,
            ProvenanceKind::SourceSpan { start, end } => {
                spans.insert((*start as usize, *end as usize));
            }
            _ => {}
        }
        pending.extend(node.antecedents.iter().map(|node| node.0 as usize));
    }
    let [(start, end)] = spans.into_iter().collect::<Vec<_>>()[..] else {
        return false;
    };
    source
        .get(start..end)
        .and_then(commands::commands)
        .and_then(|commands| {
            let command = commands.into_iter().next()?;
            let head = command.words.into_iter().find(|word| !assignment(word))?;
            Some(head.plain && head.text == "rm")
        })
        .unwrap_or(false)
}

/// Whether the call's text runs `alias` or `unalias`, or cannot be read as
/// commands, so a profile's alias may not be the one its `rm` meets.
fn sets_aliases(source: &str) -> bool {
    commands::commands(source).is_none_or(|commands| {
        commands
            .iter()
            .any(|command| matches!(name(command), Some((name, _)) if name == "alias" || name == "unalias"))
    })
}

/// Whether `word` is a shell assignment, `NAME=...`, as written.
fn assignment(word: &commands::Word) -> bool {
    word.raw.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

/// The name `command` runs past its assignments and any `builtin` or
/// `command` before it, with the words after it.
fn name(command: &commands::Command) -> Option<(&str, &[commands::Word])> {
    let mut words = &command.words[..];
    while let [word, rest @ ..] = words {
        if assignment(word) || matches!(word.text.as_str(), "builtin" | "command") {
            words = rest;
        } else {
            return Some((word.text.as_str(), rest));
        }
    }
    None
}

/// The `rm` alias a profile's `text` defines last: `None` where it names
/// none, `Some(None)` where the last one cannot be read, else its value's
/// words, which start with `rm`.
fn rm_alias(text: &str) -> Option<Option<Vec<String>>> {
    let Some(commands) = commands::commands(text) else {
        // Text that does not lex may still define one.
        return (text.contains("alias") && names_rm(text)).then_some(None);
    };
    let mut alias = None;
    for command in &commands {
        match name(command) {
            Some(("alias", operands)) => {
                let options = operands.iter().any(|word| word.text.starts_with('-'));
                for operand in operands {
                    let Some(("rm", value)) = operand.text.split_once('=') else {
                        continue;
                    };
                    let readable =
                        command.top_level && command.unconditional && !options && !operand.computed;
                    alias = Some(readable.then(|| definition(value)).flatten());
                }
            }
            Some(("unalias", operands))
                if operands
                    .iter()
                    .any(|word| word.text == "rm" || word.text == "-a") =>
            {
                alias = Some(None);
            }
            _ => {}
        }
    }
    alias
}

/// Whether `text` holds `rm` as a name of its own, not inside a longer one
/// such as `rmdir` or `perms`.
fn names_rm(text: &str) -> bool {
    let part_of_name = |character: char| character.is_ascii_alphanumeric() || character == '_';
    text.match_indices("rm").any(|(at, _)| {
        !text[..at].chars().next_back().is_some_and(part_of_name)
            && !text[at + 2..].chars().next().is_some_and(part_of_name)
    })
}

/// The words of an alias `value` after its quotes are removed, when they
/// start with `rm` and hold nothing a shell would expand, quote or split on
/// where the alias is used.
fn definition(value: &str) -> Option<Vec<String>> {
    if value
        .chars()
        .any(|character| "$`\\'\";&|<>()*?[]{}~#!\n".contains(character))
    {
        return None;
    }
    let words: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
    (words.first().map(String::as_str) == Some("rm")).then_some(words)
}

/// How `rm` with `argv` (after its name) prompts, and the word that decides
/// it; `None` where it does not, or where GNU and BSD `rm` may differ.
fn prompt(argv: &[ResourceExpr]) -> Option<(&'static str, String)> {
    // The last of `-i`, `-I` and `-f`, with the word holding it.
    let mut last: Option<(char, &str)> = None;
    let mut interactive = false;
    let mut operands = 0;
    let mut options_done = false;
    for word in argv {
        let ResourceExpr::Literal { value } = word else {
            // A computed word may be an option unless `--` came first.
            if !options_done {
                return None;
            }
            operands += 1;
            continue;
        };
        if options_done {
            operands += 1;
        } else if value == "--" {
            options_done = true;
        } else if value.starts_with("--") {
            return None;
        } else if let Some(flags) = value.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            // GNU reads an option after an operand; BSD takes it for a file.
            if operands > 0 {
                return None;
            }
            for flag in flags.chars() {
                match flag {
                    'i' | 'I' | 'f' => {
                        interactive |= flag == 'i';
                        last = Some((flag, value));
                    }
                    'd' | 'r' | 'R' | 'v' => {}
                    _ => return None,
                }
            }
        } else {
            operands += 1;
        }
    }
    match last? {
        ('i', word) => Some(("each", word.to_owned())),
        ('I', word) if !interactive && operands > 3 => Some(("once", word.to_owned())),
        _ => None,
    }
}
