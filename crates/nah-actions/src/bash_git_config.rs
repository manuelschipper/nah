//! Interprets bounded static Git command-line configuration and aliases.

use nah_parse::{Statement, Word};

use crate::shell_word::static_word;

pub(crate) struct ParsedGit<'a> {
    complete: bool,
    terminal: bool,
    subcommand: Option<String>,
    arguments: &'a [Word],
    configs: Vec<(String, String)>,
    globals: Vec<String>,
}

impl<'a> ParsedGit<'a> {
    pub(crate) const fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn command(&self) -> Option<(&str, &'a [Word])> {
        (!self.terminal)
            .then(|| {
                self.subcommand
                    .as_deref()
                    .map(|name| (name, self.arguments))
            })
            .flatten()
    }

    pub(crate) fn config(&self, key: &str) -> Option<&str> {
        self.configs
            .iter()
            .rev()
            .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
    }

    fn alias(&self) -> Option<&str> {
        let subcommand = self.subcommand.as_deref()?;
        if known_git_command(subcommand) {
            return None;
        }
        self.configs.iter().rev().find_map(|(key, value)| {
            let (section, name) = key.split_once('.')?;
            (section == "alias" && name.eq_ignore_ascii_case(subcommand)).then_some(value.as_str())
        })
    }
}

pub(crate) struct AliasAnalysis {
    pub(crate) complete: bool,
    pub(crate) payload: Option<String>,
}

pub(crate) fn parse(arguments: &[Word]) -> ParsedGit<'_> {
    const FLAGS: &[&str] = &[
        "-p",
        "-P",
        "--bare",
        "--glob-pathspecs",
        "--icase-pathspecs",
        "--literal-pathspecs",
        "--no-advice",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "--no-pager",
        "--no-replace-objects",
        "--noglob-pathspecs",
        "--paginate",
    ];
    const VALUES: &[&str] = &[
        "-C",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    ];
    const ATTACHED: &[&str] = &[
        "--exec-path=",
        "--git-dir=",
        "--namespace=",
        "--super-prefix=",
        "--work-tree=",
    ];

    let mut parsed = ParsedGit {
        complete: true,
        terminal: false,
        subcommand: None,
        arguments: &[],
        configs: Vec::new(),
        globals: Vec::new(),
    };
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let Some(argument) = static_argument(word) else {
            parsed.complete = false;
            return parsed;
        };
        if matches!(argument.as_str(), "--help" | "--version" | "--exec-path") {
            parsed.terminal = true;
            return parsed;
        }
        if argument == "-c" {
            let Some(value) = arguments.get(index + 1).and_then(static_argument) else {
                parsed.complete = false;
                return parsed;
            };
            parsed.globals.extend(["-c".to_owned(), value.clone()]);
            parsed.complete &= add_config(&mut parsed.configs, &value);
            index += 2;
            continue;
        }
        if let Some(value) = argument
            .strip_prefix("-c")
            .filter(|value| !value.is_empty())
        {
            if !value.contains('=') {
                parsed.complete = false;
                return parsed;
            }
            parsed.globals.push(argument.clone());
            parsed.complete &= add_config(&mut parsed.configs, value);
            index += 1;
            continue;
        }
        if argument == "--config-env" {
            index += 2;
            parsed.complete = false;
            if index > arguments.len() {
                return parsed;
            }
            continue;
        }
        if argument.starts_with("--config-env=") {
            parsed.complete = false;
            index += 1;
            continue;
        }
        if VALUES.contains(&argument.as_str()) {
            let Some(value) = arguments.get(index + 1).and_then(static_argument) else {
                index += 2;
                parsed.complete = false;
                if index > arguments.len() {
                    return parsed;
                }
                continue;
            };
            parsed.globals.extend([argument, value]);
            index += 2;
            continue;
        }
        if argument.starts_with("-C") && argument.len() > 2
            || ATTACHED.iter().any(|prefix| argument.starts_with(prefix))
        {
            parsed.globals.push(argument);
            index += 1;
            continue;
        }
        if FLAGS.contains(&argument.as_str()) {
            parsed.globals.push(argument);
            index += 1;
            continue;
        }
        if argument == "--" || argument.starts_with('-') {
            parsed.complete = false;
            return parsed;
        }
        parsed.subcommand = Some(argument);
        parsed.arguments = &arguments[index + 1..];
        return parsed;
    }
    parsed
}

pub(crate) fn alias_analysis(arguments: &[Word]) -> AliasAnalysis {
    let parsed = parse(arguments);
    let Some(alias) = parsed.alias() else {
        return AliasAnalysis {
            complete: parsed.complete(),
            payload: None,
        };
    };
    let mut complete = parsed.complete();
    let mut tail = Vec::new();
    for argument in parsed.arguments {
        if let Some(argument) = static_argument(argument) {
            tail.push(argument);
        } else {
            complete = false;
        }
    }
    if let Some(command) = alias.strip_prefix('!') {
        let command = command.trim();
        if command.is_empty() {
            return AliasAnalysis {
                complete: false,
                payload: None,
            };
        }
        let suffix = shell_words(&tail);
        return AliasAnalysis {
            // Git runs shell aliases from the repository root, which is not
            // available until observations are fulfilled.
            complete: false,
            payload: Some(if suffix.is_empty() {
                command.to_owned()
            } else {
                format!("{command} {suffix}")
            }),
        };
    }

    let Some(mut command) = split_command_alias(alias) else {
        return AliasAnalysis {
            complete: false,
            payload: None,
        };
    };
    let mut words = vec!["git".to_owned()];
    words.extend(parsed.globals);
    words.append(&mut command);
    words.extend(tail);
    AliasAnalysis {
        complete,
        payload: Some(shell_words(&words)),
    }
}

fn add_config(configs: &mut Vec<(String, String)>, value: &str) -> bool {
    let (key, value) = value
        .split_once('=')
        .map_or((value, "true"), |(key, value)| (key, value));
    let key = key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return false;
    }
    let complete = matches!(key.as_str(), "gc.pruneexpire" | "user.email" | "user.name")
        || key
            .strip_prefix("alias.")
            .is_some_and(|name| !name.is_empty())
        || key.starts_with("advice.")
        || key.starts_with("color.");
    configs.push((key, value.trim().to_owned()));
    complete
}

fn split_command_alias(value: &str) -> Option<Vec<String>> {
    if value.contains(['$', '`', '\n', '\r']) {
        return None;
    }
    let source = format!("git {value}");
    let syntax = nah_parse::normalize(&source).ok()?;
    if !syntax.complete() || syntax.fork_bomb() {
        return None;
    }
    let [
        Statement::Command {
            name,
            name_substitutions,
            assignments,
            unmodeled_assignments,
            arguments,
            redirects,
        },
    ] = syntax.statements()
    else {
        return None;
    };
    if !name_substitutions.is_empty()
        || !assignments.is_empty()
        || !unmodeled_assignments.is_empty()
        || !redirects.is_empty()
        || static_word(name, true).as_deref() != Some("git")
    {
        return None;
    }
    let arguments = arguments
        .iter()
        .map(static_argument)
        .collect::<Option<Vec<_>>>()?;
    (!arguments.is_empty()).then_some(arguments)
}

fn known_git_command(command: &str) -> bool {
    const BUILTINS: &[&str] = &[
        "add",
        "am",
        "annotate",
        "apply",
        "archive",
        "bisect",
        "blame",
        "branch",
        "bugreport",
        "bundle",
        "cat-file",
        "check-attr",
        "check-ignore",
        "check-mailmap",
        "check-ref-format",
        "checkout",
        "checkout--worker",
        "checkout-index",
        "cherry",
        "cherry-pick",
        "clean",
        "clone",
        "column",
        "commit",
        "commit-graph",
        "commit-tree",
        "config",
        "count-objects",
        "credential",
        "credential-cache",
        "credential-cache--daemon",
        "credential-store",
        "describe",
        "diagnose",
        "diff",
        "diff-files",
        "diff-index",
        "diff-tree",
        "difftool",
        "fast-export",
        "fast-import",
        "fetch",
        "fetch-pack",
        "fmt-merge-msg",
        "for-each-ref",
        "for-each-repo",
        "format-patch",
        "fsck",
        "fsck-objects",
        "fsmonitor--daemon",
        "gc",
        "get-tar-commit-id",
        "grep",
        "hash-object",
        "help",
        "hook",
        "index-pack",
        "init",
        "init-db",
        "interpret-trailers",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "mailinfo",
        "mailsplit",
        "maintenance",
        "merge",
        "merge-base",
        "merge-file",
        "merge-index",
        "merge-ours",
        "merge-recursive",
        "merge-recursive-ours",
        "merge-recursive-theirs",
        "merge-subtree",
        "merge-tree",
        "mktag",
        "mktree",
        "multi-pack-index",
        "mv",
        "name-rev",
        "notes",
        "pack-objects",
        "pack-redundant",
        "pack-refs",
        "patch-id",
        "pickaxe",
        "prune",
        "prune-packed",
        "pull",
        "push",
        "range-diff",
        "read-tree",
        "rebase",
        "receive-pack",
        "reflog",
        "remote",
        "remote-ext",
        "remote-fd",
        "repack",
        "replace",
        "rerere",
        "reset",
        "restore",
        "rev-list",
        "rev-parse",
        "revert",
        "rm",
        "send-pack",
        "shortlog",
        "show",
        "show-branch",
        "show-index",
        "show-ref",
        "sparse-checkout",
        "stage",
        "stash",
        "status",
        "stripspace",
        "submodule--helper",
        "switch",
        "symbolic-ref",
        "tag",
        "unpack-file",
        "unpack-objects",
        "update-index",
        "update-ref",
        "update-server-info",
        "upload-archive",
        "upload-archive--writer",
        "upload-pack",
        "var",
        "verify-commit",
        "verify-pack",
        "verify-tag",
        "version",
        "whatchanged",
        "worktree",
        "write-tree",
    ];
    BUILTINS.contains(&command)
}

fn shell_words(words: &[String]) -> String {
    words
        .iter()
        .map(|word| Word::from_literal(word).raw().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn static_argument(argument: &Word) -> Option<String> {
    static_word(argument.raw(), argument.substitutions().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(source: &str) -> Vec<Word> {
        let syntax = nah_parse::normalize(&format!("git {source}")).unwrap();
        let [Statement::Command { arguments, .. }] = syntax.statements() else {
            panic!("command");
        };
        arguments.clone()
    }

    #[test]
    fn static_configuration_is_last_wins_and_dynamic_configuration_is_incomplete() {
        let arguments = words("-c gc.pruneExpire=never -c GC.PRUNEEXPIRE=now gc");
        let parsed = parse(&arguments);
        assert!(parsed.complete());
        assert_eq!(parsed.config("gc.pruneexpire"), Some("now"));
        assert_eq!(parsed.command().map(|(name, _)| name), Some("gc"));

        let arguments = words("-c \"user.name=$NAME\" status");
        assert!(!parse(&arguments).complete());

        let arguments = words("-c include.path=/tmp/other-config status");
        assert!(!parse(&arguments).complete());
        let arguments = words("-c core.pager=evil log");
        assert!(!parse(&arguments).complete());
    }

    #[test]
    fn command_and_shell_aliases_become_literal_shell_payloads() {
        let command = alias_analysis(&words("-c 'alias.x=reset \"--hard\"' x"));
        assert!(command.complete);
        assert!(
            command
                .payload
                .as_deref()
                .is_some_and(|payload| payload.contains("'reset' '--hard'"))
        );

        let shell = alias_analysis(&words("-c 'alias.x=!rm -rf /' x"));
        assert!(!shell.complete);
        assert_eq!(shell.payload.as_deref(), Some("rm -rf /"));
    }
}
