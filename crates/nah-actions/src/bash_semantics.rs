//! Canonicalizes bounded shell semantics before feature-specific lowering.

use nah_parse::Word;
use nah_proto::ctx::Platform;

use crate::shell_word::static_word;

#[derive(Clone, Copy)]
struct OptionRule {
    canonical: &'static str,
    minimum: &'static str,
}

const fn rule(canonical: &'static str, minimum: &'static str) -> OptionRule {
    OptionRule { canonical, minimum }
}

pub(crate) fn normalize_program(program: &str, platform: Platform) -> Option<String> {
    if !program.contains(['/', '\\']) {
        return Some(normalize_basename(program, platform));
    }
    trusted_program_basename(program, platform)
        .map(|basename| normalize_basename(basename, platform))
}

pub(crate) fn normalize_arguments(
    program: &str,
    arguments: &[Word],
    platform: Platform,
) -> Vec<Word> {
    if program == "git" {
        return normalize_git_arguments(arguments);
    }
    if platform != Platform::Linux {
        return arguments.to_vec();
    }
    let rules = match program {
        "rm" => &[
            rule("--recursive", "--r"),
            rule("--help", "--h"),
            rule("--version", "--vers"),
        ][..],
        "chmod" | "chown" | "chgrp" => &[
            rule("--recursive", "--rec"),
            rule("--help", "--h"),
            rule("--version", "--vers"),
        ],
        "setfacl" => &[
            rule("--recursive", "--rec"),
            rule("--help", "--h"),
            rule("--version", "--v"),
        ],
        _ => return arguments.to_vec(),
    };
    normalize_options(arguments, rules)
}

fn normalize_git_arguments(arguments: &[Word]) -> Vec<Word> {
    const GLOBAL_FLAGS: &[&str] = &[
        "--bare",
        "--glob-pathspecs",
        "--help",
        "--icase-pathspecs",
        "--literal-pathspecs",
        "--no-advice",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "--no-pager",
        "--no-replace-objects",
        "--noglob-pathspecs",
        "--paginate",
        "--version",
    ];
    const GLOBAL_VALUES: &[&str] = &[
        "--config-env",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    ];
    const GLOBAL_ATTACHED: &[&str] = &[
        "--config-env=",
        "--exec-path=",
        "--git-dir=",
        "--namespace=",
        "--super-prefix=",
        "--work-tree=",
    ];

    let normalized = arguments.to_vec();
    let mut index = 0;
    let subcommand = loop {
        let Some(argument) = normalized.get(index).and_then(static_argument) else {
            return normalized;
        };
        let argument = argument.as_str();
        if argument == "--" || argument == "--exec-path" {
            return normalized;
        }
        if matches!(argument, "-C" | "-c") || GLOBAL_VALUES.contains(&argument) {
            index += 2;
            if index > normalized.len() {
                return normalized;
            }
            continue;
        }
        if argument.starts_with("-C") && argument.len() > 2
            || argument.starts_with("-c") && argument[2..].contains('=')
            || GLOBAL_ATTACHED
                .iter()
                .any(|prefix| argument.starts_with(prefix))
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            if GLOBAL_FLAGS.contains(&argument) {
                index += 1;
                continue;
            }
            return normalized;
        }
        break argument.to_owned();
    };

    let rules = match subcommand.as_str() {
        "reset" => &[rule("--hard", "--h")][..],
        "gc" => &[rule("--prune", "--p")],
        "prune" => &[rule("--expire", "--exp"), rule("--dry-run", "--d")],
        "reflog" => &[
            rule("--expire", "--expire"),
            rule("--expire-unreachable", "--expire-"),
            rule("--all", "--a"),
            rule("--dry-run", "--d"),
        ],
        "push" => &[
            rule("--force-with-lease", "--force-w"),
            rule("--dry-run", "--dr"),
        ],
        _ => return normalized,
    };
    let mut result = normalized[..=index].to_vec();
    result.extend(normalize_options(&normalized[index + 1..], rules));
    result
}

fn normalize_options(arguments: &[Word], rules: &[OptionRule]) -> Vec<Word> {
    let mut after_separator = false;
    arguments
        .iter()
        .map(|argument| {
            if after_separator {
                return argument.clone();
            }
            let Some(value) = static_argument(argument) else {
                return argument.clone();
            };
            if value == "--" {
                after_separator = true;
                return argument.clone();
            }
            let canonical = canonical_long_option(&value, rules);
            if canonical == value {
                argument.clone()
            } else {
                Word::from_literal(&canonical)
            }
        })
        .collect()
}

fn canonical_long_option(argument: &str, rules: &[OptionRule]) -> String {
    let (name, value) = argument
        .split_once('=')
        .map_or((argument, None), |(name, value)| (name, Some(value)));
    let Some(rule) = rules.iter().find(|rule| {
        name.len() >= rule.minimum.len()
            && name.starts_with("--")
            && rule.canonical.starts_with(name)
    }) else {
        return argument.to_owned();
    };
    value.map_or_else(
        || rule.canonical.to_owned(),
        |value| format!("{}={value}", rule.canonical),
    )
}

fn static_argument(argument: &Word) -> Option<String> {
    static_word(argument.raw(), argument.substitutions().is_empty())
}

fn normalize_basename(program: &str, platform: Platform) -> String {
    if platform == Platform::Windows {
        let program = program.to_ascii_lowercase();
        program.strip_suffix(".exe").unwrap_or(&program).to_owned()
    } else {
        program.to_owned()
    }
}

fn trusted_program_basename(program: &str, platform: Platform) -> Option<&str> {
    if platform == Platform::Windows || program.contains('\\') {
        return None;
    }
    let (directory, basename) = program.rsplit_once('/')?;
    (!basename.is_empty() && matches!(directory, "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin"))
        .then_some(basename)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standard_qualified_programs_are_canonicalized() {
        assert_eq!(
            normalize_program("/usr/bin/chmod", Platform::Linux).as_deref(),
            Some("chmod")
        );
        assert_eq!(normalize_program("/tmp/chmod", Platform::Linux), None);
        assert_eq!(normalize_program("./chmod", Platform::Linux), None);
        assert_eq!(
            normalize_program("CMD.EXE", Platform::Windows).as_deref(),
            Some("cmd")
        );
    }

    #[test]
    fn only_accepted_option_prefixes_are_canonicalized() {
        let words = ["--rec", "--re", "--unknown"]
            .map(Word::from_literal)
            .to_vec();
        let normalized = normalize_arguments("chmod", &words, Platform::Linux);
        assert_eq!(
            normalized
                .iter()
                .map(|word| static_argument(word).unwrap())
                .collect::<Vec<_>>(),
            ["--recursive", "--re", "--unknown"]
        );

        let words = ["reset", "--h", "--"].map(Word::from_literal).to_vec();
        let normalized = normalize_arguments("git", &words, Platform::Linux);
        assert_eq!(
            normalized
                .iter()
                .map(|word| static_argument(word).unwrap())
                .collect::<Vec<_>>(),
            ["reset", "--hard", "--"]
        );

        let words = ["--git-d=/tmp", "reset", "--h"]
            .map(Word::from_literal)
            .to_vec();
        let normalized = normalize_arguments("git", &words, Platform::Linux);
        assert_eq!(
            normalized
                .iter()
                .map(|word| static_argument(word).unwrap())
                .collect::<Vec<_>>(),
            ["--git-d=/tmp", "reset", "--h"]
        );
    }
}
