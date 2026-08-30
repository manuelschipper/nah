//! Tags visible nah state mutations; it does not enforce structural protection.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::{AbsolutePath, Platform};

use crate::bash_filesystem::command_filesystems;
use crate::bash_model::VariableValue;
use crate::bash_symlinks::ln_symbolic_mode;
use crate::paths::{contains, resolve_from_cwd};
use crate::shell_word::{contains_unquoted_pattern, static_word};

pub(crate) struct EnvironmentVariables<'a> {
    pub(crate) visible: &'a [(String, VariableValue)],
    pub(crate) runtime: &'a [(String, VariableValue)],
}

pub(crate) fn operation(
    program: &str,
    arguments: &[Word],
    home: &str,
    platform: Platform,
) -> Option<&'static str> {
    let words = arguments
        .iter()
        .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    operation_for_values_at(program, &words, Some((home, platform)))
}

pub(crate) fn operation_for_values(program: &str, words: &[String]) -> Option<&'static str> {
    operation_for_values_at(program, words, None)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn protected_cargo_install_operation(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Option<String>)],
    variables: EnvironmentVariables<'_>,
    cwd: Option<&str>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    if normalized_program(program) != "cargo" {
        return None;
    }
    let words = arguments
        .iter()
        .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    let (installs_nah, explicit_root) = cargo_install(&words)?;
    if !installs_nah {
        return None;
    }
    let root = if let Some(root) = explicit_root {
        root.to_owned()
    } else if let Some((_, value)) = assignments
        .iter()
        .rev()
        .find(|(name, _)| name == "CARGO_HOME")
    {
        value
            .as_deref()
            .filter(|value| !value.is_empty())?
            .to_owned()
    } else {
        match variables
            .visible
            .iter()
            .rev()
            .find(|(name, _)| name == "CARGO_HOME")
            .map(|(_, value)| value)
        {
            Some(VariableValue::Static(value)) if !value.is_empty() => value.clone(),
            Some(VariableValue::Unset) | None => format!("{home}/.cargo"),
            Some(VariableValue::Static(_)) | Some(VariableValue::Unknown) => return None,
        }
    };
    let root = resolve_from_cwd(cwd, cwd, &root, home, platform, true)?;
    let binary = if platform == Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    protected_path(
        &format!("{root}/bin/{binary}"),
        home,
        critical_paths,
        platform,
    )
    .then_some("critical-mutation")
}

pub(crate) fn cargo_install_command(arguments: &[Word]) -> bool {
    arguments
        .iter()
        .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()
        .is_some_and(|words| cargo_install(&words).is_some())
}

pub(crate) fn protected_git_operation(
    program: &str,
    arguments: &[Word],
    cwd: Option<&str>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    if normalized_program(program) != "git" {
        return None;
    }
    let values = arguments
        .iter()
        .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    if terminal_help(&values) {
        return None;
    }
    let mut git_cwd = cwd?.to_owned();
    let mut index = 0;
    while let Some(argument) = values.get(index) {
        if argument == "-C" {
            let directory = values.get(index + 1)?;
            git_cwd = resolve_from_cwd(
                Some(&git_cwd),
                Some(&git_cwd),
                directory,
                home,
                platform,
                true,
            )?;
            index += 2;
        } else if let Some(directory) = argument
            .strip_prefix("-C")
            .filter(|value| !value.is_empty())
        {
            git_cwd = resolve_from_cwd(
                Some(&git_cwd),
                Some(&git_cwd),
                directory,
                home,
                platform,
                true,
            )?;
            index += 1;
        } else if matches!(argument.as_str(), "-c" | "--config-env") {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    let subcommand = values.get(index)?;
    let arguments = &values[index + 1..];
    let protected = |path: &str| protected_path(path, home, critical_paths, platform);
    match subcommand.as_str() {
        "init" => {
            let mut target = git_cwd;
            let mut cursor = 0;
            while let Some(argument) = arguments.get(cursor) {
                if matches!(argument.as_str(), "--separate-git-dir" | "--template") {
                    cursor += 2;
                    continue;
                }
                if let Some(path) = argument.strip_prefix("--separate-git-dir=")
                    && resolve_from_cwd(Some(&target), Some(&target), path, home, platform, true)
                        .is_some_and(|path| protected(&path))
                {
                    return Some("critical-mutation");
                }
                if !argument.starts_with('-') {
                    target = resolve_from_cwd(
                        Some(&target),
                        Some(&target),
                        argument,
                        home,
                        platform,
                        true,
                    )?;
                }
                cursor += 1;
            }
            protected(&target).then_some("critical-mutation")
        }
        "clean" => {
            let force = arguments
                .iter()
                .take_while(|value| *value != "--")
                .any(|value| {
                    value == "--force"
                        || value
                            .strip_prefix('-')
                            .is_some_and(|flags| !flags.starts_with('-') && flags.contains('f'))
                });
            let dry_run = arguments
                .iter()
                .take_while(|value| *value != "--")
                .any(|value| {
                    value == "--dry-run"
                        || value
                            .strip_prefix('-')
                            .is_some_and(|flags| !flags.starts_with('-') && flags.contains('n'))
                });
            (force && !dry_run && protected(&git_cwd)).then_some("critical-mutation")
        }
        _ => None,
    }
}

pub(crate) fn protected_access_control_operation(
    program: &str,
    arguments: &[Word],
    cwd: Option<&str>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    let program = normalized_program(program);
    if !matches!(program.as_str(), "chmod" | "chown" | "chgrp" | "setfacl") {
        return None;
    }
    command_filesystems(&program, arguments)?
        .iter()
        .filter(|(_, operation, _)| *operation == FilesystemOperation::Write)
        .filter_map(|(target, _, _)| resolve_from_cwd(cwd, cwd, target, home, platform, true))
        .any(|target| protected_path_ancestor(&target, home, critical_paths, platform))
        .then_some("critical-mutation")
}

fn operation_for_values_at(
    program: &str,
    words: &[String],
    runtime: Option<(&str, Platform)>,
) -> Option<&'static str> {
    let program = normalized_program(program);
    if program == "cargo" {
        return cargo_uninstalls_nah(words).then_some("critical-mutation");
    }
    if runtime_terminal_information(words) {
        return None;
    }
    if runtime_mutation(&program, words)
        || runtime_launch_bypass(
            &program,
            words,
            runtime.map(|(home, _)| home),
            runtime.map(|(_, platform)| platform),
        )
    {
        return Some("critical-mutation");
    }
    if program != "nah" {
        return None;
    }
    if terminal_help(words) {
        return None;
    }
    match words {
        [command, ..] if command == "nap" => Some("permanent-mutation"),
        [command, ..] if matches!(command.as_str(), "tui" | "effinterp") => {
            Some("critical-mutation")
        }
        [command, ..] if matches!(command.as_str(), "trust" | "untrust") => {
            Some("critical-mutation")
        }
        [kind, command, ..]
            if kind == "guard" && matches!(command.as_str(), "enable" | "disable") =>
        {
            Some("critical-mutation")
        }
        [kind, runtime, action, ..]
            if kind == "hook"
                && runtime_name(runtime)
                && matches!(action.as_str(), "install" | "uninstall") =>
        {
            Some("critical-mutation")
        }
        _ => None,
    }
}

pub(crate) fn environment_operation(
    program: &str,
    words: &[String],
    assignments: &[(String, Option<String>)],
    variables: EnvironmentVariables<'_>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    if runtime_terminal_information(words) {
        return None;
    }
    let value = |name: &str| {
        assignments
            .iter()
            .rev()
            .find(|(assigned, _)| assigned == name)
            .and_then(|(_, value)| value.as_deref())
            .or_else(|| {
                variables
                    .visible
                    .iter()
                    .rev()
                    .find(|(variable, _)| variable == name)
                    .and_then(|(_, value)| value.as_static())
            })
    };
    let home_path = |suffix: &str| format!("{home}/{suffix}");
    let program = normalized_program(program);
    let active_selector = match program.as_str() {
        "hermes" => has_projected_path(critical_paths, "config.yaml", platform),
        "kiro-cli" => has_projected_path(critical_paths, "hooks/nah.json", platform),
        "prime-agent" => has_projected_path(critical_paths, "extensions/nah.js", platform),
        _ => false,
    };
    let baseline = |name: &str| {
        variables
            .runtime
            .iter()
            .rev()
            .find(|(variable, _)| variable == name)
            .and_then(|(_, value)| value.as_static())
            .filter(|value| !value.is_empty())
    };
    let alternate = |name: &str, default: &str| {
        let expected = match (name, active_selector) {
            ("HERMES_HOME" | "KIRO_HOME" | "PRIME_AGENT_CODING_AGENT_DIR", true) => {
                baseline(name).unwrap_or(default)
            }
            _ => default,
        };
        let configured = value(name)
            .filter(|value| !value.is_empty())
            .unwrap_or(default);
        !same_lexical_path(configured, expected, platform)
    };
    let bypass = match program.as_str() {
        "amp" => value("PLUGINS") == Some("off"),
        "cline" => alternate("CLINE_DIR", &home_path(".cline")),
        "codex" => alternate("CODEX_HOME", &home_path(".codex")),
        "copilot" => alternate("COPILOT_HOME", &home_path(".copilot")),
        "hermes" => alternate("HERMES_HOME", &home_path(".hermes")),
        "kiro-cli" => alternate("KIRO_HOME", &home_path(".kiro")),
        "openclaw" => {
            alternate("OPENCLAW_HOME", &home_path(".openclaw"))
                || alternate("OPENCLAW_STATE_DIR", &home_path(".openclaw"))
                || alternate(
                    "OPENCLAW_CONFIG_PATH",
                    &home_path(".openclaw/openclaw.json"),
                )
                || value("OPENCLAW_PROFILE").is_some_and(|value| {
                    !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("default")
                })
        }
        "opencode" => {
            value("OPENCODE_PURE") == Some("1")
                || alternate("XDG_CONFIG_HOME", &home_path(".config"))
        }
        "pi" => alternate("PI_CODING_AGENT_DIR", &home_path(".pi/agent")),
        "prime-agent" => alternate("PRIME_AGENT_CODING_AGENT_DIR", &home_path(".prime/agent")),
        _ => false,
    };
    bypass.then_some("critical-mutation")
}

fn runtime_mutation(program: &str, words: &[String]) -> bool {
    let exact_or_child = |value: &str, parent: &str| {
        value == parent
            || value
                .strip_prefix(parent)
                .is_some_and(|suffix| suffix.starts_with(['.', '[']))
    };
    let names_nah = |word: Option<&String>| {
        word.is_some_and(|word| matches!(word.as_str(), "nah" | "nah.ts" | "nah.json"))
    };
    match program {
        "amp" => words.windows(3).any(|parts| {
            parts[0] == "plugins"
                && matches!(parts[1].as_str(), "remove" | "rm")
                && names_nah(parts.get(2))
        }),
        "agy" => words.windows(3).any(|parts| {
            parts[0] == "plugin"
                && matches!(parts[1].as_str(), "disable" | "uninstall")
                && names_nah(parts.get(2))
        }),
        "droid" => words.windows(3).any(|parts| {
            parts[0] == "plugin"
                && matches!(parts[1].as_str(), "remove" | "uninstall")
                && names_nah(parts.get(2))
        }),
        "hermes" => {
            words.windows(3).any(|parts| {
                parts[0] == "hooks"
                    && matches!(parts[1].as_str(), "revoke" | "remove" | "rm")
                    && parts[2] == "nah hook hermes run"
            }) || words.windows(3).any(|parts| {
                parts[0] == "config"
                    && matches!(parts[1].as_str(), "set" | "unset")
                    && exact_or_child(&parts[2], "hooks.pre_tool_call")
            })
        }
        "copilot" => words.windows(3).any(|parts| {
            matches!(parts[0].as_str(), "plugin" | "plugins")
                && matches!(parts[1].as_str(), "disable" | "remove" | "uninstall")
                && names_nah(parts.get(2))
        }),
        "openclaw" => {
            words.windows(3).any(|parts| {
                parts[0] == "plugins"
                    && matches!(parts[1].as_str(), "disable" | "uninstall")
                    && names_nah(parts.get(2))
            }) || words.windows(4).any(|parts| {
                parts[0] == "plugins"
                    && parts[1] == "uninstall"
                    && parts[2] == "--force"
                    && names_nah(parts.get(3))
            }) || words.windows(4).any(|parts| {
                parts[0] == "config"
                    && parts[1] == "set"
                    && parts[2] == "plugins.enabled"
                    && parts[3] == "false"
            }) || words.windows(3).any(|parts| {
                parts[0] == "config"
                    && parts[1] == "unset"
                    && exact_or_child(&parts[2], "plugins.entries.nah")
            })
        }
        _ => false,
    }
}

fn runtime_launch_bypass(
    program: &str,
    words: &[String],
    home: Option<&str>,
    platform: Option<Platform>,
) -> bool {
    if runtime_terminal_information(words) {
        return false;
    }
    let has_option = |option: &str| words.iter().any(|word| word == option);
    let option_value = |option: &str| {
        words
            .windows(2)
            .find(|parts| parts[0] == option)
            .map(|parts| parts[1].as_str())
            .or_else(|| {
                words
                    .iter()
                    .find_map(|word| word.strip_prefix(option)?.strip_prefix('='))
            })
    };
    let program = normalized_program(program);
    match program.as_str() {
        "claude" => has_option("--safe-mode") || has_option("--bare"),
        "cline" => option_value("--config").is_some_and(|value| {
            !value.is_empty()
                && !home.zip(platform).is_some_and(|(home, platform)| {
                    same_lexical_path(value, &format!("{home}/.cline"), platform)
                })
        }),
        "codex" => {
            words
                .windows(2)
                .any(|parts| parts[0] == "--disable" && parts[1] == "hooks")
                || has_option("--disable=hooks")
        }
        "devin" => option_value("--config").is_some_and(|value| {
            !value.is_empty()
                && !home.zip(platform).is_some_and(|(home, platform)| {
                    let relative = if platform == Platform::Windows {
                        "AppData/Roaming/devin/config.json"
                    } else {
                        ".config/devin/config.json"
                    };
                    same_lexical_path(value, &format!("{home}/{relative}"), platform)
                })
        }),
        "droid" => option_value("--settings").is_some_and(|value| {
            !value.is_empty()
                && !home.zip(platform).is_some_and(|(home, platform)| {
                    same_lexical_path(value, &format!("{home}/.factory/settings.json"), platform)
                })
        }),
        "hermes" => has_option("--safe-mode") || has_option("--ignore-user-config"),
        "openclaw" => {
            option_value("--profile").is_some_and(|value| {
                !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("default")
            }) || has_option("--dev")
        }
        "opencode" => has_option("--pure"),
        "pi" => has_option("--no-extensions"),
        "prime-agent" => has_option("--no-extensions"),
        _ => false,
    }
}

fn runtime_terminal_information(words: &[String]) -> bool {
    words
        .iter()
        .take_while(|word| word.as_str() != "--")
        .any(|word| matches!(word.as_str(), "-h" | "--help" | "-V" | "--version"))
}

pub(crate) fn hardlink_operation(
    program: &str,
    arguments: &[Word],
    cwd: Option<&str>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    let program = normalized_program(program);
    let cp_hardlink = program == "cp"
        && arguments.iter().any(|argument| {
            static_word(argument.raw(), argument.substitutions().is_empty()).is_some_and(|value| {
                value == "--link"
                    || value
                        .strip_prefix('-')
                        .filter(|flags| !flags.starts_with('-'))
                        .is_some_and(|flags| flags.contains('l'))
            })
        });
    if !matches!(program.as_str(), "ln" | "link") && !cp_hardlink
        || program == "ln" && ln_symbolic_mode(arguments)
        || terminal_help(
            &arguments
                .iter()
                .filter_map(|word| static_word(word.raw(), word.substitutions().is_empty()))
                .collect::<Vec<_>>(),
        )
    {
        return None;
    }
    command_filesystems(&program, arguments)?
        .into_iter()
        .filter(|(_, operation, _)| *operation == FilesystemOperation::Read)
        .filter_map(|(source, _, _)| {
            resolve_from_cwd(cwd, cwd, &source, home, platform, source.starts_with('~'))
        })
        .any(|source| protected_path(&source, home, critical_paths, platform))
        .then_some("critical-mutation")
}

pub(crate) fn potential_operation_for_words(
    program: &str,
    words: &[String],
) -> Option<&'static str> {
    potential_mutation(program, words, false).map(|(_, operation)| operation)
}

pub(crate) fn potential_mutation_for_words(
    program: &str,
    words: &[String],
) -> Option<(&'static str, &'static str)> {
    potential_mutation(program, words, true)
}

fn potential_mutation(
    program: &str,
    words: &[String],
    pattern_program: bool,
) -> Option<(&'static str, &'static str)> {
    if definitely_terminal_help(words) {
        return None;
    }
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let program_may_equal =
        |candidate| pattern_program && may_equal(basename, candidate) || basename == candidate;
    if program_may_equal("nah") {
        if pattern_program && contains_unquoted_pattern(basename) {
            return Some(("nah", "critical-mutation"));
        }
        if word_may_equal(words.first(), "nap") {
            return Some(("nah", "permanent-mutation"));
        }
        if ["tui", "trust", "untrust", "effinterp"]
            .iter()
            .any(|command| word_may_equal(words.first(), command))
            || words.windows(2).any(|parts| {
                word_may_equal(parts.first(), "guard")
                    && ["enable", "disable"]
                        .iter()
                        .any(|action| word_may_equal(parts.get(1), action))
            })
        {
            return Some(("nah", "critical-mutation"));
        }
        if words.windows(3).any(|parts| {
            word_may_equal(parts.first(), "hook")
                && runtime_names()
                    .iter()
                    .any(|runtime| word_may_equal(parts.get(1), runtime))
                && ["install", "uninstall"]
                    .iter()
                    .any(|action| word_may_equal(parts.get(2), action))
        }) {
            return Some(("nah", "critical-mutation"));
        }
    }
    if program_may_equal("cargo") && potential_cargo_uninstall(words) {
        return Some(("cargo", "critical-mutation"));
    }
    None
}

fn potential_cargo_uninstall(words: &[String]) -> bool {
    let mut uninstall = usize::from(
        words
            .first()
            .is_some_and(|word| definite_value(word).is_some_and(|word| word.starts_with('+'))),
    );
    loop {
        let Some(word) = words.get(uninstall) else {
            return false;
        };
        if may_equal(word, "uninstall") {
            break;
        }
        let Some(word) = definite_value(word) else {
            return false;
        };
        if matches!(
            word.as_str(),
            "-v" | "--verbose" | "-q" | "--quiet" | "--frozen" | "--locked" | "--offline"
        ) || word.starts_with("-vv")
            || word.starts_with("--color=")
            || word.starts_with("--config=")
        {
            uninstall += 1;
        } else if matches!(word.as_str(), "--color" | "--config" | "-Z") {
            uninstall += 2;
        } else {
            return false;
        }
    }
    words[uninstall + 1..]
        .iter()
        .enumerate()
        .any(|(index, word)| {
            [
                "nah",
                "nah-cli",
                "--package=nah-cli",
                "-pnah-cli",
                "--bin=nah",
            ]
            .iter()
            .any(|candidate| may_equal(word, candidate))
                || ["-p", "--package", "--bin"]
                    .iter()
                    .any(|option| may_equal(word, option))
                    && words[uninstall + index + 2..].first().is_some_and(|value| {
                        ["nah", "nah-cli"]
                            .iter()
                            .any(|candidate| may_equal(value, candidate))
                    })
        })
}

fn definite_value(raw: &str) -> Option<String> {
    (!contains_unquoted_pattern(raw))
        .then(|| static_word(raw, true))
        .flatten()
}

fn word_may_equal(word: Option<&String>, candidate: &str) -> bool {
    word.is_some_and(|word| may_equal(word, candidate))
}

fn definitely_terminal_help(words: &[String]) -> bool {
    words
        .iter()
        .map(String::as_str)
        .take_while(|word| *word != "--")
        .any(|word| {
            !contains_unquoted_pattern(word)
                && static_word(word, true)
                    .is_some_and(|word| matches!(word.as_str(), "-h" | "--help"))
        })
}

fn may_equal(raw: &str, candidate: &str) -> bool {
    let Some(pattern) = static_word(raw, true) else {
        return true;
    };
    if !contains_unquoted_pattern(raw) {
        return pattern == candidate;
    }
    choice_patterns(&pattern)
        .iter()
        .any(|pattern| wildcard_may_match(pattern, candidate))
}

fn choice_patterns(pattern: &str) -> Vec<String> {
    const MAX_CHOICES: usize = 32;

    let mut pending = vec![pattern.to_owned()];
    let mut expanded = Vec::new();
    while let Some(pattern) = pending.pop() {
        let Some(group) = first_choice_group(&pattern) else {
            expanded.push(pattern);
            continue;
        };
        let choices = match group.kind {
            ChoiceKind::Brace => split_choices(&pattern[group.content.clone()], b','),
            ChoiceKind::ExactlyOne => split_choices(&pattern[group.content.clone()], b'|'),
            ChoiceKind::Optional => {
                let mut choices = split_choices(&pattern[group.content.clone()], b'|');
                choices.push("");
                choices
            }
            ChoiceKind::Unbounded => vec!["*"],
        };
        if choices.len() <= 1 && group.kind == ChoiceKind::Brace {
            let mut conservative = pattern.clone();
            conservative.replace_range(group.full, "*");
            pending.push(conservative);
            continue;
        }
        if pending
            .len()
            .saturating_add(expanded.len())
            .saturating_add(choices.len())
            > MAX_CHOICES
        {
            return vec!["*".to_owned()];
        }
        for choice in choices {
            let mut candidate = pattern.clone();
            candidate.replace_range(group.full.clone(), choice);
            pending.push(candidate);
        }
    }
    expanded
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ChoiceKind {
    Brace,
    ExactlyOne,
    Optional,
    Unbounded,
}

struct ChoiceGroup {
    full: std::ops::Range<usize>,
    content: std::ops::Range<usize>,
    kind: ChoiceKind,
}

fn first_choice_group(pattern: &str) -> Option<ChoiceGroup> {
    let bytes = pattern.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let (open, close, kind, content_start) = match bytes[index] {
            b'{' => (b'{', b'}', ChoiceKind::Brace, index + 1),
            b'@' if bytes.get(index + 1) == Some(&b'(') => {
                (b'(', b')', ChoiceKind::ExactlyOne, index + 2)
            }
            b'?' if bytes.get(index + 1) == Some(&b'(') => {
                (b'(', b')', ChoiceKind::Optional, index + 2)
            }
            b'+' | b'*' | b'!' if bytes.get(index + 1) == Some(&b'(') => {
                (b'(', b')', ChoiceKind::Unbounded, index + 2)
            }
            _ => {
                index += 1;
                continue;
            }
        };
        let end = matching_delimiter(bytes, content_start, open, close)?;
        return Some(ChoiceGroup {
            full: index..end + 1,
            content: content_start..end,
            kind,
        });
    }
    None
}

fn matching_delimiter(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0;
    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        if byte == open {
            depth += 1;
        } else if byte == close {
            if depth == 0 {
                return Some(start + offset);
            }
            depth -= 1;
        }
    }
    None
}

fn split_choices(value: &str, separator: u8) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut choices = Vec::new();
    let mut start = 0;
    let mut parens = 0usize;
    let mut braces = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b'{' => braces += 1,
            b'}' => braces = braces.saturating_sub(1),
            _ if byte == separator && parens == 0 && braces == 0 => {
                choices.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    choices.push(&value[start..]);
    choices
}

fn wildcard_may_match(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.as_bytes();
    let candidate = candidate.as_bytes();
    let (mut pattern_index, mut candidate_index) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while candidate_index < candidate.len() {
        if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry = candidate_index;
        } else if matches!(pattern.get(pattern_index), Some(b'?')) {
            pattern_index += 1;
            candidate_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'[') {
            pattern_index = pattern[pattern_index + 1..]
                .iter()
                .position(|byte| *byte == b']')
                .map_or(pattern_index + 1, |offset| pattern_index + offset + 2);
            candidate_index += 1;
        } else if pattern.get(pattern_index) == candidate.get(candidate_index) {
            pattern_index += 1;
            candidate_index += 1;
        } else if let Some(star_index) = star {
            retry += 1;
            candidate_index = retry;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn cargo_uninstalls_nah(words: &[String]) -> bool {
    let Some(mut index) = cargo_subcommand_arguments(words, "uninstall") else {
        return false;
    };
    let mut after_options = false;
    while index < words.len() {
        let word = words[index].as_str();
        if !after_options && word == "--" {
            after_options = true;
        } else if !after_options && matches!(word, "--root" | "--color" | "--config" | "-Z") {
            index += 1;
        } else if !after_options && matches!(word, "-p" | "--package" | "--bin") {
            let Some(value) = words.get(index + 1) else {
                return false;
            };
            if (word == "--bin" && value == "nah") || (word != "--bin" && nah_package_spec(value)) {
                return true;
            }
            index += 1;
        } else if (!after_options
            && (word
                .strip_prefix("--package=")
                .is_some_and(nah_package_spec)
                || word
                    .strip_prefix("-p")
                    .is_some_and(|value| !value.is_empty() && nah_package_spec(value))
                || word.strip_prefix("--bin=") == Some("nah")))
            || ((after_options || !word.starts_with('-')) && nah_package_spec(word))
        {
            return true;
        }
        index += 1;
    }
    false
}

fn cargo_install(words: &[String]) -> Option<(bool, Option<&str>)> {
    let mut index = cargo_subcommand_arguments(words, "install")?;
    let mut source_is_nah = false;
    let mut selected = false;
    let mut selects_nah = false;
    let mut selects_bins = false;
    let mut root = None;
    let mut after_options = false;
    while index < words.len() {
        let word = words[index].as_str();
        if after_options {
            source_is_nah |= nah_package_spec(word);
            index += 1;
            continue;
        }
        if word == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if matches!(word, "--dry-run" | "--list") {
            return None;
        }
        if word == "--bins" {
            selected = true;
            selects_bins = true;
            index += 1;
            continue;
        }
        if word == "--examples" {
            selected = true;
            index += 1;
            continue;
        }
        let (option, attached) = word
            .split_once('=')
            .map_or((word, None), |(option, value)| (option, Some(value)));
        if matches!(option, "--root" | "--path" | "--bin" | "--example") {
            let value = if let Some(value) = attached {
                (!value.is_empty()).then_some(value)?
            } else {
                index += 1;
                words.get(index)?.as_str()
            };
            if option == "--root" {
                root = Some(value);
            } else if option == "--path" {
                source_is_nah |= cargo_nah_path(value);
            } else {
                selected = true;
                selects_nah |= value == "nah";
            }
            index += 1;
            continue;
        }
        if matches!(
            option,
            "--version"
                | "--git"
                | "--branch"
                | "--tag"
                | "--rev"
                | "--registry"
                | "--index"
                | "--target"
                | "--target-dir"
                | "-j"
                | "--jobs"
                | "-F"
                | "--features"
                | "--profile"
                | "--config"
                | "-Z"
                | "--color"
        ) {
            if attached.is_none() {
                index += 1;
                words.get(index)?;
            }
        } else if matches!(
            word,
            "-v" | "--verbose"
                | "-q"
                | "--quiet"
                | "--force"
                | "--no-track"
                | "--locked"
                | "--offline"
                | "--frozen"
                | "--all-features"
                | "--no-default-features"
                | "--ignore-rust-version"
        ) || word.starts_with("-vv")
            || word.starts_with("-j") && word.len() > 2
            || word.starts_with("-F") && word.len() > 2
        {
        } else if word.starts_with('-') {
            return None;
        } else {
            source_is_nah |= nah_package_spec(word);
        }
        index += 1;
    }
    Some((
        selects_nah || source_is_nah && (!selected || selects_bins),
        root,
    ))
}

fn cargo_subcommand_arguments(words: &[String], subcommand: &str) -> Option<usize> {
    if terminal_help(words) {
        return None;
    }
    let mut index = usize::from(words.first().is_some_and(|word| word.starts_with('+')));
    while index < words.len() {
        let word = words[index].as_str();
        if word == subcommand {
            return Some(index + 1);
        }
        if matches!(
            word,
            "-v" | "--verbose" | "-q" | "--quiet" | "--frozen" | "--locked" | "--offline"
        ) || word.starts_with("-vv")
            || word.starts_with("--color=")
            || word.starts_with("--config=")
        {
            index += 1;
        } else if matches!(word, "--color" | "--config" | "-Z") {
            index += 2;
        } else {
            return None;
        }
    }
    None
}

fn cargo_nah_path(value: &str) -> bool {
    matches!(
        value
            .trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next(),
        Some("nah" | "nah-cli")
    )
}

fn nah_package_spec(value: &str) -> bool {
    matches!(
        value.split_once('@').map_or(value, |(name, _)| name),
        "nah" | "nah-cli"
    )
}

pub(crate) fn inspection_operation(program: &str, arguments: &[Word]) -> Option<&'static str> {
    if normalized_program(program) != "nah" {
        return None;
    }
    let words = arguments
        .iter()
        .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    if terminal_help(&words) || words.first().is_some_and(|command| command == "help") {
        return Some("inspect");
    }
    let inspected = match words.as_slice() {
        [flag] if matches!(flag.as_str(), "-h" | "--help" | "-V" | "--version") => true,
        [command] if matches!(command.as_str(), "docs" | "guards") => true,
        [command, argument]
            if command == "docs"
                || command == "guards" && matches!(argument.as_str(), "-h" | "--help") =>
        {
            true
        }
        [command, id] if command == "why" && !id.starts_with('-') => true,
        [command, arguments @ ..] if command == "log" && log_arguments(arguments) => true,
        [command, runtime, action]
            if command == "hook" && runtime_name(runtime) && action == "status" =>
        {
            true
        }
        _ => false,
    };
    inspected.then_some("inspect")
}

fn terminal_help(arguments: &[String]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| matches!(argument.as_str(), "-h" | "--help"))
}

fn normalized_program(program: &str) -> String {
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lowercase = basename.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|suffix| lowercase.strip_suffix(suffix).map(str::to_owned))
        .unwrap_or(lowercase)
}

fn same_lexical_path(left: &str, right: &str, platform: Platform) -> bool {
    lexical_normalized_path(left, platform) == lexical_normalized_path(right, platform)
}

fn lexical_normalized_path(path: &str, platform: Platform) -> String {
    let absolute = path.starts_with(['/', '\\']);
    let mut components = Vec::new();
    for component in path.split(['/', '\\']) {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(if platform == Platform::Windows {
                component.to_ascii_lowercase()
            } else {
                component.to_owned()
            }),
        }
    }
    let normalized = components.join("/");
    if absolute && platform != Platform::Windows {
        format!("/{normalized}")
    } else {
        normalized
    }
}

fn has_projected_path(critical_paths: &[AbsolutePath], suffix: &str, platform: Platform) -> bool {
    let suffix = lexical_normalized_path(suffix, platform);
    critical_paths.iter().any(|path| {
        lexical_normalized_path(path.as_str(), platform).ends_with(&format!("/{suffix}"))
    })
}

fn log_arguments(arguments: &[String]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if matches!(argument, "--json" | "-h" | "--help") {
            index += 1;
            continue;
        }
        let count = if argument == "-n" {
            index += 1;
            arguments.get(index).map(String::as_str)
        } else {
            argument
                .strip_prefix("-n")
                .filter(|count| !count.is_empty())
        };
        if !count.is_some_and(|count| count.bytes().all(|byte| byte.is_ascii_digit())) {
            return false;
        }
        index += 1;
    }
    true
}

fn runtime_name(runtime: &str) -> bool {
    runtime_names().contains(&runtime)
}

fn runtime_names() -> &'static [&'static str] {
    &[
        "amp",
        "antigravity",
        "claude",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "devin",
        "droid",
        "hermes",
        "kiro",
        "openclaw",
        "opencode",
        "pi",
        "prime-agent",
    ]
}

pub(crate) fn protected_path(
    path: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let path = lexical_normalized_path(path, platform);
    let state = lexical_normalized_path(&format!("{home}/.nah"), platform);
    if path == state || path.starts_with(&format!("{state}/")) {
        return true;
    }
    let binary = if platform == Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    let mut installed = vec![
        format!("{home}/.local/bin/{binary}"),
        format!("{home}/.cargo/bin/{binary}"),
    ];
    if platform == Platform::Windows {
        installed.push(format!("{home}/AppData/Local/Programs/nah/{binary}"));
    } else {
        installed.extend(["/usr/local/bin/nah".into(), "/usr/bin/nah".into()]);
    }
    installed
        .iter()
        .any(|candidate| path == lexical_normalized_path(candidate, platform))
        || critical_paths
            .iter()
            .any(|candidate| path == lexical_normalized_path(candidate.as_str(), platform))
}

fn protected_path_ancestor(
    path: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let path = lexical_normalized_path(path, platform);
    let home = lexical_normalized_path(home, platform);
    if path == home {
        return false;
    }
    let ancestor_of = |candidate: &str| {
        let candidate = lexical_normalized_path(candidate, platform);
        path != candidate && contains(&path, &candidate, platform)
    };
    let binary = if platform == Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    let mut owned = vec![
        format!("{home}/.nah"),
        format!("{home}/.local/bin/{binary}"),
        format!("{home}/.cargo/bin/{binary}"),
    ];
    if platform == Platform::Windows {
        owned.push(format!("{home}/AppData/Local/Programs/nah/{binary}"));
    }
    if contains(&home, &path, platform)
        && owned
            .iter()
            .map(String::as_str)
            .chain(critical_paths.iter().map(AbsolutePath::as_str))
            .any(&ancestor_of)
    {
        return true;
    }
    path.split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .count()
        > 1
        && critical_paths
            .iter()
            .map(AbsolutePath::as_str)
            .any(ancestor_of)
}

#[cfg(test)]
mod tests;
