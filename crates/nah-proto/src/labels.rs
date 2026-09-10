//! Nah-owned labels applied to interpreted effects.

use serde::{Deserialize, Serialize};

use crate::ctx::{AbsolutePath, Platform};
use crate::runtime::HOOK_RUNTIME_NAMES;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PathScope {
    Project { root: AbsolutePath },
    Home,
    System,
    OutsideProject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    None,
    EnvironmentSecret,
    CredentialSecret,
    OtherSensitive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NahProtectionTier {
    Critical,
    Permanent,
    Proposal,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostIntegrityClass {
    ShellProfile,
    StartupPersistence,
    AuthIdentity,
}

/// Classifies exact Nah/runtime argv; arguments exclude argv[0]. No shell decoding occurs here.
pub fn invocation_protection_tier(
    program: &str,
    words: &[String],
    runtime: Option<(&str, Platform)>,
) -> Option<NahProtectionTier> {
    let program = normalized_program(program);
    if program == "cargo" {
        return cargo_uninstalls_nah(words).then_some(NahProtectionTier::Critical);
    }
    if runtime_terminal_information(words) {
        return None;
    }
    if runtime_mutation(&program, words)
        || crate::runtime_protection::runtime_launch_bypass(
            &program,
            words,
            runtime.map(|(home, _)| home),
            runtime.map(|(_, platform)| platform),
        )
    {
        return Some(NahProtectionTier::Critical);
    }
    if program != "nah" {
        return None;
    }
    if terminal_help(words) {
        return None;
    }
    match words {
        [command, ..] if command == "nap" => Some(NahProtectionTier::Permanent),
        [command, ..] if matches!(command.as_str(), "tui" | "effinterp") => {
            Some(NahProtectionTier::Critical)
        }
        [command, ..] if matches!(command.as_str(), "trust" | "untrust") => {
            Some(NahProtectionTier::Critical)
        }
        [kind, command, ..]
            if kind == "guard" && matches!(command.as_str(), "enable" | "disable" | "reset") =>
        {
            Some(NahProtectionTier::Critical)
        }
        [kind, runtime, action, ..]
            if kind == "hook"
                && HOOK_RUNTIME_NAMES.contains(&runtime.as_str())
                && matches!(action.as_str(), "install" | "uninstall") =>
        {
            Some(NahProtectionTier::Critical)
        }
        _ => None,
    }
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

pub fn runtime_terminal_information(words: &[String]) -> bool {
    words
        .iter()
        .take_while(|word| word.as_str() != "--")
        .any(|word| matches!(word.as_str(), "-h" | "--help" | "-V" | "--version"))
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

pub fn cargo_subcommand_arguments(words: &[String], subcommand: &str) -> Option<usize> {
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

pub fn nah_package_spec(value: &str) -> bool {
    matches!(
        value.split_once('@').map_or(value, |(name, _)| name),
        "nah" | "nah-cli"
    )
}

pub fn terminal_help(arguments: &[String]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| matches!(argument.as_str(), "-h" | "--help"))
}

/// Normalizes lexical CLI identity without resolving an executable on any host.
pub fn normalized_program(program: &str) -> String {
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lowercase = basename.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|suffix| lowercase.strip_suffix(suffix).map(str::to_owned))
        .unwrap_or(lowercase)
}
