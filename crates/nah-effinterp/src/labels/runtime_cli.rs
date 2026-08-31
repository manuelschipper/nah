// UNDOCUMENTED-EFFINTERP: pure runtime-CLI recognition over literal argv.

use nah_proto::ctx::{AbsolutePath, Platform};

/// An agent-runtime CLI nah installs a hook into, plus nah itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCli {
    Nah,
    Amp,
    Antigravity,
    Claude,
    Cline,
    Codex,
    Copilot,
    Cursor,
    Devin,
    Droid,
    Hermes,
    Kiro,
    Openclaw,
    Opencode,
    Pi,
    PrimeAgent,
}

impl RuntimeCli {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nah => "nah",
            Self::Amp => "amp",
            Self::Antigravity => "antigravity",
            Self::Claude => "claude",
            Self::Cline => "cline",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
            Self::Devin => "devin",
            Self::Droid => "droid",
            Self::Hermes => "hermes",
            Self::Kiro => "kiro",
            Self::Openclaw => "openclaw",
            Self::Opencode => "opencode",
            Self::Pi => "pi",
            Self::PrimeAgent => "prime-agent",
        }
    }
}

/// Recognizes an agent-runtime CLI invocation that reaches nah's wiring: a nah
/// state mutation, a runtime plugin mutation, or a launch that bypasses hooks.
/// Ordinary invocations of the same programs return `None`.
pub fn classify(
    executable: &str,
    argv: &[String],
    home: &AbsolutePath,
    platform: Platform,
) -> Option<RuntimeCli> {
    let program = normalized_program(executable);
    if program == "nah" {
        return nah_mutation(argv).then_some(RuntimeCli::Nah);
    }
    let runtime = runtime(&program)?;
    if terminal_information(argv) {
        return None;
    }
    let protects_nah_wiring = runtime_mutation(&program, argv)
        || runtime_launch_bypass(&program, argv, home.as_str(), platform);
    protects_nah_wiring.then_some(runtime)
}

fn nah_mutation(words: &[String]) -> bool {
    if terminal_information(words) {
        return false;
    }
    match words {
        [command, ..] if matches!(command.as_str(), "nap" | "tui" | "trust" | "untrust") => true,
        [kind, command, ..]
            if kind == "guard" && matches!(command.as_str(), "enable" | "disable") =>
        {
            true
        }
        [kind, ..] if kind == "effinterp" => true,
        [kind, runtime_name, action, ..]
            if kind == "hook"
                && runtime(runtime_name).is_some()
                && matches!(action.as_str(), "install" | "uninstall") =>
        {
            true
        }
        _ => false,
    }
}

fn runtime(program: &str) -> Option<RuntimeCli> {
    Some(match program {
        "amp" => RuntimeCli::Amp,
        "agy" | "antigravity" => RuntimeCli::Antigravity,
        "claude" => RuntimeCli::Claude,
        "cline" => RuntimeCli::Cline,
        "codex" => RuntimeCli::Codex,
        "copilot" => RuntimeCli::Copilot,
        "cursor" => RuntimeCli::Cursor,
        "devin" => RuntimeCli::Devin,
        "droid" => RuntimeCli::Droid,
        "hermes" => RuntimeCli::Hermes,
        "kiro" | "kiro-cli" => RuntimeCli::Kiro,
        "openclaw" => RuntimeCli::Openclaw,
        "opencode" => RuntimeCli::Opencode,
        "pi" => RuntimeCli::Pi,
        "prime-agent" => RuntimeCli::PrimeAgent,
        _ => return None,
    })
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

fn runtime_launch_bypass(program: &str, words: &[String], home: &str, platform: Platform) -> bool {
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
    match program {
        "claude" => has_option("--safe-mode") || has_option("--bare"),
        "cline" => option_value("--config").is_some_and(|value| {
            !value.is_empty() && !same_path(value, &format!("{home}/.cline"), platform)
        }),
        "codex" => {
            words
                .windows(2)
                .any(|parts| parts == ["--disable", "hooks"])
                || has_option("--disable=hooks")
        }
        "devin" => option_value("--config").is_some_and(|value| {
            let relative = if platform == Platform::Windows {
                "AppData/Roaming/devin/config.json"
            } else {
                ".config/devin/config.json"
            };
            !value.is_empty() && !same_path(value, &format!("{home}/{relative}"), platform)
        }),
        "droid" => option_value("--settings").is_some_and(|value| {
            !value.is_empty()
                && !same_path(value, &format!("{home}/.factory/settings.json"), platform)
        }),
        "hermes" => has_option("--safe-mode") || has_option("--ignore-user-config"),
        "openclaw" => {
            option_value("--profile").is_some_and(|value| {
                !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("default")
            }) || has_option("--dev")
        }
        "opencode" => has_option("--pure"),
        "pi" | "prime-agent" => has_option("--no-extensions"),
        _ => false,
    }
}

fn terminal_information(words: &[String]) -> bool {
    words
        .iter()
        .take_while(|word| word.as_str() != "--")
        .any(|word| matches!(word.as_str(), "-h" | "--help" | "-V" | "--version"))
}

fn normalized_program(program: &str) -> String {
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lowercase = basename.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|suffix| lowercase.strip_suffix(suffix).map(str::to_owned))
        .unwrap_or(lowercase)
}

fn same_path(left: &str, right: &str, platform: Platform) -> bool {
    let normalize = |path: &str| {
        let path = path.replace('\\', "/");
        if platform == Platform::Windows {
            path.to_ascii_lowercase()
        } else {
            path
        }
    };
    normalize(left).trim_end_matches('/') == normalize(right).trim_end_matches('/')
}
