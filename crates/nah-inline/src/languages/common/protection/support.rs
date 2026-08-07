use nah_proto::ctx::{AbsolutePath, Platform};

use crate::EnvironmentValue;
use crate::normalized_program;

pub(super) struct EnvironmentVariables<'a> {
    pub(super) visible: &'a [(String, EnvironmentValue)],
    pub(super) runtime: &'a [(String, EnvironmentValue)],
}

pub(in crate::languages) fn is_perl_interpreter(program: &str) -> bool {
    if program == "perl" {
        return true;
    }
    program.strip_prefix("perl5.").is_some_and(|version| {
        let version = version.split('-').next().unwrap_or(version);
        !version.is_empty()
            && version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

pub(super) fn environment_operation(
    program: &str,
    _words: &[String],
    assignments: &[(String, Option<String>)],
    variables: EnvironmentVariables<'_>,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
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

pub(super) fn runtime_launch_bypass(
    program: &str,
    words: &[String],
    home: Option<&str>,
    platform: Option<Platform>,
) -> bool {
    if terminal_information(words) {
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
        "cline" => alternate_option(option_value("--config"), home, platform, ".cline"),
        "codex" => {
            words
                .windows(2)
                .any(|parts| parts[0] == "--disable" && parts[1] == "hooks")
                || has_option("--disable=hooks")
        }
        "devin" => alternate_option(
            option_value("--config"),
            home,
            platform,
            if platform == Some(Platform::Windows) {
                "AppData/Roaming/devin/config.json"
            } else {
                ".config/devin/config.json"
            },
        ),
        "droid" => alternate_option(
            option_value("--settings"),
            home,
            platform,
            ".factory/settings.json",
        ),
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

fn alternate_option(
    value: Option<&str>,
    home: Option<&str>,
    platform: Option<Platform>,
    relative: &str,
) -> bool {
    value.is_some_and(|value| {
        !value.is_empty()
            && !home.zip(platform).is_some_and(|(home, platform)| {
                same_lexical_path(value, &format!("{home}/{relative}"), platform)
            })
    })
}

pub(super) fn runtime_launch_program(program: &str) -> bool {
    matches!(
        normalized_program(program).as_str(),
        "claude"
            | "codex"
            | "devin"
            | "droid"
            | "hermes"
            | "openclaw"
            | "opencode"
            | "pi"
            | "prime-agent"
    )
}

fn terminal_information(words: &[String]) -> bool {
    words
        .iter()
        .take_while(|word| word.as_str() != "--")
        .any(|word| matches!(word.as_str(), "-h" | "--help" | "-V" | "--version"))
}

pub(in crate::languages) fn runtime_name(runtime: &str) -> bool {
    [
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
    .contains(&runtime)
}

pub(super) fn protected_path(
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
    if platform != Platform::Windows {
        installed.extend(["/usr/local/bin/nah".into(), "/usr/bin/nah".into()]);
    }
    installed
        .iter()
        .any(|candidate| path == lexical_normalized_path(candidate, platform))
        || critical_paths
            .iter()
            .any(|candidate| path == lexical_normalized_path(candidate.as_str(), platform))
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
