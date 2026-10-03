//! Pure runtime protection rules over caller-provided evidence.

use crate::ctx::{AbsolutePath, Platform};

use crate::labels::lexical_path::{fold_path_spelling, lexically_normalized, same_path};
use crate::labels::normalized_program;

/// The runtime's own protected absolute paths, sorted and deduplicated, so a
/// producer can recognize a critical mutation of the hook wiring it runs under,
/// and the paths of the nah executable deciding the call, so a producer can
/// recognize a process that is nah wherever it is installed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelfProtectionProjection {
    protected_paths: Vec<AbsolutePath>,
    installed_executables: Vec<AbsolutePath>,
}

impl SelfProtectionProjection {
    pub fn new(mut protected_paths: Vec<AbsolutePath>) -> Self {
        protected_paths.sort();
        protected_paths.dedup();
        Self {
            protected_paths,
            installed_executables: Vec::new(),
        }
    }

    pub fn with_installed_executables(mut self, mut executables: Vec<AbsolutePath>) -> Self {
        executables.sort();
        executables.dedup();
        self.installed_executables = executables;
        self
    }

    pub fn protected_paths(&self) -> &[AbsolutePath] {
        &self.protected_paths
    }

    pub fn installed_executables(&self) -> &[AbsolutePath] {
        &self.installed_executables
    }
}

/// Classifies environment hook bypass after the caller admits the command.
/// Lookups provide visible values and the runtime baseline; terminal help/version
/// admission remains the language caller's responsibility.
pub fn environment_operation<'a>(
    program: &str,
    value: impl Fn(&str) -> Option<&'a str>,
    baseline: impl Fn(&str) -> Option<&'a str>,
    home: &str,
    cwd: Option<&str>,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> Option<&'static str> {
    let home_path = |suffix: &str| format!("{home}/{suffix}");
    let program = normalized_program(program);
    let active_selector = match program.as_str() {
        "hermes" => has_projected_path(critical_paths, "config.yaml", platform),
        "kiro-cli" => has_projected_path(critical_paths, "hooks/nah.json", platform),
        "prime-agent" => has_projected_path(critical_paths, "extensions/nah.js", platform),
        _ => false,
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
        // Claude Code reads its user settings, where Nah's hook lives, from
        // this directory instead of `~/.claude`.
        "claude" => alternate("CLAUDE_CONFIG_DIR", &home_path(".claude")),
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
        "opencode" | "opencode2" => {
            alternate("XDG_CONFIG_HOME", &home_path(".config"))
                || value("OPENCODE_CONFIG_DIR")
                    .filter(|value| !value.is_empty())
                    .is_some_and(|value| {
                        // OpenCode resolves a relative directory against its own
                        // cwd. Without that cwd, or through a `..` that a symlink
                        // could redirect, the selector stays unresolved.
                        let selected = match cwd {
                            Some(cwd)
                                if AbsolutePath::new(platform, value).is_err()
                                    && !value.split(['/', '\\']).any(|part| part == "..") =>
                            {
                                format!("{cwd}/{value}")
                            }
                            _ => value.to_owned(),
                        };
                        !same_lexical_path(&selected, &home_path(".config/opencode"), platform)
                    })
                || value("OPENCODE_CONFIG_CONTENT").is_some_and(edits_opencode_plugins)
        }
        "pi" => alternate("PI_CODING_AGENT_DIR", &home_path(".pi/agent")),
        "prime-agent" => alternate("PRIME_AGENT_CODING_AGENT_DIR", &home_path(".prime/agent")),
        _ => false,
    };
    bypass.then_some("critical-mutation")
}
/// Recognizes launch options that bypass hook wiring, excluding terminal information.
pub fn runtime_launch_bypass(
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
        "claude" => {
            has_option("--safe-mode")
                || has_option("--bare")
                || option_values(words, &["--settings"]).any(disables_claude_hooks)
                // Nah's hook is in the user settings; a source list without
                // `user` does not load them.
                || option_values(words, &["--setting-sources"])
                    .any(|sources| !sources.split(',').any(|source| source.trim() == "user"))
        }
        "cline" => alternate_option(option_value("--config"), home, platform, ".cline"),
        // `--disable NAME` is `-c features.NAME=false`; `codex_hooks` is the
        // deprecated alias of the `hooks` feature.
        "codex" => {
            option_values(words, &["--disable"]).any(|name| matches!(name, "hooks" | "codex_hooks"))
                || option_values(words, &["-c", "--config"]).any(disables_codex_hooks)
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
        "pi" => has_option("--no-extensions"),
        "prime-agent" => has_option("--no-extensions"),
        _ => false,
    }
}

/// Every value given to one of `options`, as a separate word, after `=`, or,
/// for a short option, attached (`-cKEY=VALUE`, `-c=KEY=VALUE`).
fn option_values<'a>(
    words: &'a [String],
    options: &'a [&'a str],
) -> impl Iterator<Item = &'a str> + 'a {
    words.iter().enumerate().filter_map(move |(index, word)| {
        options.iter().find_map(|option| {
            if word == option {
                return words.get(index + 1).map(String::as_str);
            }
            let rest = word.strip_prefix(option)?;
            match rest.strip_prefix('=') {
                Some(value) => Some(value),
                None if !option.starts_with("--") && !rest.is_empty() => Some(rest),
                None => None,
            }
        })
    })
}

/// Whether a Claude Code `--settings` value is inline JSON that may set
/// `disableAllHooks`, which command-line settings apply over the user settings
/// holding Nah's hook. Any mention of the key, or a `\u` escape that could
/// spell it, counts, except a top-level `"disableAllHooks": false` in a JSON
/// object that parses and spells the key exactly once: with that entry
/// removed, the object is re-serialized, decoding escapes, and must not
/// mention the key anywhere, since a nested mention such as `__proto__` may
/// still reach the merged settings. A duplicate key, which the parsed map
/// collapses to its last value, and an escaped spelling keep counting. A settings
/// file's content is not visible here, and settings merge rather than replace,
/// so a file path does not count.
fn disables_claude_hooks(value: &str) -> bool {
    if !value.trim_start().starts_with('{') {
        return false;
    }
    match serde_json::from_str::<serde_json::Value>(value) {
        Ok(serde_json::Value::Object(mut settings)) => {
            if value.matches("disableAllHooks").count() == 1
                && settings.get("disableAllHooks") == Some(&serde_json::Value::Bool(false))
            {
                settings.remove("disableAllHooks");
            }
            serde_json::Value::Object(settings)
                .to_string()
                .contains("disableAllHooks")
        }
        _ => value.contains("disableAllHooks") || value.contains("\\u"),
    }
}

/// Whether a Codex `-c KEY=VALUE` override may turn the hooks feature off:
/// `features.hooks` or `features.codex_hooks` set to anything but `true`, or
/// any TOML table value that mentions hooks or has a `\u` escape that could
/// spell it, since a parent table (`profiles.work={features={...}}`) can hold
/// the feature. A flat `features={...}` table of bare boolean keys is read
/// exactly instead, so `features={hooks=true}` keeps the feature on. Codex
/// splits the key on dots, and quoting a segment is read as naming it too.
fn disables_codex_hooks(assignment: &str) -> bool {
    let Some((key, value)) = assignment.split_once('=') else {
        return false;
    };
    let segments: Vec<_> = key
        .split('.')
        .map(|segment| segment.trim().trim_matches(['"', '\'']))
        .collect();
    if let [.., "features"] = segments.as_slice()
        && let Some(entries) = flat_boolean_table(value)
    {
        return entries
            .iter()
            .any(|(name, on)| matches!(*name, "hooks" | "codex_hooks") && !on);
    }
    match segments.as_slice() {
        [.., "features", "hooks" | "codex_hooks"] => value.trim() != "true",
        _ => {
            value.trim_start().starts_with('{')
                && (value.contains("hooks") || value.contains("\\u"))
        }
    }
}

/// The entries of a TOML inline table whose keys are all bare and whose values
/// are all `true` or `false`; `None` for any other value.
fn flat_boolean_table(value: &str) -> Option<Vec<(&str, bool)>> {
    let body = value.trim().strip_prefix('{')?.strip_suffix('}')?;
    if body.trim().is_empty() {
        return Some(Vec::new());
    }
    body.split(',')
        .map(|entry| {
            let (name, on) = entry.split_once('=')?;
            let name = name.trim();
            let bare = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
            let on = match on.trim() {
                "true" => true,
                "false" => false,
                _ => return None,
            };
            bare.then_some((name, on))
        })
        .collect()
}

/// Whether inline OpenCode 2.x config may edit its `plugins` list, where a
/// `-nah` or `-*` entry disables Nah's plugin and a later entry can re-enable
/// it. Quoting, JSON escapes and JSONC make reading the list itself unreliable,
/// so any mention of the key, or a `\u` escape that could spell it, counts.
fn edits_opencode_plugins(content: &str) -> bool {
    content.contains("plugins") || content.contains("\\u")
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

fn terminal_information(words: &[String]) -> bool {
    words
        .iter()
        .take_while(|word| word.as_str() != "--")
        .any(|word| matches!(word.as_str(), "-h" | "--help" | "-V" | "--version"))
}

/// Whether two runtime selector paths name the same directory.
fn same_lexical_path(left: &str, right: &str, platform: Platform) -> bool {
    same_path(
        &lexically_normalized(left, platform),
        &lexically_normalized(right, platform),
        platform,
    )
}

fn has_projected_path(critical_paths: &[AbsolutePath], suffix: &str, platform: Platform) -> bool {
    let suffix = fold_path_spelling(suffix, platform);
    critical_paths.iter().any(|path| {
        fold_path_spelling(&lexically_normalized(path.as_str(), platform), platform)
            .ends_with(&format!("/{suffix}"))
    })
}
