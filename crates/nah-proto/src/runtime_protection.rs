//! Pure runtime protection rules over caller-provided evidence.

use crate::ctx::{AbsolutePath, Platform};
use crate::effects::Knowledge;

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
/// admission remains the language caller's responsibility. A selector the
/// launch sets to a value the caller could not resolve is `Unknown`, and counts
/// as a bypass: nothing shows it still selects the hooked home.
pub fn environment_operation<'a>(
    program: &str,
    value: impl Fn(&str) -> Knowledge<Option<&'a str>>,
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
        _ => false,
    };
    // Whether the selector is set to a value matching `test`, or to one the
    // caller could not resolve.
    let selects = |name: &str, test: &dyn Fn(&str) -> bool| match value(name) {
        Knowledge::Known(value) => value.is_some_and(test),
        Knowledge::Unknown => true,
    };
    let alternate = |name: &str, default: &str| {
        let expected = match (name, active_selector) {
            ("HERMES_HOME", true) => baseline(name).unwrap_or(default),
            _ => default,
        };
        match value(name) {
            Knowledge::Known(configured) => {
                let configured = configured
                    .filter(|value| !value.is_empty())
                    .unwrap_or(default);
                !same_lexical_path(configured, expected, platform)
            }
            Knowledge::Unknown => true,
        }
    };
    // Bun's `os.homedir` returns the account home when `HOME` is empty or
    // unset. OpenCode is a Bun binary, so an empty `HOME` stays that home.
    // An unknown value cannot be shown to stay there.
    let relocated_home = || match value("HOME") {
        Knowledge::Known(configured) => {
            let configured = configured.filter(|value| !value.is_empty()).unwrap_or(home);
            !same_lexical_path(configured, home, platform)
        }
        Knowledge::Unknown => true,
    };
    // Node's `os.homedir` returns a set `HOME` as-is, including the empty
    // string, and a path joined onto that string is relative to the process
    // cwd. An unset `HOME` still falls through to the account home. A value
    // that names that home in another lexical spelling does not move it.
    // Claude's npm install is that Node. Its native binary is Bun, which
    // keeps the account home for an empty `HOME`; an empty value is still a
    // move, because the Node install reads hooks from the cwd.
    let node_home_moved = || match value("HOME") {
        Knowledge::Known(None) => false,
        Knowledge::Known(Some(configured)) => {
            configured.is_empty() || !same_lexical_path(configured, home, platform)
        }
        Knowledge::Unknown => true,
    };
    // A non-empty selector is the location the runtime reads, so `HOME` does
    // not move the hook.
    let pins =
        |name: &str| matches!(value(name), Knowledge::Known(Some(value)) if !value.is_empty());
    let bypass = match program.as_str() {
        // Claude Code reads its user settings, where Nah's hook lives, from
        // this directory instead of `~/.claude`.
        "claude" => {
            alternate("CLAUDE_CONFIG_DIR", &home_path(".claude"))
                || match value("CLAUDE_CONFIG_DIR") {
                    Knowledge::Known(Some(directory)) if !directory.is_empty() => false,
                    _ => node_home_moved(),
                }
        }
        "codex" => alternate("CODEX_HOME", &home_path(".codex")),
        "hermes" => alternate("HERMES_HOME", &home_path(".hermes")),
        "openclaw" => {
            alternate("OPENCLAW_HOME", &home_path(".openclaw"))
                || alternate("OPENCLAW_STATE_DIR", &home_path(".openclaw"))
                || alternate(
                    "OPENCLAW_CONFIG_PATH",
                    &home_path(".openclaw/openclaw.json"),
                )
                || selects("OPENCLAW_PROFILE", &|value| {
                    !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("default")
                })
        }
        "opencode" | "opencode2" => {
            alternate("XDG_CONFIG_HOME", &home_path(".config"))
                || selects("OPENCODE_CONFIG_DIR", &|value| {
                    if value.is_empty() {
                        return false;
                    }
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
                || selects("OPENCODE_CONFIG_CONTENT", &|content| {
                    !content.trim().is_empty() && opencode_plugin_disabled(content, true)
                })
                // xdg-basedir uses `os.homedir()/.config` when `XDG_CONFIG_HOME`
                // is unset. A set value, standard or not, is handled above.
                || (!pins("XDG_CONFIG_HOME") && relocated_home())
        }
        // User hooks are `os.homedir()/.cursor/hooks.json`. Cursor installs the
        // same CLI as `agent` and `cursor-agent`. `XDG_CONFIG_HOME` selects
        // Cursor's config directory and does not move that file. Any other
        // binary that is also named `agent` is classified the same way.
        "agent" | "cursor-agent" => node_home_moved(),
        // `getAgentDir` uses `PI_CODING_AGENT_DIR`, or `os.homedir()/.pi/agent`.
        // The launcher's `XDG_DATA_HOME` only puts node on `PATH`. The
        // launcher runs Node, so an empty `HOME` is the process cwd.
        "pi" => {
            alternate("PI_CODING_AGENT_DIR", &home_path(".pi/agent"))
                || (!pins("PI_CODING_AGENT_DIR") && node_home_moved())
        }
        _ => false,
    };
    bypass.then_some("critical-mutation")
}
/// The Hermes commands known to start no agent session of their own, as the
/// exact words that open them and the only options they may carry. Each reads
/// state or runs an MCP probe or OAuth login; none is a command Hermes'
/// `_prepare_agent_startup` sets up an agent turn for (`_AGENT_COMMANDS`,
/// `_AGENT_SUBCOMMANDS`). Read from `hermes_cli/main.py` and
/// `hermes_cli/subcommands/` of Hermes Agent at fa78e686.
///
/// Accepted limit: every Hermes invocation runs startup recovery before parsing
/// (`main.py:3477`). If an interrupted `hermes update` left a paused-gateway
/// record under that home, even a command listed here restarts that gateway
/// under that `HERMES_HOME`. This exemption does not observe or depend on such
/// a record.
const HERMES_SESSIONLESS_COMMANDS: &[(&[&str], &[&str])] = &[
    (&["config", "check"], &[]),
    (&["config", "env-path"], &[]),
    (&["config", "path"], &[]),
    (&["config", "show"], &[]),
    (&["cron", "list"], &[]),
    (&["doctor"], &[]),
    (&["gateway", "status"], &[]),
    (&["hooks", "list"], &[]),
    (&["logs"], &[]),
    (&["mcp", "catalog"], &[]),
    (&["mcp", "list"], &[]),
    (
        &["mcp", "login"],
        &["--flow", "--flow=browser", "--flow=device"],
    ),
    (&["mcp", "ls"], &[]),
    (&["mcp", "reauth"], &["--all"]),
    (&["mcp", "test"], &[]),
    (&["status"], &["--all", "--deep"]),
];

/// Whether a launch of this program is a Hermes command that starts no agent
/// session of its own, so another `HERMES_HOME` does not by itself put an agent
/// outside Nah's hook. Anything else keeps counting as a session: an unlisted command, or an option before
/// or after the command. Hermes reads some options wherever they stand, and it
/// runs a top-level `-z PROMPT` as an agent turn in place of the subcommand.
pub fn starts_no_session(program: &str, words: &[String]) -> bool {
    normalized_program(program) == "hermes"
        && HERMES_SESSIONLESS_COMMANDS
            .iter()
            .any(|(command, options)| {
                words.len() >= command.len()
                    && words.iter().zip(*command).all(|(word, part)| word == part)
                    && words[command.len()..]
                        .iter()
                        .all(|word| !word.starts_with('-') || options.contains(&word.as_str()))
            })
}

/// Recognizes launch options that bypass hook wiring, excluding terminal information.
pub fn runtime_launch_bypass(program: &str, words: &[String]) -> bool {
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
        // `--disable NAME` is `-c features.NAME=false`; `codex_hooks` is the
        // deprecated alias of the `hooks` feature.
        "codex" => {
            option_values(words, &["--disable"]).any(|name| matches!(name, "hooks" | "codex_hooks"))
                || option_values(words, &["-c", "--config"]).any(disables_codex_hooks)
        }
        "hermes" => has_option("--safe-mode") || has_option("--ignore-user-config"),
        "openclaw" => {
            option_value("--profile").is_some_and(|value| {
                !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("default")
            }) || has_option("--dev")
        }
        "pi" => has_option("--no-extensions"),
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
/// file's content is supplied separately by the engine's configuration read.
pub fn disables_claude_hooks(value: &str) -> bool {
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

/// A settings write or observed settings file that establishes the hook
/// disable. Edit tools can supply only the inserted object members, so accept
/// those members wrapped as an object too. Unrelated text and false stay inert.
pub fn claude_settings_disable_hooks(content: &str) -> bool {
    let disables = |value: serde_json::Value| {
        value.get("disableAllHooks") == Some(&serde_json::Value::Bool(true))
    };
    serde_json::from_str(content).is_ok_and(disables)
        || serde_json::from_str(&format!("{{{content}}}")).is_ok_and(disables)
}

/// User and project settings Claude loads. Project files remain ordinary
/// files unless the write itself establishes that it disables hooks.
pub fn is_claude_settings_path(path: &str, platform: Platform) -> bool {
    let path = fold_path_spelling(&lexically_normalized(path, platform), platform);
    ["/.claude/settings.json", "/.claude/settings.local.json"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
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

/// Whether the bytes a write would store can disable a Nah hook that
/// is not itself one of the protected paths. An OpenCode `opencode.json` or
/// `opencode.jsonc`, or global `.config/opencode/config.json`, whose `plugin`
/// or `plugins` list leaves the `nah` id
/// disabled does. Content with unresolved OpenCode substitutions may also
/// change those directives.
/// Only whole OpenCode documents count as disabling when parsing fails;
/// an inserted fragment need not be a document at all.
pub fn disables_hook_configuration(path: &str, content: &str, whole_document: bool) -> bool {
    disables_opencode_plugin(path, content, whole_document)
}

fn disables_opencode_plugin(path: &str, content: &str, whole_document: bool) -> bool {
    let Some(name) = path_file_name(path) else {
        return false;
    };
    if name != "opencode.json"
        && name != "opencode.jsonc"
        && !path
            .replace('\\', "/")
            .ends_with("/.config/opencode/config.json")
    {
        return false;
    }
    opencode_plugin_disabled(content, whole_document)
}

/// A file and an inline config use the same plugin directives and ordering.
fn opencode_plugin_disabled(content: &str, whole_document: bool) -> bool {
    // OpenCode substitutes environment and file references before parsing,
    // including in keys and whole virtual documents. Their expansion is not
    // established by these bytes, so a literal plugin list cannot bound it.
    if content.contains("{env:") || content.contains("{file:") {
        return true;
    }
    let Some(document) = parse_config_document(content) else {
        // OpenCode may accept documents that our parser cannot represent.
        // Failure to parse cannot establish that the Nah plugin stays on.
        return whole_document;
    };
    let Some(object) = document.as_object() else {
        return false;
    };
    // Either key is enough. `plugins` is the current one and `plugin` is the
    // deprecated one the disable entries still use. A later `nah` or `*` in
    // the same list turns the id back on.
    ["plugin", "plugins"].iter().any(|key| {
        object
            .get(*key)
            .and_then(nah_plugin_disabled)
            .unwrap_or(false)
    })
}

/// OpenCode walks the list in order. `-nah` and `-*` disable the plugin; a
/// later `nah` or `*` enables it again. An entry without a readable plugin id
/// leaves the result unknown.
fn nah_plugin_disabled(entries: &serde_json::Value) -> Option<bool> {
    let entries = entries.as_array()?;
    let mut disabled = false;
    for entry in entries {
        match plugin_directive(entry)? {
            "-nah" | "-*" => disabled = true,
            "nah" | "*" => disabled = false,
            _ => {}
        }
    }
    Some(disabled)
}

fn plugin_directive(entry: &serde_json::Value) -> Option<&str> {
    if let Some(text) = entry.as_str() {
        return Some(text.trim());
    }
    // The deprecated `plugin` schema also allows `[id, options]`.
    entry
        .as_array()
        .and_then(|pair| pair.first())
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
}

fn path_file_name(path: &str) -> Option<&str> {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
}

fn parse_config_document(content: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&strip_jsonc(content)?).ok()
}

/// OpenCode loads JSONC. Remove comments before trailing commas so a
/// comment between a comma and a closing bracket cannot hide the bracket.
/// Both passes leave string contents unchanged.
fn strip_jsonc(input: &str) -> Option<String> {
    let mut text = input.to_string();
    for remove_comments in [true, false] {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        let mut in_string = false;
        let mut escaped = false;
        while index < chars.len() {
            let current = chars[index];
            if in_string {
                out.push(current);
                if escaped {
                    escaped = false;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '"' {
                    in_string = false;
                }
                index += 1;
                continue;
            }
            match current {
                '"' => {
                    in_string = true;
                    out.push(current);
                    index += 1;
                }
                '/' if remove_comments && chars.get(index + 1) == Some(&'/') => {
                    out.push(' ');
                    index += 2;
                    while index < chars.len() && !matches!(chars[index], '\n' | '\r') {
                        index += 1;
                    }
                }
                '/' if remove_comments && chars.get(index + 1) == Some(&'*') => {
                    out.push(' ');
                    index += 2;
                    while index + 1 < chars.len()
                        && !(chars[index] == '*' && chars[index + 1] == '/')
                    {
                        index += 1;
                    }
                    if index + 1 >= chars.len() {
                        return None;
                    }
                    index += 2;
                }
                ',' if !remove_comments => {
                    let mut ahead = index + 1;
                    while ahead < chars.len() && matches!(chars[ahead], ' ' | '\t' | '\n' | '\r') {
                        ahead += 1;
                    }
                    if ahead < chars.len() && matches!(chars[ahead], '}' | ']') {
                        index += 1;
                        continue;
                    }
                    out.push(current);
                    index += 1;
                }
                _ => {
                    out.push(current);
                    index += 1;
                }
            }
        }
        text = out;
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(
        pairs: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&str) -> Knowledge<Option<&'a str>> + 'a {
        move |name| {
            Knowledge::Known(
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| *value),
            )
        }
    }

    fn launch(program: &str, pairs: &[(&str, &str)]) -> Option<&'static str> {
        environment_operation(
            program,
            env(pairs),
            |_| None,
            "/home/test",
            Some("/work"),
            &[],
            Platform::Linux,
        )
    }

    #[test]
    fn home_moves_only_the_runtimes_whose_hook_path_follows_it() {
        assert_eq!(
            launch("cursor-agent", &[("HOME", "/tmp/elsewhere")]),
            Some("critical-mutation")
        );
        assert_eq!(launch("cursor-agent", &[("HOME", "/home/test")]), None);
        assert_eq!(launch("cursor-agent", &[("HOME", "/home/test/")]), None);
        assert_eq!(
            launch("cursor-agent", &[("HOME", "")]),
            Some("critical-mutation")
        );
        assert_eq!(launch("cursor-agent", &[]), None);
        assert_eq!(
            launch("agent", &[("HOME", "/tmp/elsewhere")]),
            Some("critical-mutation")
        );
        assert_eq!(launch("agent", &[("HOME", "/home/test")]), None);
        assert_eq!(launch("agent", &[("HOME", "/home/test/")]), None);
        assert_eq!(launch("agent", &[("HOME", "")]), Some("critical-mutation"));
        assert_eq!(launch("agent", &[]), None);
        assert_eq!(launch("claude", &[("HOME", "")]), Some("critical-mutation"));
        assert_eq!(
            launch("claude", &[("HOME", "/tmp/elsewhere")]),
            Some("critical-mutation")
        );
        assert_eq!(launch("claude", &[("HOME", "/home/test")]), None);
        assert_eq!(launch("claude", &[("HOME", "/home/test/")]), None);
        assert_eq!(launch("claude", &[]), None);
        assert_eq!(
            launch(
                "claude",
                &[("HOME", ""), ("CLAUDE_CONFIG_DIR", "/home/test/.claude")]
            ),
            None
        );
        assert_eq!(
            launch("cursor-agent", &[("XDG_CONFIG_HOME", "/tmp/cursor-config")]),
            None
        );

        assert_eq!(
            launch("opencode", &[("HOME", "/tmp/elsewhere")]),
            Some("critical-mutation")
        );
        assert_eq!(
            launch(
                "opencode",
                &[
                    ("HOME", "/tmp/elsewhere"),
                    ("XDG_CONFIG_HOME", "/home/test/.config")
                ]
            ),
            None
        );
        assert_eq!(
            launch("pi", &[("HOME", "/tmp/elsewhere")]),
            Some("critical-mutation")
        );
        assert_eq!(
            launch(
                "pi",
                &[
                    ("HOME", "/tmp/elsewhere"),
                    ("PI_CODING_AGENT_DIR", "/home/test/.pi/agent")
                ]
            ),
            None
        );
        // OpenCode is Bun: an empty HOME stays the account home. pi is Node:
        // an empty HOME is the process cwd.
        assert_eq!(launch("opencode", &[("HOME", "")]), None);
        for content in ["", " ", " \t\r\n"] {
            assert_eq!(
                launch("opencode", &[("OPENCODE_CONFIG_CONTENT", content)]),
                None
            );
        }
        assert_eq!(launch("pi", &[("HOME", "")]), Some("critical-mutation"));

        // HOME does not relocate the hook of Codex or agy.
        assert_eq!(launch("codex", &[("HOME", "/tmp/elsewhere")]), None);
        assert_eq!(launch("agy", &[("HOME", "/tmp/elsewhere")]), None);
    }

    #[test]
    fn known_hook_disabling_documents_are_recognized() {
        for fragment in [
            r#""model": "b""#,
            r#""theme": "dark", "model": "a""#,
            r#""plugin": ["-nah"]"#,
            r#"{"$schema":"\ud800","plugin":["-nah"]}"#,
            "",
        ] {
            assert!(!disables_hook_configuration(
                "/home/test/.config/opencode/config.json",
                fragment,
                false,
            ));
        }
        assert!(disables_hook_configuration(
            "/home/test/.config/opencode/config.json",
            r#"{"plugin":["-nah"]}"#,
            false,
        ));
        for content in [
            r#"{"plugins":["-nah",/**/]}"#,
            r#"{"plugin":["-nah",/**/]}"#,
            r#"{"plugins":["-nah"],/**/}"#,
            "{\"plugin\":[\"-nah\",\n// keep\n]}",
            "{\"plugins\":[\"-nah\",// keep\r]}",
            r#"{"plugin":[["-nah",{"url":"https://host/*,]*/"}],/**/]}"#,
            r#"{"$schema":"\ud800","plugin":["-nah"]}"#,
            r#"{"$schema":"\udc00","plugins":["other"]}"#,
            r#"{"provider":{"p":{"options":{"x":1e400}}},"plugins":["-nah"]}"#,
            r#"{"plugins":["-nah"]}/*"#,
            "not JSONC",
        ] {
            assert!(
                disables_hook_configuration("/workspace/project/opencode.jsonc", content, true),
                "{content}"
            );
        }
        for content in [
            r#"{"plugins":["other",/**/]}"#,
            r#"{"plugins":["-nah","nah",/**/]}"#,
            r#"{"plugins":["-nah,/**/]"]}"#,
            r#"{"$schema":"\ud83d\ude00","plugins":["other"]}"#,
            r#"{"provider":{"p":{"options":{"x":1e300}}},"plugins":["other"]}"#,
        ] {
            assert!(
                !disables_hook_configuration("/workspace/project/opencode.jsonc", content, true),
                "{content}"
            );
        }
        for (depth, expected) in [(100, false), (130, true)] {
            let content = format!(
                "{{\"provider\":{{\"p\":{{\"options\":{{\"x\":{}0{}}}}}}},\"plugins\":[\"other\"]}}",
                "[".repeat(depth),
                "]".repeat(depth)
            );
            assert_eq!(
                disables_hook_configuration("/workspace/project/opencode.jsonc", &content, true),
                expected
            );
        }
        assert!(disables_hook_configuration(
            "/workspace/project/opencode.json",
            "{\"plugin\":[\"-nah\"]}\n",
            true
        ));
        assert!(disables_hook_configuration(
            "/workspace/project/opencode.jsonc",
            "{ /* drop */ \"plugin\": [\"-*\"], }\n",
            true
        ));
        assert!(disables_hook_configuration(
            "/workspace/project/opencode.json",
            "{\"plugins\":[\"-nah\",\"other\"]}\n",
            true
        ));
        assert!(!disables_hook_configuration(
            "/workspace/project/opencode.json",
            "{\"plugin\":[\"-*\",\"nah\"]}\n",
            true
        ));
        assert!(!disables_hook_configuration(
            "/workspace/project/opencode.json",
            "{\"plugin\":[\"other\"]}\n",
            true
        ));
        assert!(!disables_hook_configuration(
            "/workspace/project/opencode.json",
            "{\"model\":\"anthropic/claude-sonnet\"}\n",
            true
        ));
        assert!(!disables_hook_configuration(
            "/workspace/project/notes.txt",
            "{\"plugin\":[\"-nah\"]}\n",
            true
        ));
    }
}
