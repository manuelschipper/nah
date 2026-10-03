//! Git configuration the git model reads: repository, included and inherited
//! config files, `-c` and `GIT_CONFIG_*` parameters, remote settings, and the
//! aliases they define.

use super::*;

/// One setting the invocation may read.
pub(super) struct ConfigEntry {
    /// The key, empty when the model cannot read it: such a setting may be
    /// any key, and its value is unknown.
    pub(super) key: String,
    /// The value, `None` when the model cannot read it.
    pub(super) value: Option<String>,
    /// The setting certainly reaches this invocation, replacing what lower
    /// entries leave: the environment's settings and -c. An earlier
    /// `git config` write only adds a possible value.
    pub(super) replaces: bool,
    /// An include whose file the model could not read: it may set any key
    /// to any value, which the model does not take as a possible value of
    /// its own.
    pub(super) unobserved: bool,
}

/// What an invocation's configuration may hold for one key.
pub(super) struct ConfigValues<'a> {
    /// Each value some execution may leave; `None` for one the model cannot
    /// read.
    pub(super) values: Vec<Option<&'a str>>,
    /// The key may still hold whatever the unobserved configuration files
    /// hold, which the model takes as unset.
    pub(super) unset: bool,
    /// An include the model could not read may set the key after `values`.
    pub(super) unknown: bool,
}

impl<'a> ConfigValues<'a> {
    /// The one value every execution leaves, when there is one.
    pub(super) fn certain(&self) -> Option<Option<&'a str>> {
        match self.values.as_slice() {
            [first, rest @ ..] if !self.unset && rest.iter().all(|value| value == first) => {
                Some(*first)
            }
            _ => None,
        }
    }
}

pub(super) struct Alias {
    pub(super) name: String,
    pub(super) expansion: String,
    pub(super) value_index: Option<u32>,
    pub(super) source_node: Option<ProvenanceRef>,
}

/// An alias may name another alias; git stops at a bounded chain and so does
/// this walk.
pub(super) const GIT_ALIAS_DEPTH: usize = 4;

/// Git's split_cmdline removes quotes and escapes without shell expansion.
/// Even shell metacharacters are ordinary argument bytes in a non-shell alias.
pub(super) fn split_alias(expansion: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = None;
    let mut chars = expansion.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted.is_none() && c.is_ascii_whitespace() {
            words.push(std::mem::take(&mut word));
            while chars.peek().is_some_and(char::is_ascii_whitespace) {
                chars.next();
            }
        } else if quoted.is_none() && matches!(c, '\'' | '"') {
            quoted = Some(c);
        } else if quoted == Some(c) {
            quoted = None;
        } else if c == '\\' && quoted != Some('\'') {
            word.push(chars.next()?);
        } else {
            word.push(c);
        }
    }
    if quoted.is_some() {
        return None;
    }
    words.push(word);
    Some(words)
}

/// Recover repository aliases only from observed config bytes. Includes and
/// per-worktree config need their own effective-config observation.
pub(super) fn repository_aliases(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    globals: &Globals,
    model_node: ProvenanceRef,
    sub_index: u32,
) -> Result<Option<Vec<Alias>>, &'static str> {
    use crate::nest::SourceSearchObservation;
    use crate::{SourceNamespace, SourcePurpose};

    if !builder.is_host_realm() {
        return Err("repository alias config namespace is not observed");
    }
    if [
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_COMMON_DIR",
        "GIT_CEILING_DIRECTORIES",
    ]
    .iter()
    .any(|name| ctx.environment_value(name).is_some())
    {
        return Err("effective alias configuration has unobserved environment overrides");
    }
    let prefix = &ctx.argv[..sub_index as usize];
    if prefix
        .iter()
        .any(|word| word.as_literal() == Some("--bare"))
        || prefix
            .iter()
            .filter(|word| word.as_literal() == Some("-C"))
            .count()
            > 1
    {
        return Err("bare or chained-directory alias config discovery is not resolved");
    }
    let base = worktree_base(globals, ctx);
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: cwd },
    } = &base
    else {
        return Err("repository config location is unknown");
    };
    if !crate::paths::is_absolute(cwd) {
        return Err("repository config location is unknown");
    }
    let explicit_dir = globals
        .git_dir
        .as_ref()
        .map(|dir| resolve_fs_word_with_cwd(&dir.word, Some(base.clone())))
        .or_else(|| environment_path(ctx, "GIT_DIR", Some(base.clone())));
    let mut candidates = Vec::new();
    if let Some(dir) = explicit_dir {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = dir
        else {
            return Err("repository config location is dynamic");
        };
        candidates.push((SourceNamespace::Host, format!("{path}/config")));
    } else {
        let platform = crate::paths::path_platform(Some(cwd));
        let mut directory = cwd.as_str();
        // Every ancestor costs resolver work under the shared analysis budget.
        loop {
            let prefix = directory.trim_end_matches('/');
            candidates.push((SourceNamespace::Host, format!("{prefix}/.git")));
            candidates.push((SourceNamespace::Host, format!("{prefix}/.git/HEAD")));
            candidates.push((SourceNamespace::Host, format!("{prefix}/.git/config")));
            if candidates.len() >= 96 {
                break;
            }
            // The walk ends at the root: `/`, or a drive root such as `C:/`.
            let Some((parent, _)) = prefix.rsplit_once('/') else {
                break;
            };
            let parent = if parent.is_empty() || parent.ends_with(':') {
                &directory[..=parent.len()]
            } else {
                parent
            };
            if !effinterp_proto::is_absolute_path(parent, platform) {
                break;
            }
            directory = parent;
        }
    }
    let (mut path, mut bytes) =
        match ctx
            .nest
            .observe_source_search(builder, &candidates, SourcePurpose::DependencySource)
        {
            SourceSearchObservation::Found { index, bytes } => (candidates[index].1.clone(), bytes),
            SourceSearchObservation::Refused(crate::SourceRefusal::Limit { limit }) => {
                builder.note_saturated(limit);
                return Err("repository alias config observation exceeded the analysis budget");
            }
            _ => return Ok(None),
        };
    if path.ends_with("/.git") {
        return Err(
            "linked-worktree alias config requires observing the common and worktree configuration",
        );
    }
    if let Some(directory) = path.strip_suffix("/HEAD") {
        // Stop at the nearest repository even when it has no config file.
        // Otherwise an enclosing repository's alias could be invented here.
        path = format!("{directory}/config");
        bytes = match ctx.nest.observe_source_search(
            builder,
            &[(SourceNamespace::Host, path.clone())],
            SourcePurpose::DependencySource,
        ) {
            SourceSearchObservation::Found { bytes, .. } => bytes,
            SourceSearchObservation::Refused(crate::SourceRefusal::Limit { limit }) => {
                builder.note_saturated(limit);
                return Err("repository alias config observation exceeded the analysis budget");
            }
            _ => return Err("selected repository alias configuration is not observed"),
        };
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| "alias config is not UTF-8")?;
    if !builder.budget().try_charge_steps(source.len() as u64) {
        builder.note_saturated("max_analysis_steps");
        return Err("repository alias config parsing exceeded the analysis budget");
    }
    if source.contains('\0') {
        return Err("alias config contains a NUL byte");
    }
    let node = builder.node(
        ProvenanceKind::SourceInput {
            path,
            digest: effinterp_proto::content_digest(&bytes),
        },
        &[model_node],
    );
    let mut aliases = Vec::new();
    let mut section = String::new();
    parse_config_source(source, |line| {
        match line {
            ConfigLine::Section {
                header,
                name,
                subsection,
            } => {
                if name == "alias" && subsection.is_some()
                    || header.starts_with("include")
                    || header.starts_with("alias ")
                    || header.starts_with("alias.")
                {
                    return Err("alias config includes or alias subsections are not resolved");
                }
                section = header;
            }
            ConfigLine::Setting {
                name,
                has_value,
                value,
            } => {
                if section == "extensions"
                    && name.eq_ignore_ascii_case("worktreeconfig")
                    && !config_is_false(Some(&value))
                {
                    return Err("per-worktree alias configuration is not observed");
                }
                if section == "alias" {
                    if !has_value {
                        return Err("alias config setting has no expansion");
                    }
                    aliases.push(Alias {
                        name,
                        expansion: value,
                        value_index: None,
                        source_node: Some(node),
                    });
                }
            }
        }
        Ok(())
    })?;
    Ok(Some(aliases))
}

/// git reads an included file's settings at the include (git-config(1)
/// "Includes"). Each `include.path`, and each `includeIf.<condition>.path`
/// whose condition git recognises, is followed when the source resolver
/// serves its file: the file's settings go in its place, replacing lower
/// entries only when the include certainly applies. git never applies a
/// condition it does not recognise, and skips a missing file. The model
/// does not evaluate a recognised condition (a gitdir pattern may match the
/// git dir's real path through a link), so its settings are only possible.
/// An include whose file cannot be read is kept, marked `unobserved`.
/// `base` is the directory of the file holding `entries`, against which git
/// resolves a relative path; git refuses one from the command line.
pub(super) fn expand_includes(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    entries: Vec<ConfigEntry>,
    base: Option<&str>,
    depth: u32,
) -> Vec<ConfigEntry> {
    use crate::nest::SourceSearchObservation;
    use crate::{SourceNamespace, SourcePurpose};

    let mut expanded = Vec::new();
    for mut entry in entries {
        let Some((section, rest)) = entry.key.split_once('.') else {
            expanded.push(entry);
            continue;
        };
        let (condition, variable) = rest
            .rsplit_once('.')
            .map_or((None, rest), |(condition, variable)| {
                (Some(condition), variable)
            });
        let certain = match condition {
            None if section.eq_ignore_ascii_case("include") => true,
            Some(condition) if section.eq_ignore_ascii_case("includeif") => {
                if ![
                    "gitdir:",
                    "gitdir/i:",
                    "onbranch:",
                    "hasconfig:remote.*.url:",
                ]
                .iter()
                .any(|prefix| condition.starts_with(prefix))
                {
                    expanded.push(entry);
                    continue;
                }
                false
            }
            _ => {
                expanded.push(entry);
                continue;
            }
        };
        if !variable.eq_ignore_ascii_case("path") {
            expanded.push(entry);
            continue;
        }
        let home = || match ctx.environment_value("HOME") {
            Some(ResourceExpr::Literal { value }) => Some(value),
            _ => None,
        };
        let path = entry.value.as_deref().and_then(|value| {
            if let Some(rest) = value.strip_prefix("~/") {
                home().map(|home| format!("{}/{rest}", home.trim_end_matches('/')))
            } else if value.starts_with('/') {
                Some(value.to_string())
            } else {
                base.map(|base| format!("{}/{value}", base.trim_end_matches('/')))
            }
        });
        // git stops at this depth of nested includes.
        let observed = path
            .filter(|_| depth < 10 && builder.is_host_realm())
            .and_then(|path| {
                match ctx.nest.observe_source_search(
                    builder,
                    &[(SourceNamespace::Host, path.clone())],
                    SourcePurpose::DependencySource,
                ) {
                    SourceSearchObservation::Found { bytes, .. } => Some(Some((path, bytes))),
                    SourceSearchObservation::Missing => Some(None),
                    SourceSearchObservation::Refused(crate::SourceRefusal::Limit { limit }) => {
                        builder.note_saturated(limit);
                        None
                    }
                    _ => None,
                }
            });
        let settings = match observed {
            Some(None) => Some(Vec::new()),
            Some(Some((path, bytes))) => included_settings(builder, &bytes).map(|settings| {
                builder.node(
                    ProvenanceKind::SourceInput {
                        path: path.clone(),
                        digest: effinterp_proto::content_digest(&bytes),
                    },
                    &[model_node],
                );
                let directory = path
                    .rsplit_once('/')
                    .map_or("/", |(directory, _)| directory);
                let settings = settings
                    .into_iter()
                    .map(|(key, value)| ConfigEntry {
                        key,
                        value: Some(value),
                        replaces: entry.replaces && certain,
                        unobserved: false,
                    })
                    .collect();
                expand_includes(
                    builder,
                    ctx,
                    model_node,
                    settings,
                    Some(directory),
                    depth + 1,
                )
            }),
            None => None,
        };
        match settings {
            Some(settings) => {
                expanded.push(entry);
                expanded.extend(settings);
            }
            None => {
                entry.unobserved = true;
                expanded.push(entry);
            }
        }
    }
    expanded
}

/// The settings an included config file makes, in order, as
/// `section[.subsection].variable` keys; a name without `=` is a boolean
/// true. `None` for a file the model does not read.
fn included_settings(builder: &mut PlanBuilder, bytes: &[u8]) -> Option<Vec<(String, String)>> {
    let source = std::str::from_utf8(bytes).ok()?;
    if !builder.budget().try_charge_steps(source.len() as u64) {
        builder.note_saturated("max_analysis_steps");
        return None;
    }
    if source.contains('\0') {
        return None;
    }
    let mut settings = Vec::new();
    let mut section = String::new();
    parse_config_source(source, |line| {
        match line {
            ConfigLine::Section {
                name, subsection, ..
            } => {
                section = match subsection {
                    Some(subsection) => format!("{name}.{subsection}"),
                    None => name,
                };
            }
            ConfigLine::Setting {
                name,
                has_value,
                value,
            } => settings.push((
                format!("{section}.{name}"),
                if has_value { value } else { "true".into() },
            )),
        }
        Ok(())
    })
    .ok()?;
    Some(settings)
}

/// One line of a git config file that `parse_config_source` read.
enum ConfigLine {
    /// A `[section]` or `[section "subsection"]` header: the whole header
    /// lowercased, the section name lowercased, and the subsection as
    /// written, unescaped. The older `[section.subsection]` spelling is one
    /// lowercased name.
    Section {
        header: String,
        name: String,
        subsection: Option<String>,
    },
    /// A variable under the current section, with its value; `has_value` is
    /// false for a name without `=`, which git reads as a boolean true.
    Setting {
        name: String,
        has_value: bool,
        value: String,
    },
}

/// Read a git config file's text line by line, in order, handing each
/// section header and setting to `visit`. A syntax the model does not read
/// is an error, as is any error `visit` returns.
fn parse_config_source(
    source: &str,
    mut visit: impl FnMut(ConfigLine) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut in_section = false;
    let mut chars = source.trim_start_matches('\u{feff}').chars().peekable();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            chars.next();
        }
        if matches!(chars.peek(), Some('#' | ';')) {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            let mut raw = String::new();
            loop {
                match chars.next() {
                    Some(']') => break,
                    Some('\n') | None => return Err("git config has an invalid section"),
                    Some(c) => raw.push(c),
                }
            }
            let raw = raw.trim();
            let (name, subsection) = raw
                .split_once(char::is_whitespace)
                .map_or((raw, None), |(name, rest)| (name, Some(rest.trim())));
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
            {
                return Err("git config has an invalid section name");
            }
            let subsection = match subsection {
                Some(subsection) => {
                    let mut chars = subsection.chars();
                    if chars.next() != Some('"') {
                        return Err("git config has an invalid subsection");
                    }
                    let mut unescaped = String::new();
                    loop {
                        match chars.next() {
                            Some('\\') => match chars.next() {
                                Some(c) => unescaped.push(c),
                                None => {
                                    return Err("git config has an invalid subsection escape");
                                }
                            },
                            Some('"') if chars.next().is_none() => break,
                            Some('"') | None => {
                                return Err("git config has an invalid subsection");
                            }
                            Some(c) => unescaped.push(c),
                        }
                    }
                    Some(unescaped)
                }
                None => None,
            };
            in_section = true;
            visit(ConfigLine::Section {
                header: raw.to_ascii_lowercase(),
                name: name.to_ascii_lowercase(),
                subsection,
            })?;
            continue;
        }
        if chars.peek().is_none() {
            break;
        }
        let mut name = String::new();
        while chars
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '-')
        {
            name.push(chars.next().unwrap());
        }
        if !name.starts_with(|c: char| c.is_ascii_alphabetic()) || !in_section {
            return Err("git config contains an unrecognized setting");
        }
        while chars.peek().is_some_and(|c| matches!(c, ' ' | '\t' | '\r')) {
            chars.next();
        }
        let has_value = chars.peek() == Some(&'=');
        if has_value {
            chars.next();
        }
        let mut value = String::new();
        let mut quoted = false;
        let mut whitespace = String::new();
        loop {
            match chars.next() {
                None | Some('\n') => {
                    if quoted {
                        return Err("git config has an unclosed quote");
                    }
                    break;
                }
                Some('#' | ';') if !quoted => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                    break;
                }
                Some('"') => {
                    value.push_str(&whitespace);
                    whitespace.clear();
                    quoted = !quoted;
                }
                Some('\\') => {
                    let escaped = match chars.next() {
                        Some('\n') => continue,
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('b') => '\u{8}',
                        Some(c @ ('"' | '\\')) => c,
                        _ => return Err("git config has an invalid escape"),
                    };
                    value.push_str(&whitespace);
                    whitespace.clear();
                    value.push(escaped);
                }
                Some(c @ (' ' | '\t' | '\r')) if !quoted => {
                    if !value.is_empty() {
                        whitespace.push(c);
                    }
                }
                Some(c) => {
                    if !has_value {
                        return Err("git config setting is missing '='");
                    }
                    value.push_str(&whitespace);
                    whitespace.clear();
                    value.push(c);
                }
            }
        }
        visit(ConfigLine::Setting {
            name,
            has_value,
            value,
        })?;
    }
    Ok(())
}

/// The values `key` may hold, under git's key equality: section and
/// variable names ignore case, a subsection does not. A setting under an
/// unreadable key may be this key, so it adds an unknown value.
pub(super) fn config_values<'a>(globals: &'a Globals, key: &str) -> ConfigValues<'a> {
    let parts = |key: &str| -> Option<(String, String, String)> {
        let (section, rest) = key.split_once('.')?;
        let (subsection, variable) = rest.rsplit_once('.').unwrap_or(("", rest));
        Some((
            section.to_ascii_lowercase(),
            subsection.to_string(),
            variable.to_ascii_lowercase(),
        ))
    };
    let wanted = parts(key);
    let mut found = ConfigValues {
        values: Vec::new(),
        unset: true,
        unknown: false,
    };
    for entry in &globals.configs {
        if entry.unobserved {
            found.unknown = true;
        } else if entry.key.is_empty() {
            found.values.push(None);
        } else if wanted.is_some() && parts(&entry.key) == wanted {
            if entry.replaces {
                found.values.clear();
                found.unset = false;
                found.unknown = false;
            }
            found.values.push(entry.value.as_deref());
        }
    }
    found
}

/// The outer option says whether the setting may be present, the inner one
/// the value when every execution leaves the same readable one; a value
/// that differs between executions is not known.
pub(super) fn config_value<'a>(globals: &'a Globals, key: &str) -> Option<Option<&'a str>> {
    let found = config_values(globals, key);
    if found.values.is_empty() {
        return None;
    }
    Some(found.certain().flatten())
}

/// One value `remote_settings` finds.
#[derive(Clone, Copy)]
pub(super) enum RemoteSetting<'a> {
    /// A value, `None` when the model cannot read it, and whether it
    /// certainly reaches the invocation.
    Value(Option<&'a str>, bool),
    /// An include the model could not read, which may add any value there.
    Unobserved,
}

/// Every value `remote.<name>.<variable>` may hold for the remote `remote`,
/// or for any remote when the model cannot name the one the invocation
/// selects, in order. A value certainly reaches the invocation when its own
/// environment or -c sets it for a named remote. Every value is kept, as git
/// keeps every value of a multi-valued key such as `remote.<name>.push`. A
/// setting under an unreadable key adds an unknown value.
pub(super) fn remote_settings<'a>(
    globals: &'a Globals,
    remote: Option<&str>,
    variable: &str,
) -> Vec<RemoteSetting<'a>> {
    globals
        .configs
        .iter()
        .filter_map(|entry| {
            if entry.unobserved {
                return Some(RemoteSetting::Unobserved);
            }
            if entry.key.is_empty() {
                return Some(RemoteSetting::Value(None, false));
            }
            let (section, rest) = entry.key.split_once('.')?;
            let (subsection, name) = rest.rsplit_once('.')?;
            (section.eq_ignore_ascii_case("remote")
                && name.eq_ignore_ascii_case(variable)
                && remote.is_none_or(|remote| remote == subsection))
            .then(|| {
                RemoteSetting::Value(entry.value.as_deref(), entry.replaces && remote.is_some())
            })
        })
        .collect()
}

/// The configuration an invocation of `repo` reads beneath its own `-c`
/// options, lowest precedence first (see `Globals::configs`). Git reads the
/// system, global, repository and worktree files in that order, whatever
/// order they were written in, then git(1)'s `GIT_CONFIG_COUNT` pairs, then
/// `GIT_CONFIG_PARAMETERS`, the variable that carries `-c` into nested git
/// invocations. Every earlier write in the subject only adds a value the key
/// may hold, beside what the files held and every other write, whatever git
/// dir or file it names: whether it finished, ran at all, ran last, or wrote
/// a file this invocation reads is not established. The one exception is a
/// write to a foreach submodule's superproject, or the reverse, when neither
/// invocation selects its repository or configuration other than by
/// discovery (`discovered` for this one).
/// An environment git refuses to parse fails the invocation before it runs;
/// the model then keeps what it plans without it.
pub(super) fn inherited_configs(
    builder: &PlanBuilder,
    ctx: &InvocationCtx<'_>,
    repo: &ResourceExpr,
    discovered: bool,
) -> Vec<ConfigEntry> {
    use crate::builder::GitConfigScope;

    let writes = builder.git_config_writes().collect::<Vec<_>>();
    let reader = ScopedRepo::new(repo, builder.git_foreach_binding());
    let mut configs = Vec::new();
    for scope in [
        GitConfigScope::System,
        GitConfigScope::Global,
        GitConfigScope::Local,
        GitConfigScope::Worktree,
    ] {
        for write in writes.iter().filter(|write| write.scope == scope) {
            // A redirected write has no repository (`record_config_write`).
            if discovered
                && write.repository.as_ref().is_some_and(|written| {
                    superproject_and_submodule(
                        builder,
                        ScopedRepo::new(written, write.binding),
                        reader,
                    )
                })
            {
                continue;
            }
            configs.push(ConfigEntry {
                key: write.key.clone().unwrap_or_default(),
                value: write.value.clone(),
                replaces: false,
                unobserved: false,
            });
        }
    }
    let literal = |name: &str| match ctx.environment_value(name) {
        Some(ResourceExpr::Literal { value }) => Some(Ok(value)),
        Some(_) => Some(Err(())),
        None => None,
    };
    let unknown = || ConfigEntry {
        key: String::new(),
        value: None,
        replaces: false,
        unobserved: false,
    };
    let mut environment = Vec::new();
    match literal("GIT_CONFIG_COUNT") {
        Some(Ok(count)) => match config_count(&count) {
            // A count git refuses, or a pair it cannot find, fails the
            // invocation (config.c `git_config_from_parameters`).
            None => return configs,
            Some(count) if count > GIT_CONFIG_COUNT_LIMIT => environment.push(unknown()),
            Some(count) => {
                for index in 0..count {
                    let (Some(key), Some(value)) = (
                        literal(&format!("GIT_CONFIG_KEY_{index}")),
                        literal(&format!("GIT_CONFIG_VALUE_{index}")),
                    ) else {
                        return configs;
                    };
                    if key.as_ref().is_ok_and(String::is_empty) {
                        return configs;
                    }
                    environment.push(ConfigEntry {
                        key: key.unwrap_or_default(),
                        value: value.ok(),
                        replaces: true,
                        unobserved: false,
                    });
                }
            }
        },
        Some(Err(())) => environment.push(unknown()),
        None => {}
    }
    match literal("GIT_CONFIG_PARAMETERS") {
        // NUL is a value `command_parameters` could not read.
        Some(Ok(parameters)) => match config_parameters(&parameters) {
            Some(pairs) => environment.extend(pairs.into_iter().map(|(key, value)| {
                if key.contains('\0') {
                    unknown()
                } else {
                    ConfigEntry {
                        key,
                        value: (!value.contains('\0')).then_some(value),
                        replaces: true,
                        unobserved: false,
                    }
                }
            })),
            None => return configs,
        },
        Some(Err(())) => environment.push(unknown()),
        None => {}
    }
    configs.extend(environment);
    configs
}

/// More `GIT_CONFIG_COUNT` pairs than this are read as one unknown setting.
const GIT_CONFIG_COUNT_LIMIT: u64 = 64;

/// `GIT_CONFIG_COUNT` as git reads it with `strtoul`: leading whitespace, an
/// optional sign, decimal digits, and nothing after them; `None` for a value
/// git refuses, including one above `INT_MAX`.
fn config_count(text: &str) -> Option<u64> {
    let trimmed = text.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    if digits.is_empty() {
        // No digits: strtoul consumes nothing, which only an empty value
        // leaves with nothing after it.
        return text.is_empty().then_some(0);
    }
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = digits
        .trim_start_matches('0')
        .parse::<u64>()
        .ok()
        .or_else(|| digits.bytes().all(|byte| byte == b'0').then_some(0))?;
    // A negated nonzero count wraps to a huge unsigned value.
    let value = if negative && value != 0 {
        u64::MAX
    } else {
        value
    };
    (value <= i32::MAX as u64).then_some(value)
}

/// Parse `GIT_CONFIG_PARAMETERS` the way git's `parse_config_env_list`
/// does: whitespace-separated single-quoted `'key'='value'` pairs, the
/// implicit boolean `'key'=`, or the older `'key=value'` form. A key
/// without a value is a boolean true. `None` for text git refuses.
pub(super) fn config_parameters(text: &str) -> Option<Vec<(String, String)>> {
    // One shell single-quoted word, with `'\''` and `'\!'` escapes.
    fn dequote(text: &str) -> Option<(String, &str)> {
        let mut rest = text.strip_prefix('\'')?;
        let mut word = String::new();
        loop {
            let end = rest.find('\'')?;
            word.push_str(&rest[..end]);
            rest = &rest[end + 1..];
            match rest.as_bytes() {
                [b'\\', quoted @ (b'\'' | b'!'), b'\'', ..] => {
                    word.push(*quoted as char);
                    rest = &rest[3..];
                }
                _ => return Some((word, rest)),
            }
        }
    }
    let mut configs = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let (key, after) = dequote(rest)?;
        let (key, value, after) = match after.strip_prefix('=') {
            Some(after) if after.starts_with('\'') => {
                let (value, after) = dequote(after)?;
                (key, value, after)
            }
            Some(after) if after.is_empty() || after.starts_with(char::is_whitespace) => {
                (key, "true".to_string(), after)
            }
            Some(_) => return None,
            None => match key.split_once('=') {
                Some((key, value)) => (key.to_string(), value.to_string(), after),
                None => (key, "true".to_string(), after),
            },
        };
        if !after.is_empty() && !after.starts_with(char::is_whitespace) {
            return None;
        }
        if key.is_empty() {
            return None;
        }
        configs.push((key, value));
        rest = after.trim_start();
    }
    Some(configs)
}

/// A git boolean config or option value the model classifies: `true`,
/// `yes`, `on`, `false`, `no`, `off` or empty in any case, or a plain
/// decimal integer that every supported release accepts (within `i32`,
/// above its minimum, no leading zero), nonzero meaning true. git also
/// reads unit suffixes, hex and leading-zero octal (rejecting `08`) within
/// its own checks; those, and everything else, are `None`: a value the
/// model does not classify.
pub(super) fn git_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => Some(true),
        "false" | "no" | "off" | "" => Some(false),
        number => {
            let digits = number.strip_prefix(['+', '-']).unwrap_or(number);
            (!digits.is_empty()
                && (digits == "0" || !digits.starts_with('0'))
                && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| number.parse::<i32>().ok())
            .flatten()
            // 2.39 refuses `i32::MIN`, which 2.55 accepts.
            .filter(|number| *number != i32::MIN)
            .map(|number| number != 0)
        }
    }
}

fn config_is_false(value: Option<&str>) -> bool {
    matches!(value, Some("false" | "no" | "0" | "off"))
}

/// git(1) appends each -c pair to `GIT_CONFIG_PARAMETERS` as
/// `'key'='value'`, shell-quoted, so every command it runs reads them. A
/// value the model cannot read is NUL inside its quotes, which no real
/// environment value holds, so the pairs beside it stay readable.
/// The setting a `-c` word makes, as git-config(1) spells it:
/// `<name>=<value>`, or `<name>` alone for a boolean true. The name is
/// readable whenever it precedes the first `=` in the literal head of the
/// word, even when the value after it is not. `None` for a word the model
/// cannot read, and for a valueless alias, which git refuses.
pub(super) fn config_option_setting(word: &Word) -> Option<(String, Option<String>)> {
    match word.as_literal() {
        Some(text) => match text.split_once('=') {
            Some((key, value)) => Some((key.to_string(), Some(value.to_string()))),
            None if !text.is_empty()
                && !text
                    .split_once('.')
                    .is_some_and(|(section, _)| section.eq_ignore_ascii_case("alias")) =>
            {
                Some((text.to_string(), Some("true".into())))
            }
            None => None,
        },
        None => word
            .literal_prefix()
            .split_once('=')
            .map(|(key, _)| (key.to_string(), None)),
    }
}

/// The setting `--config-env=<name>=<envvar>` makes: the name before the
/// last `=`, valued from that environment variable, which the model may not
/// know. `None` for a word git refuses or the model cannot read.
pub(super) fn config_env_setting(
    ctx: &InvocationCtx<'_>,
    word: &Word,
) -> Option<(String, Option<String>)> {
    let (key, name) = word.as_literal()?.rsplit_once('=')?;
    if key.is_empty() || name.is_empty() {
        return None;
    }
    let value = match ctx.environment_value(name) {
        Some(ResourceExpr::Literal { value }) => Some(value),
        _ => None,
    };
    Some((key.to_string(), value))
}

pub(super) fn command_parameters(
    ctx: &InvocationCtx<'_>,
    pairs: &[(String, Option<String>)],
) -> Option<Option<String>> {
    if pairs.is_empty() {
        return None;
    }
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''").replace('!', "'\\!'"));
    let mut text = match ctx.environment_value("GIT_CONFIG_PARAMETERS") {
        Some(ResourceExpr::Literal { value }) => value,
        Some(_) => return Some(None),
        None => String::new(),
    };
    for (key, value) in pairs {
        if !text.is_empty() {
            text.push(' ');
        }
        let value = value.as_deref().map_or_else(|| "'\0'".to_string(), quote);
        text.push_str(&format!("{}={value}", quote(key)));
    }
    Some(Some(text))
}
