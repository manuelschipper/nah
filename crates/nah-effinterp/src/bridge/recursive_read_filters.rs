//! Which observed descendants a recursive read skips under the name and path
//! filters its model states (tar and rsync `--exclude`, aws s3 `--exclude`,
//! az `--pattern`, and the hidden-entry, `--glob`, `--type` and ignore-file
//! rules of a ripgrep-style search).

/// Whether a recursive read whose model states `excluded_names`, a list of
/// whole names and `name*` prefixes (tar and rsync `--exclude`), skips
/// `path`: a component of it below the observed `root` is one of those names
/// or starts with one of those prefixes, so neither it nor anything below it
/// is read. An unreadable list skips nothing.
pub(super) fn skipped_by_excluded_names(
    effect: &effinterp_proto::Effect,
    root: &nah_proto::observation::PathObservation,
    path: &nah_proto::ctx::AbsolutePath,
) -> bool {
    let Some(names) = excluded_name_list(effect) else {
        return false;
    };
    path_below_observed_root(root, path).is_some_and(|below| {
        below
            .split('/')
            .any(|component| excludes_component(&names, component))
    })
}

/// The `excluded_names` a recursive read's model states, when the list is
/// readable.
pub(super) fn excluded_name_list(effect: &effinterp_proto::Effect) -> Option<Vec<&str>> {
    let effinterp_proto::AttrValue::List(names) = effect.attributes.get("excluded_names")? else {
        return None;
    };
    names
        .iter()
        .map(|name| match name {
            effinterp_proto::AttrValue::String(name) => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

/// Whether one of the excluded `names`, a whole name or a `name*` prefix, is
/// the path component `component`.
pub(super) fn excludes_component(names: &[&str], component: &str) -> bool {
    names.iter().any(|name| match name.strip_suffix('*') {
        Some(prefix) => component.starts_with(prefix),
        None => component == *name,
    })
}

/// The observed descendants a recursive read skips under the path filters
/// its model states: `excluded_paths` (aws s3 `--exclude`) and
/// `included_paths` (az `--pattern`), JSON lists of fnmatch globs matched
/// against a file's path relative to the read's `root`, where `*` also
/// crosses `/`. A file is skipped when an exclusion matches it or no
/// inclusion does; a directory only when it and everything listed below it
/// are skipped. The tools join each glob under the root they were given, so
/// a root spelled with glob characters proves nothing.
pub(super) fn skipped_by_path_filters<'a>(
    effect: &effinterp_proto::Effect,
    root: &nah_proto::observation::PathObservation,
    paths: &'a [nah_proto::ctx::AbsolutePath],
) -> std::collections::BTreeSet<&'a nah_proto::ctx::AbsolutePath> {
    let globs = |name: &str| match effect.attributes.get(name) {
        Some(effinterp_proto::AttrValue::String(list)) => {
            serde_json::from_str::<Vec<String>>(list).ok()
        }
        _ => None,
    };
    let excluded = globs("excluded_paths").unwrap_or_default();
    let included = globs("included_paths");
    if (excluded.is_empty() && included.is_none())
        || root.resolved().as_str().contains(['*', '?', '['])
    {
        return Default::default();
    }
    // Whether the platform folds case is not known. An exclusion counts when
    // it matches as written. One holding a negated bracket class must also
    // match with case folded, where the class can stop matching and the file
    // would be kept. A range is read as written, though folding can shrink
    // one that spans both cases (`[A-z]`). An inclusion counts when it
    // matches either way.
    let folded = |glob: &str, relative: &str| {
        fnmatch(&glob.to_ascii_lowercase(), &relative.to_ascii_lowercase())
    };
    let selected = |relative: &str| {
        !excluded
            .iter()
            .any(|glob| fnmatch(glob, relative) && (!glob.contains("[!") || folded(glob, relative)))
            && included.as_ref().is_none_or(|included| {
                included
                    .iter()
                    .any(|glob| fnmatch(glob, relative) || folded(glob, relative))
            })
    };
    let relative = |path: &'a nah_proto::ctx::AbsolutePath| path_below_observed_root(root, path);
    // Every directory above a file the filters keep.
    let mut kept_above = std::collections::BTreeSet::new();
    for relative in paths.iter().filter_map(relative) {
        if selected(relative) {
            kept_above.extend(relative.match_indices('/').map(|(at, _)| &relative[..at]));
        }
    }
    paths
        .iter()
        .filter(|path| {
            relative(path)
                .is_some_and(|relative| !selected(relative) && !kept_above.contains(relative))
        })
        .collect()
}

/// The observed descendants a ripgrep-style search does not open (`rg`, `ag`
/// and the native search tools, which run ripgrep). Its model states
/// `hidden_entries_skipped` when the search leaves out entries whose name
/// starts with a dot, `search_globs` for its `--glob` overrides in order, and
/// `search_types` for its `--type` names. ripgrep decides each entry below a
/// root it was given, never the root itself:
///
/// - The last glob matching an entry's name decides it: `!glob` leaves it
///   out, a plain glob searches it even when it is hidden. A file no glob
///   matches is left out once any plain glob is stated.
/// - Otherwise a file is searched only when it belongs to a stated type, and
///   then even when it is hidden.
/// - Otherwise a hidden entry is left out when hidden entries are skipped.
/// - Nothing below a directory that is left out is searched.
///
/// Only a glob that names an entry at any depth is read: `NAME`, `**/NAME`
/// and, as an exclusion, `NAME/**`. Another exclusion is passed over, which
/// only searches more. Another plain glob, a type this table does not hold,
/// or `search_filters_unmodeled` (an option that changes how globs or types
/// match) proves nothing, and then no entry is skipped. Whether a glob folds
/// case differs between the tools (`--glob`, `--iglob`), so a plain glob or a
/// type counts when it matches either way and an exclusion only as written.
pub(super) fn skipped_by_search_filters<'a>(
    effect: &effinterp_proto::Effect,
    root: &nah_proto::observation::PathObservation,
    paths: &'a [nah_proto::ctx::AbsolutePath],
) -> std::collections::BTreeSet<&'a nah_proto::ctx::AbsolutePath> {
    use effinterp_proto::AttrValue;
    let flag = |name: &str| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    let strings = |name: &str| match effect.attributes.get(name) {
        Some(AttrValue::List(values)) => values
            .iter()
            .map(|value| match value {
                AttrValue::String(value) => Some(value.as_str()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>(),
        Some(_) => None,
        None => Some(Vec::new()),
    };
    let hidden_skipped = flag("hidden_entries_skipped");
    let (Some(stated_globs), Some(stated_types)) =
        (strings("search_globs"), strings("search_types"))
    else {
        return Default::default();
    };
    if flag("search_filters_unmodeled")
        || !hidden_skipped && stated_globs.is_empty() && stated_types.is_empty()
    {
        return Default::default();
    }
    // Each override as whether it searches what it matches, the entry names
    // it matches, and whether it matches directories alone.
    let mut overrides = Vec::new();
    for stated in stated_globs {
        let (searches, glob) = match stated.strip_prefix('!') {
            Some(glob) => (false, glob),
            None => (true, stated),
        };
        let mut name = glob;
        while let Some(rest) = name.strip_prefix("**/") {
            name = rest;
        }
        let below = name.strip_suffix("/**");
        let name = below.unwrap_or(name);
        let names = (!name.is_empty() && !name.contains(['/', '\\']) && !name.contains("[^"))
            .then(|| brace_alternatives(name))
            .flatten();
        match names {
            Some(names) if searches && below.is_none() => overrides.push((true, names, false)),
            Some(names) if !searches => overrides.push((false, names, below.is_some())),
            _ if searches => return Default::default(),
            _ => {}
        }
    }
    let mut type_globs = Vec::new();
    for name in stated_types {
        let Some((_, globs)) = RIPGREP_TYPES.iter().find(|(known, _)| *known == name) else {
            return Default::default();
        };
        type_globs.extend(globs.iter().copied());
    }
    let matches_either_way = |glob: &str, name: &str| {
        fnmatch(glob, name) || fnmatch(&glob.to_ascii_lowercase(), &name.to_ascii_lowercase())
    };
    // Whether an override decides this entry name, and how.
    let overridden = |name: &str, directory: bool| {
        overrides
            .iter()
            .rev()
            .find(|(searches, globs, directories_only)| {
                (directory || !directories_only)
                    && globs.iter().any(|glob| {
                        if *searches {
                            matches_either_way(glob, name)
                        } else {
                            fnmatch(glob, name)
                        }
                    })
            })
            .map(|(searches, _, _)| *searches)
    };
    let any_plain_glob = overrides.iter().any(|(searches, _, _)| *searches);
    let hidden = |name: &str| hidden_skipped && name.starts_with('.');
    let searched = |relative: &str| {
        let (directories, name) = relative.rsplit_once('/').unwrap_or(("", relative));
        let entered = directories
            .split('/')
            .filter(|directory| !directory.is_empty())
            .all(|directory| overridden(directory, true).unwrap_or(!hidden(directory)));
        entered
            && match overridden(name, false) {
                Some(searches) => searches,
                None if any_plain_glob => false,
                None if !type_globs.is_empty() => {
                    type_globs.iter().any(|glob| matches_either_way(glob, name))
                }
                None => !hidden(name),
            }
    };
    let relative = |path: &'a nah_proto::ctx::AbsolutePath| path_below_observed_root(root, path);
    // Every directory above a file the search opens.
    let mut searched_above = std::collections::BTreeSet::new();
    for relative in paths.iter().filter_map(relative) {
        if searched(relative) {
            searched_above.extend(relative.match_indices('/').map(|(at, _)| &relative[..at]));
        }
    }
    paths
        .iter()
        .filter(|path| {
            relative(path)
                .is_some_and(|relative| !searched(relative) && !searched_above.contains(relative))
        })
        .collect()
}

/// Which ignore rules a search leaves entries out by.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum HonouredIgnores {
    /// Every rule Git applies, as ripgrep does: the `.gitignore` files from
    /// the repository's top level down, its `info/exclude` and the global
    /// excludes file.
    Git,
    /// Only a line that is an entry's own name, in a `.gitignore` or
    /// `.git/info/exclude` the search passes on its way down to the entry.
    /// ag reads no ignore file above the path it was given and no global
    /// one through Git's rules, matches a wildcard line by its own rules,
    /// and drops such a named entry whatever another line says.
    NamedBelow,
}

/// The ignore rules the search `effect` states it honours:
/// `ignore_files_honoured` (`rg` without an option that turns ignore files
/// off) or `named_ignores_honoured` (`ag`). A native search tool states
/// neither, so `native_search` answers for it: the runtime's tool is ripgrep
/// run without `--no-ignore`.
pub(super) fn honoured_ignores(
    effect: &effinterp_proto::Effect,
    native_search: bool,
) -> Option<HonouredIgnores> {
    let flag =
        |name: &str| effect.attributes.get(name) == Some(&effinterp_proto::AttrValue::Bool(true));
    if effect.operation.as_str() != "filesystem.read" || !flag("recursive") {
        None
    } else if flag("ignore_files_honoured") || native_search {
        Some(HonouredIgnores::Git)
    } else if flag("named_ignores_honoured") {
        Some(HonouredIgnores::NamedBelow)
    } else {
        None
    }
}

/// One query per host directory a search of `plan` reads while honouring
/// ignore files: the entries below it that those files leave out.
pub(super) fn ignored_entries_queries(
    plan: &effinterp_proto::Plan,
    native_search: bool,
) -> Vec<nah_proto::observation::ObservationQuery> {
    plan.effects
        .iter()
        .filter(|effect| {
            effect.realm.is_host() && honoured_ignores(effect, native_search).is_some()
        })
        .filter_map(|effect| match &effect.resource {
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(
            |(index, requested)| nah_proto::observation::ObservationQuery::IgnoredEntries {
                key: format!("effinterp-ignored-entries-{index:04}"),
                requested: requested.to_owned(),
                cwd_key: crate::observation_request::CWD_KEY.into(),
            },
        )
        .collect()
}

/// The ignored entries the observation lists below the directory `requested`,
/// when it answered for them.
pub(super) fn observed_ignored_entries<'a>(
    observation: &'a nah_proto::observation::Observation,
    requested: &str,
) -> Option<&'a nah_proto::observation::IgnoredEntriesObservation> {
    use nah_proto::observation::{ObservationQuery, ObservationValue, Observed};
    observation
        .facts()
        .iter()
        .find_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::IgnoredEntries {
                    requested: directory,
                    ..
                },
                ObservationValue::IgnoredEntries {
                    observed: Observed::Ok { value },
                },
            ) if directory == requested => Some(value),
            _ => None,
        })
}

/// Whether the observation shows `name` unset or empty.
pub(super) fn observed_unset(
    observation: &nah_proto::observation::Observation,
    name: &str,
) -> bool {
    use nah_proto::observation::{EnvObservation, ObservationQuery, ObservationValue, Observed};
    observation.facts().iter().any(|fact| {
        matches!(fact.query(), ObservationQuery::Env { name: asked, .. } if asked == name)
            && match fact.value() {
                ObservationValue::Env {
                    observed: Observed::Ok { value },
                } => match value {
                    EnvObservation::Unset => true,
                    EnvObservation::Value { text } => text.is_empty(),
                },
                _ => false,
            }
    })
}

/// Whether a path component names a file that decides what a search ignores,
/// or a directory that holds a repository's or a user's Git files: an ignore
/// file, `.git`, `.gitconfig`, or the `git` of `~/.config/git`. A global
/// excludes file is commonly named after `.gitignore` (`.gitignore_global`).
fn holds_ignore_rules(component: &str) -> bool {
    component.starts_with(".gitignore")
        || matches!(
            component,
            ".ignore" | ".rgignore" | ".git" | "git" | ".gitconfig"
        )
}

/// Whether nothing else the invocation does can change which entries its
/// searches ignore. The ignored entries are observed before the invocation
/// runs, so they answer only when every other effect leaves the ignore
/// files, the repository and the tree as observed: it reads, runs a program
/// whose own effects are stated beside it, or writes, removes or re-modes
/// one named path. That path must not be one of the `rule_files` the
/// observation rests on or a directory above one, as spelled or as the host
/// resolved it, and must not be named like an ignore file or lie in a `.git`
/// directory, where a new rule file would count. A move can carry an ignored
/// entry to where no rule matches it, and so can a link made beside it for a
/// search that follows links (`follows_links`), which therefore takes no
/// write at all. Order is not read, so a change after the search refuses the
/// answer too.
pub(super) fn ignore_rules_stand(
    view: &crate::plan_view::PlanView<'_>,
    follows_links: bool,
    rule_files: &[String],
) -> bool {
    use effinterp_proto::{ResourceExpr, ResourceIdentity};
    let plan = view.plan();
    let platform = view.authority().platform();
    let reaches_rule_file = |path: &str| {
        rule_files.iter().any(|file| {
            nah_proto::labels::lexical_path::same_path(path, file, platform)
                || nah_proto::labels::lexically_contains(path, file, platform)
        })
    };
    plan.boundaries.iter().all(|boundary| {
        !boundary
            .domains
            .iter()
            .any(|domain| matches!(domain.0.as_str(), "filesystem" | "git" | "process"))
    }) && plan
        .effects
        .iter()
        .all(|effect| match effect.operation.as_str() {
            "process.exec" | "environment.read" | "filesystem.read" | "git.read" => true,
            operation if operation.starts_with("network.") => true,
            "filesystem.write"
            | "filesystem.create"
            | "filesystem.delete"
            | "filesystem.metadata"
                if !follows_links =>
            {
                match &effect.resource {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => {
                        !path.split(['/', '\\']).any(holds_ignore_rules)
                            && !reaches_rule_file(path)
                            && !view
                                .observed_path(path)
                                .and_then(|observed| observed.realpath())
                                .is_some_and(|real| reaches_rule_file(real.as_str()))
                    }
                    _ => false,
                }
            }
            _ => false,
        })
}

/// The observed descendants a search leaves out because an ignore rule it
/// honours matches them: `ignored` lists the entries Git ignores below the
/// search's `root`, a directory standing for everything it holds.
///
/// Nothing is left out where the answer is not established:
/// The search states a plain glob, which ripgrep searches even when a rule
/// ignores the entry, or an option that changes how globs match. An ignore
/// file that may re-include an entry is the observation's to answer for: it
/// lists no such entry.
pub(super) fn skipped_by_ignore_files<'a>(
    effect: &effinterp_proto::Effect,
    honoured: HonouredIgnores,
    root: &nah_proto::observation::PathObservation,
    paths: &'a [nah_proto::ctx::AbsolutePath],
    ignored: &nah_proto::observation::IgnoredEntriesObservation,
) -> std::collections::BTreeSet<&'a nah_proto::ctx::AbsolutePath> {
    use effinterp_proto::AttrValue;
    let plain_glob = match effect.attributes.get("search_globs") {
        Some(AttrValue::List(globs)) => globs
            .iter()
            .any(|glob| !matches!(glob, AttrValue::String(glob) if glob.starts_with('!'))),
        Some(_) => true,
        None => false,
    };
    if plain_glob
        || effect.attributes.get("search_filters_unmodeled") == Some(&AttrValue::Bool(true))
    {
        return Default::default();
    }
    let relative = |path: &'a nah_proto::ctx::AbsolutePath| path_below_observed_root(root, path);
    let rules = ignored
        .entries()
        .iter()
        .filter(|entry| honoured == HonouredIgnores::Git || named_below(entry))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths
        .iter()
        .filter(|path| {
            relative(path).is_some_and(|relative| {
                rules.iter().any(|rule| match rule.strip_suffix('/') {
                    Some(_) => relative.starts_with(rule),
                    None => relative == *rule,
                })
            })
        })
        .collect()
}

/// Whether the rule deciding `entry` is a line spelling the entry's own name
/// in a `.gitignore` or `.git/info/exclude` at or below the observed
/// directory: the one kind of rule `HonouredIgnores::NamedBelow` reads.
fn named_below(entry: &nah_proto::observation::IgnoredEntry) -> bool {
    let path = entry.path();
    let (name, pattern) = match path.strip_suffix('/') {
        Some(directory) => (
            directory,
            entry.pattern().strip_suffix('/').unwrap_or(entry.pattern()),
        ),
        None => (path, entry.pattern()),
    };
    let name = name.rsplit_once('/').map_or(name, |(_, name)| name);
    entry.rule_file().is_some_and(|file| {
        file == ".git/info/exclude" || file == ".gitignore" || file.ends_with("/.gitignore")
    }) && pattern == name
        && pattern.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

/// The file-name globs of the ripgrep `--type` names agents commonly pass,
/// as `rg --type-list` prints them (ripgrep 14.1).
const RIPGREP_TYPES: &[(&str, &[&str])] = &[
    ("c", &["*.[chH]", "*.[chH].in", "*.cats"]),
    (
        "cpp",
        &[
            "*.[ChH]",
            "*.[ChH].in",
            "*.[ch]pp",
            "*.[ch]pp.in",
            "*.[ch]xx",
            "*.[ch]xx.in",
            "*.cc",
            "*.cc.in",
            "*.hh",
            "*.hh.in",
            "*.inl",
        ],
    ),
    ("cs", &["*.cs"]),
    ("css", &["*.css", "*.scss"]),
    ("go", &["*.go"]),
    ("h", &["*.h", "*.hh", "*.hpp"]),
    ("html", &["*.ejs", "*.htm", "*.html"]),
    ("java", &["*.java", "*.jsp", "*.jspx", "*.properties"]),
    ("js", &["*.cjs", "*.js", "*.jsx", "*.mjs", "*.vue"]),
    ("json", &["*.json", "*.sarif", "composer.lock"]),
    ("kotlin", &["*.kt", "*.kts"]),
    ("markdown", RIPGREP_MARKDOWN),
    ("md", RIPGREP_MARKDOWN),
    (
        "php",
        &[
            "*.php", "*.php3", "*.php4", "*.php5", "*.php7", "*.php8", "*.pht", "*.phtml",
        ],
    ),
    ("py", &["*.py", "*.pyi"]),
    ("python", &["*.py", "*.pyi"]),
    (
        "ruby",
        &[
            "*.gemspec",
            "*.rb",
            "*.rbw",
            ".irbrc",
            "Gemfile",
            "Rakefile",
            "config.ru",
        ],
    ),
    ("rust", &["*.rs"]),
    (
        "sh",
        &[
            "*.bash",
            "*.bashrc",
            "*.csh",
            "*.cshrc",
            "*.ksh",
            "*.kshrc",
            "*.sh",
            "*.tcsh",
            "*.zsh",
            ".bash_login",
            ".bash_logout",
            ".bash_profile",
            ".bashrc",
            ".cshrc",
            ".kshrc",
            ".login",
            ".logout",
            ".profile",
            ".tcshrc",
            ".zlogin",
            ".zlogout",
            ".zprofile",
            ".zshenv",
            ".zshrc",
            "bash_login",
            "bash_logout",
            "bash_profile",
            "bashrc",
            "profile",
            "zlogin",
            "zlogout",
            "zprofile",
            "zshenv",
            "zshrc",
        ],
    ),
    ("sql", &["*.psql", "*.sql"]),
    ("swift", &["*.swift"]),
    ("toml", &["*.toml", "Cargo.lock"]),
    ("ts", &["*.cts", "*.mts", "*.ts", "*.tsx"]),
    ("typescript", &["*.cts", "*.mts", "*.ts", "*.tsx"]),
    ("txt", &["*.txt"]),
    (
        "xml",
        &[
            "*.dtd",
            "*.rng",
            "*.sch",
            "*.xhtml",
            "*.xjb",
            "*.xml",
            "*.xml.dist",
            "*.xsd",
            "*.xsl",
            "*.xslt",
        ],
    ),
    ("yaml", &["*.yaml", "*.yml"]),
];

const RIPGREP_MARKDOWN: &[&str] = &[
    "*.markdown",
    "*.md",
    "*.mdown",
    "*.mdwn",
    "*.mdx",
    "*.mkd",
    "*.mkdn",
];

/// The globs a `{a,b}` alternation stands for, nested groups included. None
/// for an unclosed group or more alternatives than a search states by hand.
fn brace_alternatives(glob: &str) -> Option<Vec<String>> {
    let Some(open) = glob.find('{') else {
        return (!glob.contains('}')).then(|| vec![glob.to_owned()]);
    };
    let mut depth = 0;
    let mut commas = Vec::new();
    let mut close = None;
    for (at, character) in glob[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' if depth == 1 => {
                close = Some(open + at);
                break;
            }
            '}' => depth -= 1,
            ',' if depth == 1 => commas.push(open + at),
            _ => {}
        }
    }
    let close = close?;
    let mut alternatives = Vec::new();
    let mut start = open + 1;
    for end in commas.into_iter().chain([close]) {
        let joined = format!(
            "{}{}{}",
            &glob[..open],
            &glob[start..end],
            &glob[close + 1..]
        );
        alternatives.extend(brace_alternatives(&joined)?);
        if alternatives.len() > 64 {
            return None;
        }
        start = end + 1;
    }
    Some(alternatives)
}

/// A listed path relative to the observed `root` it lies below, under the
/// root's real path or, failing that, its resolved one. None for the root
/// itself and for a path outside it.
pub(super) fn path_below_observed_root<'a>(
    root: &nah_proto::observation::PathObservation,
    path: &'a nah_proto::ctx::AbsolutePath,
) -> Option<&'a str> {
    [root.realpath(), Some(root.resolved())]
        .into_iter()
        .flatten()
        .find_map(|base| {
            path.as_str()
                .strip_prefix(base.as_str().trim_end_matches('/'))
                .and_then(|rest| rest.strip_prefix('/'))
        })
}

/// Python's fnmatch over `*` (any run, `/` included), `?` (one character),
/// bracket classes and literal characters.
fn fnmatch(glob: &str, text: &str) -> bool {
    let (glob, text) = (
        glob.chars().collect::<Vec<_>>(),
        text.chars().collect::<Vec<_>>(),
    );
    let (mut g, mut t) = (0, 0);
    // The last `*` seen and the text position it currently stops at.
    let mut star = None;
    while t < text.len() {
        // Where the glob continues once its element at `g` takes `text[t]`.
        let taken = match glob.get(g) {
            Some('*') => {
                star = Some((g, t));
                g += 1;
                continue;
            }
            Some('?') => Some(g + 1),
            Some('[') => match bracket_class(&glob, g, text[t]) {
                Some((holds, after)) => holds.then_some(after),
                None => (text[t] == '[').then_some(g + 1),
            },
            Some(&character) => (character == text[t]).then_some(g + 1),
            None => None,
        };
        match (taken, star) {
            (Some(next), _) => {
                g = next;
                t += 1;
            }
            (None, Some((star_at, stop))) => {
                g = star_at + 1;
                t = stop + 1;
                star = Some((star_at, stop + 1));
            }
            (None, None) => return false,
        }
    }
    glob[g..].iter().all(|character| *character == '*')
}

/// Whether the fnmatch bracket class opening at `glob[open]` holds
/// `character`, and the index after its closing `]`. A leading `!` negates
/// the class, a `]` placed first is a member, and `a-z` is a range. None when
/// no `]` closes the class: fnmatch then reads the `[` as itself.
fn bracket_class(glob: &[char], open: usize, character: char) -> Option<(bool, usize)> {
    let negated = glob.get(open + 1) == Some(&'!');
    let first = open + 1 + usize::from(negated);
    let close = (first + 1..glob.len()).find(|at| glob[*at] == ']')?;
    let members = &glob[first..close];
    let mut holds = false;
    let mut at = 0;
    while at < members.len() {
        if at + 2 < members.len() && members[at + 1] == '-' {
            holds |= (members[at]..=members[at + 2]).contains(&character);
            at += 3;
        } else {
            holds |= members[at] == character;
            at += 1;
        }
    }
    Some((holds != negated, close + 1))
}

#[cfg(test)]
mod tests {
    use super::{brace_alternatives, fnmatch};

    #[test]
    fn brace_alternatives_expand_nested_groups_and_refuse_unclosed_ones() {
        let expanded = |glob| brace_alternatives(glob).map(|globs| globs.join(" "));
        assert_eq!(expanded("*.{ts,tsx}").as_deref(), Some("*.ts *.tsx"));
        assert_eq!(
            expanded("{a,b{c,d}}.rs").as_deref(),
            Some("a.rs bc.rs bd.rs")
        );
        assert_eq!(expanded("plain").as_deref(), Some("plain"));
        assert_eq!(expanded("*.{ts"), None);
        assert_eq!(expanded("*.ts}"), None);
    }

    #[test]
    fn fnmatch_reads_bracket_classes_as_python_does() {
        for (glob, text, matches) in [
            ("*.[kp]e[ym]", "certs/server.key", true),
            ("*.[kp]e[ym]", "certs/server.pem", true),
            ("*.[kp]e[ym]", "certs/server.crt", false),
            ("file[0-9].txt", "file7.txt", true),
            ("file[0-9].txt", "filex.txt", false),
            ("[!a-c]x", "dx", true),
            ("[!a-c]x", "bx", false),
            // A `]` placed first is a member, and an unclosed `[` is itself.
            ("[]a]", "]", true),
            ("a[b", "a[b", true),
            ("a[b", "ab", false),
            ("*[s]erver.key", "certs/server.key", true),
        ] {
            assert_eq!(fnmatch(glob, text), matches, "{glob} against {text}");
        }
    }
}
