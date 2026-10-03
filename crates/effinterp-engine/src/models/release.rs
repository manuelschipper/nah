//! Release tools that publish packages: lerna, Changesets, semantic-release,
//! np and release-it for npm projects; PDM, Rye and maturin for PyPI; and
//! cargo-release and cargo-workspaces, which the cargo model enters. Which
//! packages, versions and registry a release publishes comes from project
//! configuration and history that are not read here, so an active release is
//! a publication request for an unresolved artifact plus boundaries.
//!
//! A release is suppressed (a dry run, a skipped publish, or cargo-release
//! without `--execute`) only by the effective value of exactly recognized
//! flags, read in argument order with negations and explicit values, the last
//! one winning. Any option this reading does not recognize, or any symbolic
//! word, keeps the publication request.

use std::collections::BTreeMap;

use effinterp_proto::{AttrValue, BoundaryReason, ProvenanceRef, RequestAssurance};

use super::artifact::{artifact_boundary, artifact_environment_boundary, mutation, unknown};
use crate::builder::PlanBuilder;
use crate::exec::dispatch_program_name;
use crate::models::common::{Attrs, arg_effect, reviewed_source_node};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

pub(crate) fn release_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(ReleaseTools)]
}

struct ReleaseTools;

/// One option a tool's parser recognizes: its setting key, long spellings
/// without `--` (aliases included), short letter, and whether it takes a
/// value.
pub(super) struct Opt {
    pub key: &'static str,
    pub long: &'static [&'static str],
    pub short: Option<char>,
    pub value: bool,
}

const fn flag_opt(key: &'static str, long: &'static [&'static str], short: Option<char>) -> Opt {
    Opt {
        key,
        long,
        short,
        value: false,
    }
}

const fn valued(key: &'static str, long: &'static [&'static str], short: Option<char>) -> Opt {
    Opt {
        key,
        long,
        short,
        value: true,
    }
}

/// How a tool's parser reads boolean flags beyond their bare spelling.
#[derive(Clone, Copy)]
pub(super) struct Style {
    /// `--no-<long>` sets the flag false (yargs, meow, `parseArgs` with
    /// `allowNegative`).
    pub negatable: bool,
    /// `--<long>=true` and `--<long>=false` set it (yargs, meow).
    pub inline_boolean: bool,
}

const YARGS: Style = Style {
    negatable: true,
    inline_boolean: true,
};
const PARSE_ARGS: Style = Style {
    negatable: true,
    inline_boolean: false,
};
pub(super) const CLAP: Style = Style {
    negatable: false,
    inline_boolean: false,
};

/// The effective boolean settings of an option list, and whether any word
/// was not understood.
#[derive(Default)]
pub(super) struct Settings {
    values: BTreeMap<&'static str, bool>,
    pub uncertain: bool,
}

impl Settings {
    pub fn get(&self, key: &str) -> Option<bool> {
        self.values.get(key).copied()
    }
}

/// Reads the option at `words[index]`, recording a boolean setting, and
/// returns how many words it spans; `None` when it is not recognized.
fn read_option(
    words: &[Word],
    index: usize,
    options: &[Opt],
    style: Style,
    settings: &mut Settings,
) -> Option<usize> {
    let word = words[index].as_literal()?;
    let following = || words.get(index + 1).and_then(Word::as_literal);
    // A separate `true` or `false` after a flag is read differently by
    // different parsers.
    let settle = |settings: &mut Settings, key, value| {
        if matches!(following(), Some("true" | "false")) {
            settings.uncertain = true;
        }
        settings.values.insert(key, value);
    };
    if let Some(long) = word.strip_prefix("--") {
        let (name, inline) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        if let Some(option) = options.iter().find(|option| option.long.contains(&name)) {
            if option.value {
                return match inline {
                    Some(_) => Some(1),
                    None => following().map(|_| 2),
                };
            }
            match inline {
                None => settle(settings, option.key, true),
                Some(value @ ("true" | "false")) if style.inline_boolean => {
                    settings.values.insert(option.key, value == "true");
                }
                Some(_) => return None,
            }
            return Some(1);
        }
        let negated = name.strip_prefix("no-").filter(|_| style.negatable)?;
        let option = options
            .iter()
            .find(|option| !option.value && option.long.contains(&negated))?;
        if inline.is_some() {
            return None;
        }
        settle(settings, option.key, false);
        return Some(1);
    }
    // A short cluster: boolean letters, optionally ending in one value
    // letter whose value is the rest of the word or the next word.
    let letters = word
        .strip_prefix('-')
        .filter(|letters| !letters.is_empty())?;
    for (offset, letter) in letters.char_indices() {
        let option = options.iter().find(|option| option.short == Some(letter))?;
        if option.value {
            return if offset + letter.len_utf8() < letters.len() {
                Some(1)
            } else {
                following().map(|_| 2)
            };
        }
        settle(settings, option.key, true);
    }
    Some(1)
}

/// Reads the options among `words`: operands are skipped, `--` ends the
/// options, and an unrecognized option or a symbolic word makes the reading
/// uncertain.
fn read_options(words: &[Word], options: &[Opt], style: Style) -> Settings {
    let mut settings = Settings::default();
    let mut index = 0;
    while index < words.len() {
        match words[index].as_literal() {
            None => {
                settings.uncertain = true;
                index += 1;
            }
            Some("--") => {
                settings.uncertain |= words[index + 1..]
                    .iter()
                    .any(|word| word.as_literal().is_none());
                break;
            }
            Some(word) if word.starts_with('-') && word != "-" => {
                match read_option(words, index, options, style, &mut settings) {
                    Some(width) => index += width,
                    None => {
                        settings.uncertain = true;
                        index += 1;
                    }
                }
            }
            Some(_) => index += 1,
        }
    }
    settings
}

/// The argv index after `verb`, read past the tool's global options, and whether an
/// option or symbolic word before it was not understood. With such a word the
/// verb is the first later literal equal to it, which may be the value of the
/// unknown option: the reading is uncertain, and the publication stays.
fn select_verb(
    ctx: &InvocationCtx,
    globals: &[Opt],
    style: Style,
    verbs: &[&str],
) -> Option<(usize, bool)> {
    let words = &ctx.argv[1..];
    let mut settings = Settings::default();
    let mut index = 0;
    while index < words.len() {
        match words[index].as_literal() {
            None => {
                settings.uncertain = true;
                index += 1;
            }
            Some("--") => return None,
            Some(word) if word.starts_with('-') => {
                match read_option(words, index, globals, style, &mut settings) {
                    Some(width) => index += width,
                    None => {
                        settings.uncertain = true;
                        index += 1;
                    }
                }
            }
            Some(word) if verbs.contains(&word) => return Some((index + 2, settings.uncertain)),
            Some(_) if settings.uncertain => index += 1,
            Some(_) => return None,
        }
    }
    None
}

/// One release command's publication surface.
pub(super) struct Release {
    /// The tool, recorded as the package manager.
    pub tool: &'static str,
    /// The ecosystem the tool publishes to, when it has only one.
    pub ecosystem: Option<&'static str>,
    /// The argv index of the first word after the publishing command.
    pub start: usize,
    /// Words before the command that were not understood.
    pub uncertain: bool,
    /// The options the publishing command recognizes.
    pub options: &'static [Opt],
    pub style: Style,
    /// Whether settings read without uncertainty prove no upload happens.
    pub suppressed: fn(&Settings) -> bool,
    /// The reviewed documentation the reading follows.
    pub source: &'static str,
}

fn never(_: &Settings) -> bool {
    false
}

fn dry_run(settings: &Settings) -> bool {
    settings.get("dry-run") == Some(true)
}

fn np_suppressed(settings: &Settings) -> bool {
    dry_run(settings)
        || settings.get("publish") == Some(false)
        || settings.get("release-draft-only") == Some(true)
}

// Global options each tool reads before its subcommand.
const LERNA_GLOBALS: &[Opt] = &[
    valued("loglevel", &["loglevel"], None),
    valued("concurrency", &["concurrency"], None),
    valued("max-buffer", &["max-buffer"], None),
    flag_opt("reject-cycles", &["reject-cycles"], None),
    flag_opt("progress", &["progress"], None),
    flag_opt("sort", &["sort"], None),
];
const PDM_GLOBALS: &[Opt] = &[
    flag_opt("verbose", &["verbose"], Some('v')),
    flag_opt("quiet", &["quiet"], Some('q')),
    flag_opt("ignore-python", &["ignore-python"], Some('I')),
    valued("config", &["config"], Some('c')),
    valued("project", &["project"], Some('p')),
];

// Options of the commands whose settings can suppress a publication.
const SEMANTIC_RELEASE: &[Opt] = &[
    flag_opt("dry-run", &["dry-run"], Some('d')),
    flag_opt("ci", &["ci"], None),
    flag_opt("debug", &["debug"], None),
    valued("branches", &["branches"], Some('b')),
    valued("repository-url", &["repository-url"], Some('r')),
    valued("tag-format", &["tag-format"], Some('t')),
    valued("plugins", &["plugins"], Some('p')),
    valued("extends", &["extends"], Some('e')),
];
const NP: &[Opt] = &[
    flag_opt("dry-run", &["dry-run", "preview"], None),
    flag_opt("publish", &["publish"], None),
    flag_opt("release-draft-only", &["release-draft-only"], None),
    flag_opt("release-draft", &["release-draft"], None),
    flag_opt("release-notes", &["release-notes"], None),
    flag_opt("any-branch", &["any-branch"], None),
    flag_opt("cleanup", &["cleanup"], None),
    flag_opt("tests", &["tests"], None),
    flag_opt("yolo", &["yolo"], None),
    flag_opt("2fa", &["2fa"], None),
    flag_opt("provenance", &["provenance"], None),
    flag_opt("stage", &["stage"], None),
    valued("branch", &["branch"], None),
    valued("tag", &["tag"], None),
    valued("contents", &["contents"], None),
    valued("test-script", &["test-script"], None),
    valued("message", &["message"], None),
    valued("package-manager", &["package-manager"], None),
    valued("remote", &["remote"], None),
];
const RELEASE_IT: &[Opt] = &[
    flag_opt("dry-run", &["dry-run"], Some('d')),
    flag_opt("ci", &["ci"], None),
    flag_opt("verbose", &["verbose"], Some('V')),
    flag_opt("only-version", &["only-version"], None),
    valued("increment", &["increment"], Some('i')),
    valued("config", &["config"], Some('c')),
    valued("preRelease", &["preRelease"], None),
];
pub(super) const CARGO_RELEASE: &[Opt] = &[
    flag_opt("execute", &["execute"], Some('x')),
    flag_opt("no-publish", &["no-publish"], None),
    flag_opt("no-push", &["no-push"], None),
    flag_opt("no-tag", &["no-tag"], None),
    flag_opt("no-verify", &["no-verify"], None),
    flag_opt("no-confirm", &["no-confirm"], None),
    flag_opt("workspace", &["workspace", "all"], None),
    flag_opt("verbose", &["verbose"], Some('v')),
    flag_opt("quiet", &["quiet"], Some('q')),
    valued("package", &["package"], Some('p')),
    valued("exclude", &["exclude"], None),
    valued("manifest-path", &["manifest-path"], None),
    valued("config", &["config"], Some('c')),
    valued("registry", &["registry"], None),
    valued("metadata", &["metadata"], None),
];
pub(super) const CARGO_WORKSPACES_PUBLISH: &[Opt] = &[
    flag_opt("dry-run", &["dry-run"], None),
    flag_opt("yes", &["yes"], Some('y')),
    flag_opt("no-verify", &["no-verify"], None),
    flag_opt("publish-as-is", &["publish-as-is"], None),
    flag_opt("from-git", &["from-git"], None),
    flag_opt("allow-dirty", &["allow-dirty"], None),
    flag_opt("skip-published", &["skip-published"], None),
    flag_opt("no-git-commit", &["no-git-commit"], None),
    flag_opt("no-git-push", &["no-git-push"], None),
    flag_opt("no-git-tag", &["no-git-tag"], None),
    flag_opt("exact", &["exact"], None),
    flag_opt("all", &["all"], Some('a')),
    valued("registry", &["registry"], None),
    valued("token", &["token"], None),
    valued("allow-branch", &["allow-branch"], None),
    valued("pre-id", &["pre-id"], None),
    valued("git-remote", &["git-remote"], None),
    valued("message", &["message"], Some('m')),
];

pub(super) fn cargo_release_suppressed(settings: &Settings) -> bool {
    settings.get("execute") != Some(true) || settings.get("no-publish") == Some(true)
}

pub(super) fn cargo_workspaces_suppressed(settings: &Settings) -> bool {
    dry_run(settings)
}

/// The release command `argv` runs, when it publishes.
fn release(ctx: &InvocationCtx) -> Option<Release> {
    let tool = ctx.argv.first().and_then(dispatch_program_name)?;
    let (tool, ecosystem, (start, uncertain), options, style, suppressed, source): (
        _,
        _,
        _,
        &[Opt],
        _,
        fn(&Settings) -> bool,
        _,
    ) = match tool {
        "lerna" => (
            "lerna",
            Some("npm"),
            select_verb(ctx, LERNA_GLOBALS, YARGS, &["publish"])?,
            &[],
            YARGS,
            never,
            "https://github.com/lerna/lerna/tree/main/libs/commands/publish#readme",
        ),
        "changeset" => (
            "changeset",
            Some("npm"),
            select_verb(ctx, &[], YARGS, &["publish"])?,
            &[],
            YARGS,
            never,
            "https://github.com/changesets/changesets/tree/main/packages/cli#publish",
        ),
        "semantic-release" => (
            "semantic-release",
            None,
            (1, false),
            SEMANTIC_RELEASE,
            YARGS,
            dry_run,
            "https://github.com/semantic-release/semantic-release/blob/master/cli.js",
        ),
        "np" => (
            "np",
            Some("npm"),
            (1, false),
            NP,
            YARGS,
            np_suppressed,
            "https://github.com/sindresorhus/np/blob/main/source/cli-implementation.js",
        ),
        "release-it" => (
            "release-it",
            None,
            (1, false),
            RELEASE_IT,
            PARSE_ARGS,
            dry_run,
            "https://github.com/release-it/release-it/blob/main/lib/args.js",
        ),
        "pdm" => (
            "pdm",
            Some("pypi"),
            select_verb(ctx, PDM_GLOBALS, CLAP, &["publish"])?,
            &[],
            CLAP,
            never,
            "https://pdm-project.org/latest/reference/cli/",
        ),
        "rye" => (
            "rye",
            Some("pypi"),
            select_verb(ctx, &[], CLAP, &["publish"])?,
            &[],
            CLAP,
            never,
            "https://rye.astral.sh/guide/commands/publish/",
        ),
        "maturin" => (
            "maturin",
            Some("pypi"),
            select_verb(ctx, &[], CLAP, &["publish", "upload"])?,
            &[],
            CLAP,
            never,
            "https://www.maturin.rs/distribution#uploading-with-maturin",
        ),
        _ => return None,
    };
    Some(Release {
        tool,
        ecosystem,
        start,
        uncertain,
        options,
        style,
        suppressed,
        source,
    })
}

/// Models `release`: a help request prints only; otherwise the tool's hooks,
/// plugins or builds are a boundary, and it publishes unless its settings,
/// read without uncertainty, prove no upload.
pub(super) fn release_publication(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    release: &Release,
) {
    let words = &ctx.argv[release.start..];
    if !release.uncertain
        && let [word] = words
        && matches!(word.as_literal(), Some("-h" | "--help"))
    {
        return;
    }
    let node = reviewed_source_node(
        builder,
        ctx,
        node,
        &format!("release/{}@2026-09:{}", release.tool, release.source),
    );
    // A tool without suppressing options publishes whatever its options say;
    // only a symbolic word leaves its arguments unread.
    let settings = if release.options.is_empty() {
        Settings {
            uncertain: words.iter().any(|word| word.as_literal().is_none()),
            ..Settings::default()
        }
    } else {
        read_options(words, release.options, release.style)
    };
    let uncertain = release.uncertain || settings.uncertain;
    if uncertain {
        artifact_boundary(
            builder,
            node,
            &["artifact", "network", "filesystem", "process"],
            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            "release arguments this reading does not understand may change whether and what it publishes",
        );
    }
    artifact_environment_boundary(
        builder,
        node,
        &["artifact", "filesystem", "network", "process"],
        BoundaryReason::PACKAGE_SCRIPTS,
        &format!(
            "{} runs project hooks, plugins or builds that may execute arbitrary code",
            release.tool
        ),
    );
    if !uncertain && (release.suppressed)(&settings) {
        arg_effect(
            builder,
            ctx,
            node,
            (release.start - 1) as u32,
            "network.request",
            unresolved_resource("network"),
            Attrs::new(),
        );
        artifact_environment_boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::REVIEWED_COMMAND_SURFACE,
            "a release dry run or skipped publish does not upload an artifact",
        );
        return;
    }
    artifact_boundary(
        builder,
        node,
        &["artifact", "filesystem"],
        BoundaryReason::MODEL_COVERAGE,
        &format!(
            "{} selects the packages, versions and registry from project configuration",
            release.tool
        ),
    );
    let mut attrs = Attrs::new();
    attrs.insert("active".into(), AttrValue::Bool(true));
    attrs.insert("dry_run".into(), AttrValue::Bool(false));
    attrs.insert(
        "package_manager".into(),
        AttrValue::String(release.tool.into()),
    );
    attrs.insert("action".into(), AttrValue::String("publish".into()));
    attrs.insert("selection".into(), AttrValue::String("unknown".into()));
    if let Some(ecosystem) = release.ecosystem {
        attrs.insert("ecosystem".into(), AttrValue::String(ecosystem.into()));
    }
    mutation(
        builder,
        ctx,
        node,
        None,
        release.start - 1,
        "artifact.publish",
        unknown(),
        attrs,
        Some(RequestAssurance::Exact),
    );
}

impl CommandModel for ReleaseTools {
    fn domains(&self) -> &'static [&'static str] {
        &["artifact", "filesystem", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "package/release-tools@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &[
            "lerna",
            "changeset",
            "semantic-release",
            "np",
            "release-it",
            "pdm",
            "rye",
            "maturin",
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        match release(ctx) {
            Some(release) => release_publication(builder, ctx, node, &release),
            None => artifact_boundary(
                builder,
                node,
                &["artifact", "filesystem", "network", "process"],
                BoundaryReason::UNMODELED_SUBCOMMAND,
                "this release tool command is unmodeled",
            ),
        }
    }
}
