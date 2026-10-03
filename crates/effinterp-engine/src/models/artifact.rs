use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    ArtifactEcosystem, ArtifactReference, AttrValue, Boundary, BoundaryClass, BoundaryReason,
    BoundaryScope, CoverageLevel, Domain, Effect, ExecutionEdgeKind, ExecutionNodeRef,
    ExecutionRealm, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::exec::program_name;
use crate::models::common::{Attrs, arg_effect, arg_node};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{SourceResolution, Transition, word_resource};
use crate::value::unresolved_resource;
use crate::word::Word;

struct GithubRelease {
    owner: Box<dyn CommandModel>,
}

struct PackagePublicationOwner {
    owner: Box<dyn CommandModel>,
}

pub(super) fn with_releases(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(GithubRelease { owner })
}

pub(super) fn with_package_publication(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(PackagePublicationOwner { owner })
}

fn literal(value: &str) -> ResourceExpr {
    ResourceExpr::Literal {
        value: value.into(),
    }
}

pub(super) fn unknown() -> ResourceExpr {
    unresolved_resource("artifact")
}

pub(super) fn boundary(
    builder: &mut PlanBuilder,
    node: ProvenanceRef,
    domains: &[&str],
    reason: BoundaryReason,
    detail: &str,
) {
    scoped_boundary(
        builder,
        node,
        domains,
        reason,
        BoundaryScope::Invocation,
        detail,
    );
}

/// A gap in what the registry, its configuration, or a package's own scripts
/// do once the invocation runs, rather than in the invocation's own input.
pub(super) fn environment_boundary(
    builder: &mut PlanBuilder,
    node: ProvenanceRef,
    domains: &[&str],
    reason: BoundaryReason,
    detail: &str,
) {
    scoped_boundary(
        builder,
        node,
        domains,
        reason,
        BoundaryScope::Environment,
        detail,
    );
}

fn scoped_boundary(
    builder: &mut PlanBuilder,
    node: ProvenanceRef,
    domains: &[&str],
    reason: BoundaryReason,
    scope: BoundaryScope,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason,
        class: BoundaryClass::Unmodeled,
        scope,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
        provenance: vec![node],
        limit: None,
        detail: Some(detail.into()),
    });
    for domain in domains {
        builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
    }
}

// Handwritten models pin their reviewed source in the same model-application
// provenance used by the command catalog. Analysis never fetches these sources.
pub(super) fn reviewed(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    source: &str,
) -> ProvenanceRef {
    let mut provenance = vec![node];
    for index in 1..ctx.argv.len() {
        provenance.push(arg_node(builder, ctx, index as u32));
    }
    builder.node(
        ProvenanceKind::ModelApplication {
            model: source.into(),
        },
        &provenance,
    )
}

#[derive(Default)]
struct Options {
    values: BTreeMap<String, Word>,
    operands: Vec<usize>,
    invalid: bool,
}

impl Options {
    fn boolean(&self, name: &str) -> bool {
        self.values.get(name).and_then(Word::as_literal) == Some("true")
    }
    fn text(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(Word::as_literal)
    }
}

/// npm 11's configuration keys whose values are not booleans, from its
/// config definitions. nopt reads the word after a bare `--<key>` as the
/// value; every other key, npm's booleans and undefined keys alike, takes at
/// most a following `true` or `false`.
const NPM_VALUE_KEYS: &[&str] = &[
    "_auth",
    "access",
    "also",
    "audit-level",
    "auth-type",
    "before",
    "ca",
    "cache",
    "cache-max",
    "cache-min",
    "cafile",
    "call",
    "cert",
    "cidr",
    "cpu",
    "depth",
    "diff",
    "diff-dst-prefix",
    "diff-src-prefix",
    "diff-unified",
    "editor",
    "expect-result-count",
    "fetch-retries",
    "fetch-retry-factor",
    "fetch-retry-maxtimeout",
    "fetch-retry-mintimeout",
    "fetch-timeout",
    "git",
    "globalconfig",
    "heading",
    "https-proxy",
    "include",
    "init-author-email",
    "init-author-name",
    "init-author-url",
    "init-license",
    "init-module",
    "init-type",
    "init-version",
    "install-strategy",
    "key",
    "libc",
    "local-address",
    "location",
    "lockfile-version",
    "loglevel",
    "logs-dir",
    "logs-max",
    "maxsockets",
    "message",
    "node-gyp",
    "node-options",
    "noproxy",
    "omit",
    "only",
    "os",
    "otp",
    "pack-destination",
    "package",
    "prefix",
    "preid",
    "provenance-file",
    "proxy",
    "registry",
    "replace-registry-host",
    "save-prefix",
    "sbom-format",
    "sbom-type",
    "scope",
    "script-shell",
    "searchexclude",
    "searchlimit",
    "searchopts",
    "searchstaleness",
    "shell",
    "sso-poll-frequency",
    "sso-type",
    "tag",
    "tag-version-prefix",
    "umask",
    "user-agent",
    "userconfig",
    "viewer",
    "which",
    "workspace",
];

/// npm 11's boolean configuration keys, including those whose type also
/// admits a string (`browser`, `color`). A key in neither list is not
/// understood.
const NPM_BOOLEAN_KEYS: &[&str] = &[
    "all",
    "allow-same-version",
    "audit",
    "bin-links",
    "browser",
    "color",
    "commit-hooks",
    "description",
    "dev",
    "diff-ignore-all-space",
    "diff-name-only",
    "diff-no-prefix",
    "diff-text",
    "dry-run",
    "engine-strict",
    "expect-results",
    "force",
    "foreground-scripts",
    "format-package-lock",
    "fund",
    "git-tag-version",
    "global",
    "global-style",
    "if-present",
    "ignore-scripts",
    "include-staged",
    "include-workspace-root",
    "init-private",
    "install-links",
    "json",
    "legacy-bundling",
    "legacy-peer-deps",
    "link",
    "long",
    "offline",
    "omit-lockfile-deps",
    "optional",
    "package-lock",
    "package-lock-only",
    "parseable",
    "prefer-dedupe",
    "prefer-offline",
    "prefer-online",
    "production",
    "progress",
    "provenance",
    "read-only",
    "rebuild-bundle",
    "save",
    "save-bundle",
    "save-dev",
    "save-exact",
    "save-optional",
    "save-peer",
    "save-prod",
    "shrinkwrap",
    "sign-git-commit",
    "sign-git-tag",
    "strict-peer-deps",
    "strict-ssl",
    "timing",
    "unicode",
    "update-notifier",
    "usage",
    "version",
    "versions",
    "workspaces",
    "workspaces-update",
    "yes",
];

/// npm 11's shorthands, which nopt expands before it reads a flag.
const NPM_SHORTHANDS: &[(&str, &[&str])] = &[
    ("?", &["--usage"]),
    ("B", &["--save-bundle"]),
    ("C", &["--prefix"]),
    ("D", &["--save-dev"]),
    ("E", &["--save-exact"]),
    ("H", &["--usage"]),
    ("O", &["--save-optional"]),
    ("P", &["--save-prod"]),
    ("S", &["--save"]),
    ("a", &["--all"]),
    ("c", &["--call"]),
    ("d", &["--loglevel", "info"]),
    ("dd", &["--loglevel", "verbose"]),
    ("ddd", &["--loglevel", "silly"]),
    ("desc", &["--description"]),
    ("enjoy-by", &["--before"]),
    ("f", &["--force"]),
    ("g", &["--global"]),
    ("h", &["--usage"]),
    ("help", &["--usage"]),
    ("iwr", &["--include-workspace-root"]),
    ("l", &["--long"]),
    ("local", &["--no-global"]),
    ("m", &["--message"]),
    ("n", &["--no-yes"]),
    ("no", &["--no-yes"]),
    ("p", &["--parseable"]),
    ("porcelain", &["--parseable"]),
    ("q", &["--loglevel", "warn"]),
    ("quiet", &["--loglevel", "warn"]),
    ("readonly", &["--read-only"]),
    ("reg", &["--registry"]),
    ("s", &["--loglevel", "silent"]),
    ("silent", &["--loglevel", "silent"]),
    ("v", &["--version"]),
    ("verbose", &["--loglevel", "verbose"]),
    ("w", &["--workspace"]),
    ("ws", &["--workspaces"]),
    ("y", &["--yes"]),
];

fn npm_key(key: &str) -> bool {
    NPM_VALUE_KEYS.contains(&key) || NPM_BOOLEAN_KEYS.contains(&key)
}

/// npm's command line under one conservative reading. It understands only
/// exact spellings of npm 11's keys: `--<value-key> <value>`,
/// `--<value-key>=<value>`, `--<boolean>`, `--<boolean>=true|false`,
/// `--<boolean> true|false`, `--no-<boolean>` and a whole-word shorthand.
/// Any other option word (an abbreviation, a combined shorthand, a repeated
/// negation, a case variant, an undefined or symbolic key) is unresolved: it
/// is read as nopt reads an undefined key, taking at most a following `true`
/// or `false`, and the operand after it may be its value instead. Callers
/// keep the request or lifecycle such a word could hide and add an
/// unresolved-arguments boundary; nothing it could set counts as proven.
#[derive(Default)]
pub(super) struct NpmOptions {
    values: BTreeMap<String, Word>,
    /// Value keys named in an exact spelling, whether or not their value was
    /// read.
    named: BTreeSet<String>,
    booleans: BTreeMap<String, bool>,
    /// Booleans whose last spelling sets them true without a negation: a
    /// bare `--<key>`, `--<key>=true`, `--<key> true`, or a shorthand.
    proven: BTreeSet<String>,
    /// npm's repeatable `--workspace` selections.
    workspaces: Vec<Word>,
    pub(super) operands: Vec<usize>,
    /// Words read as operands that npm may not read as operands: one right
    /// after an unresolved option may be its value, and a symbolic one may
    /// expand to an option.
    maybe_values: BTreeSet<usize>,
    /// An option word this reading does not understand appeared.
    pub(super) unresolved: bool,
    /// A symbolic word appeared, which may expand to any option or to `--`.
    symbolic: bool,
}

/// How far npm's layered configuration establishes one boolean key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum NpmSetting {
    /// Nothing at this layer sets it.
    Unset,
    /// Set true in one of the exact spellings.
    Proven,
    /// Set false in one of the exact spellings.
    False,
    /// Set, or possibly set, in a way this reading does not prove.
    Unproven,
}

impl NpmOptions {
    fn text(&self, key: &str) -> Option<&str> {
        self.values.get(key).and_then(Word::as_literal)
    }
    /// The command line's setting of the boolean `key`.
    pub(super) fn setting(&self, key: &str) -> NpmSetting {
        if self.unresolved || self.symbolic {
            NpmSetting::Unproven
        } else if self.proven.contains(key) {
            NpmSetting::Proven
        } else {
            match self.booleans.get(key) {
                None => NpmSetting::Unset,
                Some(false) => NpmSetting::False,
                Some(true) => NpmSetting::Unproven,
            }
        }
    }
    /// Whether npm certainly prints usage or its version and exits.
    pub(super) fn prints_only(&self) -> bool {
        ["usage", "version", "versions"]
            .iter()
            .any(|key| self.setting(key) == NpmSetting::Proven)
    }
    /// Whether npm runs the command from workspace directories.
    pub(super) fn selects_workspaces(&self) -> bool {
        !self.workspaces.is_empty() || self.booleans.get("workspaces") == Some(&true)
    }
    /// Whether a global install, `--location=global`, or a literal prefix
    /// naming another directory moves the package away from the current
    /// one. A symbolic or missing value leaves the package here.
    pub(super) fn relocated(&self, ctx: &InvocationCtx) -> bool {
        self.booleans.get("global") == Some(&true)
            || self.text("location") == Some("global")
            || self
                .text("prefix")
                .is_some_and(|prefix| !npm_prefix_is_cwd(ctx, prefix))
    }
    /// Whether the command line names the value key `key`.
    pub(super) fn names(&self, key: &str) -> bool {
        self.named.contains(key)
    }
    pub(super) fn value(&self, key: &str) -> Option<&Word> {
        self.values.get(key)
    }
    /// Whether npm may not read the operand at `index` as an operand.
    pub(super) fn maybe_value(&self, index: usize) -> bool {
        self.maybe_values.contains(&index)
    }
    /// The first word among the operands from `from` that npm may read as
    /// the next operand and that is one of `names`: the first operand, or a
    /// later one while each before it may be an option's value.
    pub(super) fn select<'a>(
        &self,
        ctx: &'a InvocationCtx,
        from: usize,
        names: &[&str],
    ) -> Option<(usize, &'a str)> {
        for &index in self.operands.iter().filter(|index| **index >= from) {
            if let Some(word) = ctx.argv[index].as_literal()
                && names.contains(&word)
            {
                return Some((index, word));
            }
            if !self.maybe_value(index) {
                break;
            }
        }
        None
    }
}

/// npm's command line from `start`, as [`NpmOptions`] reads it.
pub(super) fn npm_options(ctx: &InvocationCtx, start: usize) -> NpmOptions {
    let mut out = NpmOptions::default();
    let mut index = start;
    let mut positional = false;
    // The last word was an unresolved option without an attached value.
    let mut pending = false;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        index += 1;
        let after_unresolved = std::mem::take(&mut pending);
        if positional || !word.literal_prefix().starts_with('-') || word.as_literal() == Some("-") {
            let symbolic = !positional && word.as_literal().is_none();
            out.symbolic |= symbolic;
            if after_unresolved || symbolic {
                out.maybe_values.insert(index - 1);
            }
            out.operands.push(index - 1);
            continue;
        }
        if word.as_literal() == Some("--") {
            positional = true;
            continue;
        }
        let (flag, attached) = match word.split_assignment() {
            Some((key, value)) => (key, Some(value)),
            None => match word.as_literal() {
                Some(flag) => (flag, None),
                None => {
                    out.unresolved = true;
                    out.symbolic = true;
                    pending = true;
                    continue;
                }
            },
        };
        let bare = flag.trim_start_matches('-');
        let shorthand = NPM_SHORTHANDS
            .iter()
            .find(|(short, _)| *short == bare && !npm_key(bare));
        // nopt splits a word of single-letter shorthands such as `-fs`. Only
        // the neutral force and log-level letters are read here.
        if shorthand.is_none()
            && attached.is_none()
            && !flag.starts_with("--")
            && bare.len() > 1
            && bare.bytes().all(|letter| b"fsqd".contains(&letter))
        {
            for letter in bare.bytes() {
                if letter == b'f' {
                    out.booleans.insert("force".into(), true);
                    out.proven.insert("force".into());
                } else {
                    let level = match letter {
                        b's' => "silent",
                        b'q' => "warn",
                        _ => "info",
                    };
                    out.values.insert("loglevel".into(), Word::literal(level));
                }
            }
            continue;
        }
        let (key, value) = match shorthand {
            Some((_, [key, value])) if attached.is_none() => {
                (&key[2..], Some(Word::literal(*value)))
            }
            Some((_, [key])) => (&key[2..], attached),
            Some(_) => ("", None),
            None => match flag.strip_prefix("--") {
                Some(key) => (key, attached),
                None => ("", None),
            },
        };
        let negated = key
            .strip_prefix("no-")
            .filter(|key| NPM_BOOLEAN_KEYS.contains(key));
        if let Some(key) = negated {
            if value.is_some() {
                out.unresolved = true;
                continue;
            }
            // nopt negates a following `true` or `false` too.
            let setting = match ctx.argv.get(index).and_then(Word::as_literal) {
                Some(given @ ("true" | "false")) => {
                    index += 1;
                    given == "false"
                }
                _ => false,
            };
            out.booleans.insert(key.into(), setting);
            out.proven.remove(key);
            continue;
        }
        if NPM_VALUE_KEYS.contains(&key) {
            out.named.insert(key.into());
            let value = match value {
                Some(value) => Some(value),
                // nopt takes the next word as the value, whatever it is,
                // unless it is `--`.
                None => match ctx.argv.get(index) {
                    Some(next) if next.as_literal() != Some("--") => {
                        index += 1;
                        Some(next.clone())
                    }
                    _ => None,
                },
            };
            match value {
                // An empty value, as an unset variable gives, is still a
                // value; one that looks like an option is not understood.
                Some(value) if value.as_literal().is_none_or(|text| !text.starts_with('-')) => {
                    if key == "workspace" {
                        out.workspaces.push(value);
                    } else {
                        out.values.insert(key.into(), value);
                    }
                }
                _ => out.unresolved = true,
            }
            continue;
        }
        // `browser` also takes any string, so a bare one may take the next
        // word; `color` takes only `always` besides a boolean.
        if NPM_BOOLEAN_KEYS.contains(&key) && !(value.is_none() && key == "browser") {
            let setting = match value.as_ref().map(Word::as_literal) {
                None => match ctx.argv.get(index).and_then(Word::as_literal) {
                    Some(given @ ("true" | "false")) => {
                        index += 1;
                        Some(given == "true")
                    }
                    Some("always") if key == "color" => {
                        index += 1;
                        Some(true)
                    }
                    _ => Some(true),
                },
                Some(Some("true")) => Some(true),
                Some(Some("false")) => Some(false),
                Some(Some("always")) if key == "color" => Some(true),
                Some(_) => None,
            };
            match setting {
                Some(setting) => {
                    out.booleans.insert(key.into(), setting);
                    if setting {
                        out.proven.insert(key.into());
                    } else {
                        out.proven.remove(key);
                    }
                }
                None => out.unresolved = true,
            }
            continue;
        }
        out.unresolved = true;
        if value.is_none() {
            if matches!(
                ctx.argv.get(index).and_then(Word::as_literal),
                Some("true" | "false")
            ) {
                index += 1;
            } else {
                pending = true;
            }
        }
    }
    out
}

/// Marks an npm request kept behind an option word this reading does not
/// understand, which may change its package, destination or suppression.
fn unrecognized_npm_options(builder: &mut PlanBuilder, node: ProvenanceRef) {
    boundary(
        builder,
        node,
        &["artifact", "network", "filesystem", "process"],
        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        "npm options this reading does not understand may change the request",
    );
}

/// Whether npm's literal `prefix` names the runtime cwd.
pub(super) fn npm_prefix_is_cwd(ctx: &InvocationCtx, prefix: &str) -> bool {
    fn components(path: &str) -> Vec<&str> {
        path.split('/').filter(|part| !part.is_empty()).collect()
    }
    let Some(cwd) = ctx.runtime_cwd else {
        return prefix.split('/').all(|part| part.is_empty() || part == ".");
    };
    let mut parts = if prefix.starts_with('/') {
        Vec::new()
    } else {
        components(cwd)
    };
    for part in prefix.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts == components(cwd)
}

/// An npm boolean configuration key set in the environment. npm reads every
/// nonempty `npm_config_*` variable, its prefix matched case-insensitively
/// and the rest lowercased with `_` after the first character read as `-`.
/// Only a value of exactly `true` or `1` proves it true, and exactly `false`
/// or `0` false; variables that disagree leave it unproven.
pub(super) fn npm_environment_setting(ctx: &InvocationCtx, key: &str) -> NpmSetting {
    let mut found = NpmSetting::Unset;
    for name in ctx.nest.environment_names() {
        let Some(rest) = name
            .get(..11)
            .filter(|prefix| prefix.eq_ignore_ascii_case("npm_config_"))
            .and_then(|_| name.get(11..))
        else {
            continue;
        };
        let normalized = rest
            .char_indices()
            .map(|(at, c)| if at > 0 && c == '_' { '-' } else { c })
            .collect::<String>()
            .to_lowercase();
        if rest.starts_with("//") || normalized != key {
            continue;
        }
        let setting = match ctx.environment_value(&name) {
            Some(ResourceExpr::Literal { value }) => match value.as_str() {
                "" => continue,
                "true" | "1" => NpmSetting::Proven,
                "false" | "0" => NpmSetting::False,
                _ => NpmSetting::Unproven,
            },
            _ => NpmSetting::Unproven,
        };
        found = match found {
            NpmSetting::Unset => setting,
            previous if previous == setting => setting,
            _ => NpmSetting::Unproven,
        };
    }
    found
}

// Parse values before collecting operands: a flag value is never an artifact.
fn options(
    ctx: &InvocationCtx,
    start: usize,
    booleans: &[&str],
    values: &[&str],
    aliases: &[(&str, &str)],
) -> Options {
    let mut out = Options::default();
    let mut index = start;
    let mut positional = false;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        let prefix = word.literal_prefix();
        if !positional && word.as_literal() == Some("--") {
            positional = true;
        } else if !positional && prefix.starts_with('-') {
            let (raw, attached) = word
                .split_assignment()
                .map_or((prefix, None), |(key, value)| (key, Some(value)));
            let name = aliases
                .iter()
                .find(|(alias, _)| *alias == raw)
                .map_or(raw, |(_, name)| *name);
            let value = if booleans.contains(&name) {
                let value = attached.unwrap_or_else(|| Word::literal("true"));
                if !matches!(value.as_literal(), Some("true" | "false")) {
                    out.invalid = true;
                }
                value
            } else if values.contains(&name) {
                if let Some(value) = attached {
                    value
                } else if ctx.argv.get(index + 1).is_some_and(|w| {
                    !w.literal_prefix().starts_with('-') || w.as_literal() == Some("-")
                }) {
                    index += 1;
                    ctx.argv[index].clone()
                } else {
                    out.invalid = true;
                    Word::literal("")
                }
            } else {
                out.invalid = true;
                index += 1;
                continue;
            };
            if value.as_literal() == Some("") {
                out.invalid = true;
            }
            if let Some(previous) = out.values.insert(name.into(), value.clone())
                && previous != value
            {
                out.invalid = true;
            }
        } else {
            out.operands.push(index);
        }
        index += 1;
    }
    out
}

fn artifact(
    ecosystem: ArtifactEcosystem,
    endpoint: ResourceExpr,
    name: ResourceExpr,
    reference: ArtifactReference,
) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::Artifact {
            ecosystem,
            endpoint: Box::new(endpoint),
            name: Box::new(name),
            reference: Box::new(reference),
        },
    }
}

// Package metadata is data, not an executable input. Observe it through the
// bounded source channel without manufacturing an execution gap when absent.
fn package_metadata(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    path: &str,
) -> Option<(String, serde_json::Value)> {
    let (origin, bytes) = observe_data_file(builder, ctx, path)?;
    serde_json::from_slice(&bytes)
        .ok()
        .map(|value| (origin, value))
}

/// Observes a data file relative to the runtime cwd, such as package metadata
/// or an npmrc, returning its origin and bytes. Absence is not a gap.
pub(super) fn observe_data_file(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    path: &str,
) -> Option<(String, Vec<u8>)> {
    if !builder.is_host_realm() {
        return None;
    }
    let candidate = crate::paths::join_source_path(ctx.runtime_cwd, path)?;
    let bytes = match ctx.nest.observe_source_search(
        builder,
        std::slice::from_ref(&candidate),
        SourcePurpose::InvocationInput,
    ) {
        crate::nest::SourceSearchObservation::Found { bytes, .. } => bytes,
        crate::nest::SourceSearchObservation::Refused(crate::SourceRefusal::Limit { limit }) => {
            builder.note_saturated(limit);
            return None;
        }
        _ => return None,
    };
    if !builder.budget().try_charge_steps(bytes.len() as u64) {
        builder.note_saturated("max_analysis_steps");
        return None;
    }
    Some((candidate.1, bytes))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn mutation(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    manifest: Option<ProvenanceRef>,
    index: usize,
    operation: &str,
    resource: ResourceExpr,
    attrs: Attrs,
    request: Option<effinterp_proto::RequestAssurance>,
) {
    let endpoint = match &resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact { endpoint, .. },
        } => match endpoint.as_ref() {
            ResourceExpr::Literal { value } => crate::models::net::parse_endpoint(value)
                .map(|identity| ResourceExpr::Concrete { identity }),
            _ => None,
        },
        _ => None,
    };
    let arg = arg_node(builder, ctx, index as u32);
    // The model node stays beside the manifest node that supplied the package
    // identity: the builder establishes a request only from a model's own
    // provenance.
    let provenance = [arg, node].into_iter().chain(manifest).collect::<Vec<_>>();
    let request_operation = match operation {
        "artifact.publish" => Some("artifact.publish_request"),
        "artifact.delete" => Some("artifact.remove_request"),
        _ => None,
    };
    if let Some(request_assurance) = request {
        let Some(request_operation) = request_operation else {
            return;
        };
        builder.effect(Effect {
            request_assurance,
            id: Default::default(),
            operation: Operation::new(request_operation),
            resource: resource.clone(),
            attributes: attrs.clone(),
            modality: Modality::MustOnSuccess,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: provenance.clone(),
        });
    }
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: attrs,
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: None,
        execution: ExecutionNodeRef(0),
        provenance,
    });
    arg_effect(
        builder,
        ctx,
        manifest.unwrap_or(node),
        index as u32,
        "network.upload",
        endpoint.unwrap_or(unresolved_resource("network")),
        Attrs::new(),
    );
    builder.declare_coverage(Domain::new("artifact"), CoverageLevel::Full);
    environment_boundary(
        builder,
        node,
        &["network", "filesystem"],
        BoundaryReason::ENVIRONMENT_CONFIGURATION,
        "publication authentication, configuration and transport details are unmodeled",
    );
}

/// Preserve the identity components selected by publication arguments and
/// supplied package metadata. Unobserved configuration remains unresolved.
pub(super) fn literal_package_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    if registry_owner_dispatch(builder, ctx, node) {
        return true;
    }
    let command = ctx.argv.first().and_then(program_name).unwrap_or("");
    // rustup's `cargo +<toolchain>` selects the toolchain, not the subcommand.
    let toolchain = usize::from(
        command == "cargo"
            && ctx
                .argv
                .get(1)
                .and_then(Word::as_literal)
                .is_some_and(|word| word.starts_with('+')),
    );
    // pnpm's workspace selectors precede the subcommand: `pnpm -r publish`,
    // `pnpm --filter <selector> publish`.
    let mut pnpm_selection = false;
    let mut pnpm_start = 1;
    while let Some(width) = match ctx.argv.get(pnpm_start).and_then(Word::as_literal) {
        _ if command != "pnpm" => None,
        Some("-r" | "--recursive") => Some(1),
        Some("-F" | "--filter") if ctx.argv.len() > pnpm_start + 1 => Some(2),
        Some(word) if word.starts_with("--filter=") => Some(1),
        _ => None,
    } {
        pnpm_start += width;
        pnpm_selection = true;
    }
    let (action, start) = match command {
        "gem" if ctx.argv.get(1).and_then(Word::as_literal) == Some("push") => ("publish", 2),
        "gem" if ctx.argv.get(1).and_then(Word::as_literal) == Some("yank") => ("yank", 2),
        "twine" if ctx.argv.get(1).and_then(Word::as_literal) == Some("upload") => ("publish", 2),
        "uv" if ctx.argv.get(1).and_then(Word::as_literal) == Some("publish") => ("publish", 2),
        "poetry" if ctx.argv.get(1).and_then(Word::as_literal) == Some("publish") => ("publish", 2),
        "hatch" if ctx.argv.get(1).and_then(Word::as_literal) == Some("publish") => ("publish", 2),
        "flit" if ctx.argv.get(1).and_then(Word::as_literal) == Some("publish") => ("publish", 2),
        "dotnet"
            if ctx.argv.get(1).and_then(Word::as_literal) == Some("nuget")
                && ctx.argv.get(2).and_then(Word::as_literal) == Some("push") =>
        {
            ("publish", 3)
        }
        "nuget" if ctx.argv.get(1).and_then(Word::as_literal) == Some("push") => ("publish", 2),
        "yarn"
            if ctx.argv.get(1).and_then(Word::as_literal) == Some("npm")
                && ctx.argv.get(2).and_then(Word::as_literal) == Some("publish") =>
        {
            ("publish", 3)
        }
        "pnpm" if pnpm_selection => match ctx.argv.get(pnpm_start).and_then(Word::as_literal) {
            Some("publish") => ("publish", pnpm_start + 1),
            _ => return false,
        },
        "pnpm" | "yarn" | "bun"
            if matches!(
                ctx.argv.get(1).and_then(Word::as_literal),
                Some("publish" | "unpublish")
            ) =>
        {
            (
                if ctx.argv[1].as_literal() == Some("unpublish") {
                    "remove"
                } else {
                    "publish"
                },
                2,
            )
        }
        "cargo" if ctx.argv.get(1 + toolchain).and_then(Word::as_literal) == Some("publish") => {
            ("publish", 2 + toolchain)
        }
        _ => return false,
    };
    let node = reviewed(
        builder,
        ctx,
        node,
        "package/publication@2026-09:https://guides.rubygems.org/command-reference/;https://twine.readthedocs.io/en/stable/;https://docs.astral.sh/uv/guides/publish/;https://python-poetry.org/docs/repositories/;https://hatch.pypa.io/latest/publish/;https://flit.pypa.io/en/stable/upload.html;https://learn.microsoft.com/nuget/reference/cli-reference/cli-ref-push;https://pnpm.io/cli/publish;https://bun.com/docs/pm/cli/publish;https://yarnpkg.com/cli/npm/publish;https://classic.yarnpkg.com/en/docs/cli/publish",
    );
    let mut operands = Vec::new();
    let mut dry_run = false;
    let mut invalid = false;
    let mut help = false;
    let mut gem_version_value: Option<String> = None;
    let mut selected_options = BTreeMap::new();
    let mut positional = false;
    let value_options: &[&str] = match command {
        "cargo" => &[
            "--manifest-path",
            "--registry",
            "--token",
            "-p",
            "--package",
            "--exclude",
        ],
        "gem" if action == "yank" => &["-v", "--version", "--host", "--key", "--platform", "--otp"],
        "gem" => &["--host", "--key", "--otp"],
        "twine" => &[
            "-r",
            "--repository",
            "--repository-url",
            "--sign-with",
            "-i",
            "--identity",
            "-u",
            "--username",
            "-p",
            "--password",
            "-c",
            "--comment",
            "--config-file",
            "--cert",
            "--client-cert",
        ],
        "uv" => &[
            "--publish-url",
            "-i",
            "--index",
            "--check-url",
            "-t",
            "--token",
            "-u",
            "--username",
            "-p",
            "--password",
            "--keyring-provider",
            "--trusted-publishing",
            "--allow-insecure-host",
            "--trusted-host",
            "--cache-dir",
            "--config-file",
            "--color",
            "--directory",
            "--project",
        ],
        "pnpm" => &[
            "--tag",
            "--access",
            "--registry",
            "--otp",
            "-F",
            "--filter",
            "--publish-branch",
        ],
        "yarn" => &["--tag", "--access", "--new-version"],
        "bun" => &["--tag", "--access"],
        "poetry" => &[
            "--repository",
            "-u",
            "--username",
            "-p",
            "--password",
            "--cert",
            "--client-cert",
            "--dist-dir",
        ],
        "flit" => &["--repository"],
        "hatch" => &[
            "-r",
            "--repo",
            "-u",
            "--user",
            "-a",
            "--auth",
            "--ca-cert",
            "--client-cert",
            "--client-key",
            "-p",
            "--publisher",
            "-o",
            "--option",
        ],
        "dotnet" => &["--source", "--api-key"],
        "nuget" => &["-Source", "-ApiKey"],
        _ => &[],
    };
    let boolean_options: &[&str] = match command {
        "cargo" => &["--allow-dirty", "--no-verify", "--locked", "--workspace"],
        "twine" => &[
            "--attestations",
            "-s",
            "--sign",
            "--non-interactive",
            "--skip-existing",
            "--verbose",
            "--disable-progress-bar",
        ],
        "uv" => &[
            "--no-attestations",
            "--offline",
            "--no-cache",
            "--no-cache-dir",
            "-n",
            "--no-config",
            "--system-certs",
            "--managed-python",
            "--no-managed-python",
            "--no-progress",
            "--no-python-downloads",
            "-q",
            "--quiet",
            "-v",
            "--verbose",
        ],
        "hatch" => &["-n", "--no-prompt", "--initialize-auth", "-y", "--yes"],
        "poetry" => &["--build", "--skip-existing", "-n", "--no-interaction"],
        // Git checks and reporting do not change what pnpm uploads.
        "pnpm" => &[
            "-r",
            "--recursive",
            "--no-git-checks",
            "--force",
            "--json",
            "--report-summary",
            "--ignore-scripts",
        ],
        "yarn" => &["--non-interactive"],
        "dotnet" => &["--skip-duplicate", "--no-symbols"],
        "nuget" => &["-SkipDuplicate"],
        _ => &[],
    };
    let mut index = start;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        let Some(text) = word.as_literal() else {
            if word
                .parts
                .iter()
                .any(|part| matches!(part, crate::word::WordPart::Glob(_)))
            {
                operands.push(index);
            } else {
                invalid = true;
            }
            index += 1;
            continue;
        };
        if !positional && text == "--" {
            positional = true;
        } else if !positional && text == "--help" {
            help = true;
        } else if !positional && text == "--dry-run" {
            // Only these clients document a no-upload run. `hatch publish`
            // does not: its option list ends at `--yes`, so the flag is an
            // unrecognized argument there, not a suppressed publication.
            if matches!(command, "cargo" | "uv" | "poetry" | "pnpm" | "yarn" | "bun") {
                dry_run = true;
            } else {
                invalid = true;
            }
        } else if !positional && text.starts_with('-') {
            let key = text.split_once('=').map_or(text, |(key, _)| key);
            let key = match (command, key) {
                ("twine" | "poetry", "-r") => "--repository",
                ("uv", "-i") => "--index",
                ("hatch", "-r") => "--repo",
                ("dotnet", "-s") => "--source",
                ("dotnet", "-k") => "--api-key",
                _ => key,
            };
            if value_options.contains(&key) && !text.contains('=') {
                if index + 1 >= ctx.argv.len()
                    || ctx.argv[index + 1]
                        .as_literal()
                        .is_none_or(|value| value.is_empty() || value.starts_with('-'))
                {
                    invalid = true;
                } else {
                    if command == "gem" && action == "yank" && matches!(key, "-v" | "--version") {
                        gem_version_value = ctx.argv[index + 1].as_literal().map(str::to_owned);
                    }
                    selected_options.insert(
                        key.to_string(),
                        ctx.argv[index + 1].as_literal().unwrap().to_string(),
                    );
                    index += 1;
                }
            } else if value_options.contains(&key)
                && text
                    .split_once('=')
                    .is_some_and(|(_, value)| value.is_empty())
            {
                invalid = true;
            } else if command == "gem"
                && action == "yank"
                && matches!(key, "-v" | "--version")
                && let Some((_, value)) = text.split_once('=')
            {
                gem_version_value = Some(value.to_owned());
            } else if command == "gem"
                && action == "yank"
                && let Some(value) = text.strip_prefix("-v").filter(|value| !value.is_empty())
            {
                // OptionParser attaches a short option's value: `-v3.0.0`.
                gem_version_value = Some(value.to_owned());
            } else if boolean_options.contains(&key) {
                if text.contains('=') {
                    invalid = true;
                }
            } else if !value_options.contains(&key) {
                invalid = true;
            }
            if value_options.contains(&key)
                && let Some((_, value)) = text.split_once('=')
            {
                selected_options.insert(key.to_string(), value.to_string());
            }
        } else {
            operands.push(index);
        }
        index += 1;
    }
    // A help request aborts the operation, so operand cardinality no longer
    // matters. A malformed option list does not become understood because
    // `--help` appears in it: these clients reject the invocation instead of
    // printing help, and claiming coverage of a command we did not parse
    // would be an over-claim.
    if help && !invalid {
        return true;
    }
    let allows_current_project = matches!(
        command,
        "cargo" | "pnpm" | "yarn" | "bun" | "uv" | "poetry" | "hatch" | "flit"
    );
    let cardinality_invalid = match command {
        "cargo" | "poetry" | "flit" => !operands.is_empty(),
        "yarn" if start == 3 => !operands.is_empty(),
        "pnpm" | "yarn" | "bun" => operands.len() > 1,
        "gem" if action == "yank" => gem_version_value.is_none() || operands.len() != 1,
        "gem" => operands.len() != 1,
        _ => false,
    };
    if invalid || cardinality_invalid || (operands.is_empty() && !allows_current_project) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: ["artifact", "network", "filesystem", "process"]
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some("package publication arguments are incomplete or unsupported".into()),
        });
        return true;
    }
    if command == "gem" && matches!(action, "publish" | "yank") && operands.len() != 1 {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "gem push accepts one package file",
        );
        return true;
    }
    if command == "poetry"
        && ctx
            .argv
            .iter()
            .any(|word| word.as_literal() == Some("--build"))
    {
        environment_boundary(
            builder,
            node,
            &["artifact", "filesystem", "network", "process"],
            BoundaryReason::PACKAGE_SCRIPTS,
            "Poetry publication build backend may execute project code",
        );
    }
    let mut attrs = Attrs::new();
    attrs.insert("active".into(), AttrValue::Bool(true));
    attrs.insert("dry_run".into(), AttrValue::Bool(false));
    attrs.insert("package_manager".into(), AttrValue::String(command.into()));
    let ecosystem = match command {
        "gem" => "rubygems",
        "cargo" => "crates.io",
        "pnpm" | "yarn" | "bun" => "npm",
        "twine" | "uv" | "poetry" | "hatch" | "flit" => "pypi",
        "dotnet" | "nuget" => "nuget",
        _ => command,
    };
    attrs.insert("ecosystem".into(), AttrValue::String(ecosystem.into()));
    attrs.insert("action".into(), AttrValue::String(action.into()));
    let pattern_target = operands.iter().any(|index| {
        ctx.argv[*index]
            .parts
            .iter()
            .any(|part| matches!(part, crate::word::WordPart::Glob(_)))
    });
    attrs.insert(
        "selection".into(),
        AttrValue::String(if pattern_target { "pattern" } else { "unknown" }.into()),
    );
    // A publication's operands name the files to upload, not the artifact:
    // which distributions a pattern expands to is the `selection` attribute
    // above, and the client publishes whatever it matches rather than nothing.
    // A yank or an unpublish takes the artifact's own name there instead, so a
    // pattern leaves the requested artifact unknown.
    let request_assurance = if pattern_target && matches!(action, "yank" | "remove") {
        effinterp_proto::RequestAssurance::Conservative
    } else {
        effinterp_proto::RequestAssurance::Exact
    };
    if let Some(version) = gem_version_value {
        attrs.insert("version".into(), AttrValue::String(version));
    }
    // Registry aliases select configuration entries, not literal endpoints.
    for (option, attribute) in match command {
        "cargo" => &[("--registry", "registry_name")][..],
        "gem" => &[("--host", "registry"), ("--platform", "platform")][..],
        "twine" => &[
            ("--repository-url", "registry"),
            ("--repository", "registry_name"),
        ][..],
        "uv" => &[("--publish-url", "registry"), ("--index", "registry_name")][..],
        "poetry" | "flit" => &[("--repository", "registry_name")][..],
        "hatch" => &[("--repo", "registry_name")][..],
        "dotnet" => &[("--source", "registry")][..],
        "nuget" => &[("-Source", "registry")][..],
        _ => &[("--registry", "registry"), ("--tag", "tag")][..],
    } {
        if let Some(value) = selected_options.get(*option) {
            let attribute = if matches!(command, "dotnet" | "nuget")
                && !value.starts_with("https://")
                && !value.starts_with("http://")
            {
                "registry_name"
            } else {
                attribute
            };
            attrs.insert(attribute.into(), AttrValue::String(value.clone()));
        }
    }
    if action == "yank" {
        if let Some(package) = operands
            .first()
            .and_then(|index| ctx.argv[*index].as_literal())
        {
            attrs.insert("package".into(), AttrValue::String(package.into()));
        }
        attrs.insert("scope".into(), AttrValue::String("version".into()));
    }
    let mut source_node = node;
    let resource = if ecosystem == "npm" && action == "publish" {
        let mut name = unknown();
        let mut version = unknown();
        let endpoint = selected_options
            .get("--registry")
            .map_or_else(unknown, |value| literal(value));
        // A recursive or filtered pnpm publication publishes the selected
        // workspace packages, which are not read here.
        let workspace = pnpm_selection
            || command == "pnpm"
                && ctx.argv[start..]
                    .iter()
                    .take_while(|word| word.as_literal() != Some("--"))
                    .filter_map(Word::as_literal)
                    .any(|word| {
                        matches!(word, "-r" | "--recursive" | "-F" | "--filter")
                            || word.starts_with("--filter=")
                    });
        if workspace {
            boundary(
                builder,
                node,
                &["artifact", "filesystem"],
                BoundaryReason::MODEL_COVERAGE,
                "pnpm workspace selection leaves the published packages unresolved",
            );
        }
        let directory = operands
            .first()
            .map_or(Some("."), |index| ctx.argv[*index].as_literal())
            .filter(|path| {
                !workspace
                    && !path.ends_with(".tgz")
                    && !path.ends_with(".tar.gz")
                    && !path.contains("://")
            });
        if let Some(directory) = directory {
            let path = if directory == "." {
                "package.json".into()
            } else {
                format!("{directory}/package.json")
            };
            arg_effect(
                builder,
                ctx,
                node,
                operands.first().copied().unwrap_or(start) as u32,
                "filesystem.read",
                ctx.resolve_fs_word(&Word::literal(&path)),
                Attrs::new(),
            );
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            if let Some((origin, manifest)) = package_metadata(builder, ctx, &path) {
                source_node = builder.node(ProvenanceKind::ToolArgument { name: origin }, &[node]);
                // pnpm can select a different package via publishConfig.directory.
                // Yarn Classic prompts for a new version before publishing.
                if command != "pnpm"
                    || manifest
                        .get("publishConfig")
                        .and_then(|v| v.get("directory"))
                        .is_none()
                {
                    if let Some(value) = manifest
                        .get("name")
                        .and_then(|v| v.as_str())
                        .filter(|v| !v.is_empty())
                    {
                        name = literal(value);
                    }
                    if (command != "yarn" || start == 3)
                        && let Some(value) = manifest
                            .get("version")
                            .and_then(|v| v.as_str())
                            .filter(|v| exact_npm_version(v))
                    {
                        version = literal(value);
                    }
                }
            }
        }
        artifact(
            ArtifactEcosystem::Npm,
            endpoint,
            name,
            ArtifactReference::Version { value: version },
        )
    } else {
        unknown()
    };
    if dry_run {
        let index = operands.first().copied().unwrap_or(start);
        arg_effect(
            builder,
            ctx,
            node,
            index as u32,
            "network.request",
            unresolved_resource("network"),
            Attrs::new(),
        );
        environment_boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::REVIEWED_COMMAND_SURFACE,
            "package publication dry-run does not upload an artifact",
        );
        return true;
    }
    if action == "yank" {
        let arg = operands.first().copied().unwrap_or(start);
        let arg_provenance = arg_node(builder, ctx, arg as u32);
        builder.effect(Effect {
            request_assurance,
            id: Default::default(),
            operation: Operation::new("artifact.yank_request"),
            resource: unresolved_resource("artifact"),
            attributes: attrs.clone(),
            modality: Modality::MustOnSuccess,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: vec![arg_provenance, node],
        });
        mutation(
            builder,
            ctx,
            node,
            None,
            arg,
            "artifact.delete",
            unresolved_resource("artifact"),
            attrs,
            None,
        );
        builder.declare_coverage(Domain::new("artifact"), CoverageLevel::Full);
        return true;
    }
    mutation(
        builder,
        ctx,
        node,
        (source_node != node).then_some(source_node),
        operands.first().copied().unwrap_or(start),
        if action == "remove" {
            "artifact.delete"
        } else {
            "artifact.publish"
        },
        resource,
        attrs,
        Some(request_assurance),
    );
    true
}

struct LiteralPackages;

fn package_publication_selected(argv: &[Word]) -> bool {
    let command = argv.first().and_then(program_name);
    let sub = argv.get(1).and_then(Word::as_literal);
    let verb = argv.get(2).and_then(Word::as_literal);
    matches!(
        (command, sub),
        (Some("gem"), Some("push" | "yank" | "owner"))
            | (Some("twine"), Some("upload"))
            | (Some("uv" | "poetry" | "hatch" | "flit"), Some("publish"))
            | (Some("nuget"), Some("push"))
            | (Some("pnpm" | "yarn" | "bun"), Some("publish" | "unpublish"))
            | (Some("cargo"), Some("publish"))
    ) || matches!(
        (command, sub, verb),
        (Some("dotnet"), Some("nuget"), Some("push"))
    )
}

pub(super) fn package_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(LiteralPackages)]
}

impl CommandModel for LiteralPackages {
    fn domains(&self) -> &'static [&'static str] {
        &["artifact", "filesystem", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "package/publication@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["twine", "hatch", "flit"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        if !literal_package_dispatch(builder, ctx, node) {
            boundary(
                builder,
                node,
                &["artifact", "network", "filesystem", "process"],
                BoundaryReason::MODEL_COVERAGE,
                "package publication command surface is unmodeled",
            );
        }
    }
}

impl CommandModel for PackagePublicationOwner {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn records_process(&self) -> bool {
        self.owner.records_process()
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<super::ModelCausalBinding> {
        if package_publication_selected(argv) {
            Vec::new()
        } else {
            self.owner.stdout_value_bindings(argv)
        }
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<super::ModelCausalBinding> {
        if package_publication_selected(argv) {
            Vec::new()
        } else {
            self.owner.causal_bindings(argv)
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        if !literal_package_dispatch(builder, ctx, node) {
            self.owner.apply(builder, ctx, node);
        }
    }
}

/// `gh gist create -p` is `--public`, but the gh document declares `-p` for
/// the whole command as `--preview`, whose value would swallow the first gist
/// file. The argv with each such `-p` spelled `--public`, which the document
/// reads as the boolean it is, or None when nothing changes.
fn gist_public_spelled_out(argv: &[Word]) -> Option<Vec<Word>> {
    if argv.get(1).and_then(Word::as_literal) != Some("gist")
        || argv.get(2).and_then(Word::as_literal) != Some("create")
    {
        return None;
    }
    let mut rewritten = argv.to_vec();
    let mut changed = false;
    let mut index = 3;
    while index < argv.len() {
        match argv[index].as_literal() {
            Some("--") => break,
            Some("-d" | "--desc" | "-f" | "--filename") => index += 1,
            Some("-p") => {
                rewritten[index] = Word::literal("--public");
                changed = true;
            }
            _ => {}
        }
        index += 1;
    }
    changed.then_some(rewritten)
}

/// Whether a wholly literal `gh gist create` reads its content from stdin:
/// with no file operand, or with `-` among them.
fn gist_create_reads_stdin(argv: &[Word]) -> bool {
    let Some(words) = argv
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if words.get(1..3) != Some(&["gist", "create"][..]) {
        return false;
    }
    let mut files = Vec::new();
    let mut words = words[3..].iter();
    while let Some(word) = words.next() {
        match *word {
            "-d" | "--desc" | "-f" | "--filename" => {
                words.next();
            }
            "-" => files.push(*word),
            word if word.starts_with('-') => {}
            word => files.push(word),
        }
    }
    files.is_empty() || files.contains(&"-")
}

/// `gh release download -p NAME` saves each asset a pattern matches under
/// the asset's name in `--dir` (default: the working directory). A pattern
/// without glob characters matches only the asset of that name, so the file
/// it writes is known and a later read of it joins the download; the gh
/// document's `*` write under the directory cannot.
fn release_download_assets(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    start: usize,
) {
    let argv = ctx.argv;
    if argv.get(1).and_then(Word::as_literal) != Some("release")
        || argv.get(2).and_then(Word::as_literal) != Some("download")
    {
        return;
    }
    let Some(download) = (start..builder.effects_len())
        .find(|&i| builder.effect_operation(i) == Some("network.download"))
    else {
        return;
    };
    let mut directory = None;
    let mut names = Vec::new();
    let mut index = 3;
    while index < argv.len() {
        let value = argv.get(index + 1);
        match argv[index].as_literal() {
            Some("-p" | "--pattern") => {
                names.extend(value.map(|value| (index + 1, value.as_literal())));
                index += 2;
            }
            Some("-D" | "--dir") => {
                directory = Some(value.and_then(Word::as_literal));
                index += 2;
            }
            Some("-R" | "--repo" | "-O" | "--output" | "-A" | "--archive") => index += 2,
            // An attached value anchors on the flag's own word.
            Some(word) if word.starts_with("--pattern=") => {
                names.push((index, word.strip_prefix("--pattern=")));
                index += 1;
            }
            Some(word) if word.starts_with("--dir=") => {
                directory = Some(word.strip_prefix("--dir="));
                index += 1;
            }
            None if matches!(
                argv[index].parts.first(),
                Some(crate::word::WordPart::Literal(head)) if head.starts_with("--dir=")
            ) =>
            {
                return;
            }
            _ => index += 1,
        }
    }
    // An empty directory is the current one, as if the flag were absent.
    let directory = match directory {
        Some(Some(directory)) => Some(directory).filter(|directory| !directory.is_empty()),
        Some(None) => return,
        None => None,
    };
    for (index, name) in names {
        let Some(name) =
            name.filter(|name| !name.is_empty() && !name.contains(['*', '?', '[', '\\', '/']))
        else {
            continue;
        };
        let path = directory.map_or_else(
            || name.to_string(),
            |directory| format!("{directory}/{name}"),
        );
        if let Some(write) = super::common::fs_arg_effect(
            builder,
            ctx,
            node,
            index as u32,
            &argv[index],
            "filesystem.write",
            ctx.resolve_fs_word(&Word::literal(&path)),
            Attrs::new(),
        ) {
            builder.transfer_binding(crate::resource_transfer::TransferBinding::new(
                download as u32,
                write,
            ));
        }
    }
}

pub(super) fn docker_push(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    start: usize,
) {
    let node = reviewed(
        builder,
        ctx,
        node,
        "docker/image-push@2026-09-09:https://docs.docker.com/reference/cli/docker/image/push/;https://docs.docker.com/reference/cli/docker/image/tag/;https://github.com/distribution/reference/blob/v0.6.0/normalize.go",
    );
    if ctx.argv[0].as_literal() != Some("docker")
        || !((start == 2 && ctx.argv[1].as_literal() == Some("push"))
            || (start == 3
                && ctx.argv[1].as_literal() == Some("image")
                && ctx.argv[2].as_literal() == Some("push")))
    {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "podman publication and Docker global publication options are unmodeled",
        );
        return;
    }
    let parsed = options(
        ctx,
        start,
        &["--quiet", "--all-tags"],
        &[],
        &[("-q", "--quiet"), ("-a", "--all-tags")],
    );
    if parsed.invalid || parsed.operands.len() != 1 {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "Docker push requires one image and reviewed options",
        );
        return;
    }
    let index = parsed.operands[0];
    let image = &ctx.argv[index];
    let (endpoint, repository) =
        if let Some((first, rest)) = super::container::split_word_once(image, '/') {
            match first.as_literal() {
                Some("index.docker.io") => (literal("docker.io"), rest),
                Some(v) if v.contains(['.', ':']) || v == "localhost" || v != v.to_lowercase() => {
                    (word_resource(&first), rest)
                }
                Some(_) => (literal("docker.io"), image.clone()),
                // A symbolic first component can be a registry or a namespace.
                None => (unknown(), rest),
            }
        } else if image.as_literal().is_some() {
            (literal("docker.io"), image.clone())
        } else {
            boundary(
                builder,
                node,
                &["artifact", "network"],
                BoundaryReason::MODEL_COVERAGE,
                "symbolic image may contain a registry endpoint",
            );
            (unknown(), image.clone())
        };
    let (name, reference) =
        if let Some((name, digest)) = super::container::split_word_once(&repository, '@') {
            (
                name,
                ArtifactReference::Digest {
                    value: word_resource(&digest),
                },
            )
        } else if let Some((name, tag)) = super::container::split_word_once(&repository, ':') {
            (
                name,
                ArtifactReference::Tag {
                    value: word_resource(&tag),
                },
            )
        } else {
            (
                repository,
                ArtifactReference::Tag {
                    value: if image.as_literal().is_some() {
                        literal("latest")
                    } else {
                        unknown()
                    },
                },
            )
        };
    if matches!(reference, ArtifactReference::Digest { .. }) {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "Docker publication by digest is outside the reviewed tag publication surface",
        );
        return;
    }
    let mut name = if matches!(endpoint, ResourceExpr::Unresolved { .. }) {
        unknown()
    } else {
        word_resource(&name)
    };
    if endpoint == literal("docker.io")
        && let ResourceExpr::Literal { value } = &mut name
        && !value.contains('/')
    {
        *value = format!("library/{value}");
    }
    if matches!(&name, ResourceExpr::Literal { value } if value.is_empty() || value != &value.to_lowercase() || value.contains([' ', '@', ':']) || value.split('/').any(str::is_empty))
        || reference
            .value()
            .is_some_and(|v| matches!(v, ResourceExpr::Literal { value } if value.is_empty()))
    {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "invalid Docker image reference",
        );
        return;
    }
    if parsed.boolean("--all-tags")
        && (super::container::split_word_once(image, '@').is_some()
            || image.as_literal().is_some_and(|image| {
                image
                    .rsplit('/')
                    .next()
                    .is_some_and(|last| last.contains(':'))
            }))
    {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "Docker all-tags requires a repository without an explicit reference",
        );
        return;
    }
    let reference = if parsed.boolean("--all-tags") {
        ArtifactReference::Tag {
            value: ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::ArtifactField { glob: "*".into() },
            },
        }
    } else {
        reference
    };
    if image.as_literal().is_none() {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "symbolic Docker image reference",
        );
    }
    let resource = artifact(ArtifactEcosystem::Oci, endpoint, name, reference);
    if parsed.boolean("--all-tags") {
        builder.boundary(Boundary {
            reason: BoundaryReason::LIVE_INVENTORY,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            domains: vec![Domain::new("artifact")],
            affected_resource: Some(resource.clone()),
            callee: None,
            provenance: vec![node],
            limit: None,
            detail: Some("Docker all-tags inventory is unavailable within this repository".into()),
        });
    }
    mutation(
        builder,
        ctx,
        node,
        None,
        index,
        "artifact.publish",
        resource,
        Attrs::new(),
        None,
    );
}

fn registry_owner_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    let command = program_name(&ctx.argv[0]).unwrap_or("");
    if !matches!(command, "npm" | "cargo" | "gem" | "yarn" | "pnpm") {
        return false;
    }
    // rustup's `cargo +<toolchain>` selects the toolchain, not the subcommand.
    let toolchain = usize::from(
        command == "cargo"
            && ctx
                .argv
                .get(1)
                .and_then(Word::as_literal)
                .is_some_and(|word| word.starts_with('+')),
    );
    let mut changes = Vec::new();
    let mut registry = None;
    let mut registry_name = None;
    let mut registry_index = None;
    // Whether the package directory an omitted package name is read from is
    // the current one.
    let mut local = true;
    // An npm option this reading does not understand appeared.
    let mut unresolved = false;
    let (package, invalid) = if matches!(command, "yarn" | "pnpm") {
        // Yarn Classic's `owner add|rm|remove <user> [<package>]`, which
        // reads an omitted package from package.json, and pnpm's
        // `owner add|rm <user> <package>` (pnpm 11; earlier releases hand
        // `owner` to npm, which also accepts `remove`).
        if !matches!(
            (command, ctx.argv.get(1).and_then(Word::as_literal)),
            (_, Some("owner")) | ("pnpm", Some("owners"))
        ) {
            return false;
        }
        let parsed = if command == "yarn" {
            options(
                ctx,
                2,
                &[
                    "--silent",
                    "-s",
                    "--verbose",
                    "--non-interactive",
                    "--no-progress",
                ],
                &[],
                &[],
            )
        } else {
            options(ctx, 2, &["--silent", "-s"], &["--registry", "--otp"], &[])
        };
        registry = parsed.values.get("--registry").map(word_resource);
        let action = parsed
            .operands
            .first()
            .and_then(|index| ctx.argv[*index].as_literal());
        if let Some(action @ ("add" | "rm" | "remove")) = action
            && let Some(&index) = parsed.operands.get(1)
        {
            changes.push((
                if action == "add" { "add" } else { "remove" },
                ctx.argv[index].clone(),
                index,
            ));
        }
        let operands = if command == "yarn" { 2..=3 } else { 3..=3 };
        (
            parsed.operands.get(2).copied(),
            parsed.invalid || !operands.contains(&parsed.operands.len()),
        )
    } else if command == "npm" {
        let parsed = npm_options(ctx, 1);
        let Some((subindex, _)) = parsed.select(ctx, 1, &["owner", "author"]) else {
            return false;
        };
        // A workspace change names each selected workspace's package, and
        // an option this reading does not understand may relocate it.
        local = !(parsed.selects_workspaces() || parsed.relocated(ctx) || parsed.unresolved);
        unresolved = parsed.unresolved;
        registry = parsed.value("registry").map(word_resource);
        let mut rest = 0;
        let mut package = None;
        if let Some((index, action)) =
            parsed.select(ctx, subindex + 1, &["add", "rm", "remove", "ls", "list"])
        {
            let operands: Vec<usize> = parsed
                .operands
                .iter()
                .copied()
                .filter(|operand| *operand > index)
                .collect();
            rest = operands
                .iter()
                .filter(|operand| !parsed.maybe_value(**operand))
                .count();
            if action != "ls"
                && action != "list"
                && let Some(&user) = operands.first()
            {
                changes.push((
                    if action == "add" { "add" } else { "remove" },
                    ctx.argv[user].clone(),
                    user,
                ));
            }
            package = operands.get(1).copied();
        }
        (
            package,
            parsed.prints_only() || (!(1..=2).contains(&rest) && !parsed.unresolved),
        )
    } else {
        if ctx.argv.get(1 + toolchain).and_then(Word::as_literal) != Some("owner") {
            return false;
        }
        let mut package = None;
        let mut invalid = false;
        let mut index = 2 + toolchain;
        let mut positional = false;
        while index < ctx.argv.len() {
            let Some(text) = ctx.argv[index].as_literal() else {
                invalid = true;
                break;
            };
            if !positional && text == "--" {
                positional = true;
            } else if !positional && text.starts_with('-') {
                let (key, attached) = if let Some((key, value)) = text.split_once('=') {
                    (key, Some(value))
                } else if (text.starts_with("-a") || text.starts_with("-r"))
                    && !text.starts_with("--")
                    && text.len() > 2
                {
                    (&text[..2], Some(&text[2..]))
                } else {
                    (text, None)
                };
                let action = match key {
                    "-a" | "--add" => Some("add"),
                    "-r" | "--remove" => Some("remove"),
                    _ => None,
                };
                let takes_value = action.is_some()
                    || match command {
                        "cargo" => matches!(key, "--registry" | "--index" | "--token"),
                        "gem" => matches!(key, "--host" | "--key" | "--otp"),
                        _ => false,
                    };
                if !takes_value {
                    invalid = true;
                    break;
                }
                let option_index = index;
                let value = if let Some(value) = attached {
                    Word::literal(value)
                } else {
                    index += 1;
                    ctx.argv
                        .get(index)
                        .cloned()
                        .unwrap_or_else(|| Word::literal(""))
                };
                if value
                    .as_literal()
                    .is_none_or(|value| value.is_empty() || value.starts_with('-'))
                {
                    invalid = true;
                }
                match key {
                    "--host" => registry = Some(word_resource(&value)),
                    "--registry" => registry_name = value.as_literal().map(str::to_string),
                    "--index" => registry_index = value.as_literal().map(str::to_string),
                    _ => {}
                }
                if let Some(action) = action {
                    changes.push((action, value, option_index));
                }
            } else if package.replace(index).is_some() {
                invalid = true;
            }
            index += 1;
        }
        (package, invalid || (command == "gem" && package.is_none()))
    };
    let node = reviewed(
        builder,
        ctx,
        node,
        "package/owner@2026-09:https://docs.npmjs.com/cli/v11/commands/npm-owner/;https://doc.rust-lang.org/cargo/commands/cargo-owner.html;https://guides.rubygems.org/command-reference/#gem-owner;https://classic.yarnpkg.com/en/docs/cli/owner;https://github.com/pnpm/pnpm/blob/main/registry-access/commands/src/owner.ts;https://rust-lang.github.io/rustup/overrides.html#toolchain-override-shorthand",
    );
    if invalid
        || changes.is_empty()
        || changes
            .iter()
            .any(|(_, user, _)| user.as_literal().is_none_or(str::is_empty))
    {
        boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::MODEL_COVERAGE,
            "registry ownership arguments or operation are unsupported",
        );
        return true;
    }
    if unresolved {
        unrecognized_npm_options(builder, node);
    }
    let mut name = package
        .map(|index| word_resource(&ctx.argv[index]))
        .unwrap_or_else(unknown);
    if package.is_none() && local && matches!(command, "npm" | "yarn") {
        arg_effect(
            builder,
            ctx,
            node,
            1,
            "filesystem.read",
            ctx.resolve_fs_word(&Word::literal("package.json")),
            Attrs::new(),
        );
        if let SourceResolution::Source { source, .. } =
            ctx.resolve_source_operand(builder, "package.json", SourcePurpose::InvocationInput)
            && let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&source)
            && let Some(value) = manifest
                .get("name")
                .and_then(|name| name.as_str())
                .filter(|name| !name.is_empty())
        {
            name = literal(value);
        }
    }
    let endpoint = registry.unwrap_or_else(|| {
        if command == "npm" {
            ctx.environment_value("npm_config_registry")
                .unwrap_or_else(unknown)
        } else {
            unknown()
        }
    });
    // npm's scope registry can override its generic registry setting.
    let endpoint = if command != "cargo"
        && command != "gem"
        && matches!(&name, ResourceExpr::Literal { value } if value.starts_with('@'))
    {
        unknown()
    } else {
        endpoint
    };
    for (action, user, index) in changes {
        let mut attrs = Attrs::new();
        attrs.insert("package_manager".into(), AttrValue::String(command.into()));
        attrs.insert("action".into(), AttrValue::String(action.into()));
        attrs.insert("active".into(), AttrValue::Bool(true));
        attrs.insert("dry_run".into(), AttrValue::Bool(false));
        attrs.insert("scope".into(), AttrValue::String("whole".into()));
        if let ResourceExpr::Literal { value } = &endpoint {
            attrs.insert("registry".into(), AttrValue::String(value.clone()));
        }
        if let Some(value) = &registry_name {
            attrs.insert("registry_name".into(), AttrValue::String(value.clone()));
        }
        if let Some(value) = &registry_index {
            attrs.insert("registry_index".into(), AttrValue::String(value.clone()));
        }
        attrs.insert(
            "principal".into(),
            AttrValue::String(user.as_literal().unwrap().into()),
        );
        if let ResourceExpr::Literal { value } = &name {
            attrs.insert("package".into(), AttrValue::String(value.clone()));
        }
        arg_effect(
            builder,
            ctx,
            node,
            index as u32,
            "artifact.owner_change",
            if matches!(command, "npm" | "yarn" | "pnpm") {
                artifact(
                    ArtifactEcosystem::Npm,
                    endpoint.clone(),
                    name.clone(),
                    ArtifactReference::Whole {},
                )
            } else {
                unknown()
            },
            attrs,
        );
    }
    builder.declare_coverage(Domain::new("artifact"), CoverageLevel::Full);
    let (reason, scope) = if matches!(name, ResourceExpr::Literal { .. }) {
        (
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            BoundaryScope::Environment,
        )
    } else {
        (BoundaryReason::MODEL_COVERAGE, BoundaryScope::Invocation)
    };
    scoped_boundary(
        builder,
        node,
        &["artifact", "filesystem", "network"],
        reason,
        scope,
        "registry ownership target configuration and authentication are unresolved",
    );
    true
}

fn exact_npm_version(version: &str) -> bool {
    let core = version.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<_> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
}

pub(super) fn npm_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    if registry_owner_dispatch(builder, ctx, node) {
        return true;
    }
    let parsed = npm_options(ctx, 1);
    let Some((subindex, sub)) = parsed.select(ctx, 1, &["publish", "unpublish"]) else {
        return false;
    };
    let operands: Vec<usize> = parsed
        .operands
        .iter()
        .copied()
        .filter(|operand| *operand > subindex)
        .collect();
    let publish = sub == "publish";
    let node = reviewed(
        builder,
        ctx,
        node,
        "npm/publication@11:https://docs.npmjs.com/cli/v11/commands/npm-publish/;https://docs.npmjs.com/cli/v11/commands/npm-unpublish/;https://docs.npmjs.com/cli/v11/configuring-npm/package-json/;https://docs.npmjs.com/cli/v11/using-npm/scripts/",
    );
    // npm rejects a second package operand.
    if operands
        .iter()
        .filter(|operand| !parsed.maybe_value(**operand))
        .count()
        > 1
    {
        boundary(
            builder,
            node,
            &["artifact", "network", "filesystem", "process"],
            BoundaryReason::MODEL_COVERAGE,
            "npm publication selection is unmodeled",
        );
        return true;
    }
    if parsed.unresolved {
        unrecognized_npm_options(builder, node);
    }
    let operand = operands.first().copied();
    // Which word is the package is unproven when the first operand may be an
    // unresolved option's value.
    let uncertain = operand.is_some_and(|index| parsed.maybe_value(index));
    // A workspace runs the command from package directories other than the
    // current one, which are not read here, and so does a global or prefixed
    // unpublish. A workspace publication ignores its operand and publishes each
    // selected workspace. npm 11's publish resolves its operand, `.` when
    // absent, against the process cwd, so a prefix or global location moves
    // only its configuration, not the package or its hooks.
    let elsewhere = parsed.selects_workspaces() || (!publish && parsed.relocated(ctx));
    // An option this reading does not understand may select another package,
    // so the current one's manifest still supplies the hooks that may run but
    // not the package's identity.
    let unsettled = uncertain || (parsed.unresolved && (publish || operand.is_none()));
    // The command line decides a dry run before the environment does. Only a
    // proven true value suppresses the request.
    let dry_run = match parsed.setting("dry-run") {
        NpmSetting::Unset => npm_environment_setting(ctx, "dry-run") == NpmSetting::Proven,
        setting => setting == NpmSetting::Proven,
    };
    let ignore_scripts = parsed.setting("ignore-scripts") == NpmSetting::Proven;
    let mut manifest = None;
    let mut source_node = node;
    let mut directory = ".".to_string();
    let tarball = publish
        && !elsewhere
        && !uncertain
        && operand.is_some_and(|index| {
            ctx.argv[index].as_literal().is_some_and(|path| {
                !path.contains("://") && (path.ends_with(".tgz") || path.ends_with(".tar.gz"))
            })
        });
    if publish && !tarball && !ignore_scripts {
        environment_boundary(
            builder,
            node,
            &["filesystem", "process", "network", "artifact"],
            BoundaryReason::PACKAGE_SCRIPTS,
            "npm publication hooks may execute arbitrary code, including during dry-run",
        );
    }
    if tarball {
        arg_effect(
            builder,
            ctx,
            node,
            operand.unwrap() as u32,
            "filesystem.read",
            ctx.resolve_fs_word(&ctx.argv[operand.unwrap()]),
            Attrs::new(),
        );
        boundary(
            builder,
            node,
            &["artifact", "filesystem"],
            BoundaryReason::MODEL_COVERAGE,
            "npm archive package identity is unavailable",
        );
    } else if elsewhere {
        boundary(
            builder,
            node,
            &["artifact", "filesystem"],
            BoundaryReason::MODEL_COVERAGE,
            "npm workspace, global or prefix selection leaves the package directory unresolved",
        );
    } else {
        if publish
            && !uncertain
            && let Some(index) = operand
        {
            let Some(path) = ctx.argv[index].as_literal() else {
                boundary(
                    builder,
                    node,
                    &["artifact", "filesystem"],
                    BoundaryReason::MODEL_COVERAGE,
                    "symbolic npm publication directory",
                );
                return true;
            };
            if path.is_empty()
                || path.contains("://")
                || (path.ends_with(".tgz") || path.ends_with(".tar.gz"))
                || path.starts_with('@')
            {
                boundary(
                    builder,
                    node,
                    &["artifact", "filesystem", "network"],
                    BoundaryReason::MODEL_COVERAGE,
                    "npm tarball, URL, and package-spec publication are unmodeled",
                );
                return true;
            }
            directory = path.into();
        }
        let path = if directory == "." {
            "package.json".into()
        } else {
            format!("{directory}/package.json")
        };
        arg_effect(
            builder,
            ctx,
            node,
            operand.unwrap_or(subindex) as u32,
            "filesystem.read",
            ctx.resolve_fs_word(&Word::literal(&path)),
            Attrs::new(),
        );
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        // With an explicit package operand the local manifest is optional
        // configuration. Its absence cannot hide the selected package/version.
        if !publish && operand.is_some() {
            if let Some((origin, value)) = package_metadata(builder, ctx, &path) {
                source_node = builder.node(ProvenanceKind::ToolArgument { name: origin }, &[node]);
                manifest = Some(value);
            }
        } else if let SourceResolution::Source { origin, source } =
            ctx.resolve_source_operand(builder, &path, SourcePurpose::InvocationInput)
        {
            source_node = builder.node(
                ProvenanceKind::ToolArgument {
                    name: origin.clone(),
                },
                &[node],
            );
            manifest = serde_json::from_str::<serde_json::Value>(&source).ok();
            if manifest.is_none() {
                ctx.nest.record_unsupported_source(builder, &origin);
            }
        }
        if manifest.is_none() && (publish || operand.is_none()) {
            boundary(
                builder,
                node,
                &["artifact", "filesystem"],
                BoundaryReason::MODEL_COVERAGE,
                "npm package.json is missing, refused, or malformed",
            );
        }
    }
    let field = |name: &str| {
        manifest
            .as_ref()
            .and_then(|v| v.get(name))
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty() && (name != "version" || exact_npm_version(v)))
            .map(literal)
            .unwrap_or_else(unknown)
    };
    let (name, reference) = if unsettled {
        (unknown(), ArtifactReference::Version { value: unknown() })
    } else if !publish && let Some(index) = operand {
        match ctx.argv[index].as_literal() {
            Some(spec) => {
                let split = spec.rfind('@').filter(|index| *index > 0);
                let (name, version) = split.map_or((spec, None), |index| {
                    (&spec[..index], Some(&spec[index + 1..]))
                });
                if name.is_empty()
                    || name.contains(":")
                    || version.is_some_and(|v| !exact_npm_version(v))
                    || (name.contains('/')
                        && (!name.starts_with('@') || name.matches('/').count() != 1))
                {
                    boundary(
                        builder,
                        node,
                        &["artifact", "network"],
                        BoundaryReason::MODEL_COVERAGE,
                        "npm unpublish requires a package and optional exact version",
                    );
                    return true;
                }
                (
                    literal(name),
                    version.map_or(ArtifactReference::Whole {}, |v| {
                        ArtifactReference::Version { value: literal(v) }
                    }),
                )
            }
            None => {
                boundary(
                    builder,
                    node,
                    &["artifact"],
                    BoundaryReason::MODEL_COVERAGE,
                    "symbolic npm package spec leaves version scope unresolved",
                );
                (unknown(), ArtifactReference::Version { value: unknown() })
            }
        }
    } else {
        (
            field("name"),
            ArtifactReference::Version {
                value: field("version"),
            },
        )
    };
    if name == unknown() || reference.value() == Some(&unknown()) {
        boundary(
            builder,
            node,
            &["artifact"],
            BoundaryReason::MODEL_COVERAGE,
            "npm package name or exact version is unavailable",
        );
    }
    let selected_manifest = manifest.as_ref().filter(|manifest| {
        manifest
            .get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|manifest_name| name == literal(manifest_name))
    });
    let config = selected_manifest.and_then(|v| v.get("publishConfig"));
    let registry = parsed.value("registry").map(word_resource);
    let config_registry = config
        .and_then(|v| v.get("registry"))
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(literal);
    let env_registry = ctx.environment_value("npm_config_registry");
    let mut endpoint = registry
        .or(config_registry)
        .or(env_registry)
        .unwrap_or_else(unknown);
    // A scope-specific registry can override generic registry evidence. Only
    // publishConfig for that exact scope establishes the scoped destination here.
    if let ResourceExpr::Literal { value } = &name
        && value.starts_with('@')
    {
        let scope = value.split('/').next().unwrap();
        let scoped = config
            .and_then(|v| v.get(format!("{scope}:registry")))
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(literal);
        if let Some(scoped) = scoped {
            endpoint = scoped;
        } else {
            endpoint = unknown();
        }
    }
    if !matches!(&endpoint, ResourceExpr::Literal { value } if value.starts_with("https://") || value.starts_with("http://"))
    {
        endpoint = unknown();
        environment_boundary(
            builder,
            node,
            &["artifact", "network"],
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            "npm registry configuration is unavailable or symbolic",
        );
    }
    if parsed
        .value("tag")
        .is_some_and(|tag| tag.as_literal().is_none())
    {
        boundary(
            builder,
            node,
            &["artifact"],
            BoundaryReason::MODEL_COVERAGE,
            "npm distribution tag is symbolic; package version remains independent",
        );
    }
    let mut attrs = Attrs::new();
    attrs.insert("active".into(), AttrValue::Bool(true));
    attrs.insert("dry_run".into(), AttrValue::Bool(false));
    attrs.insert("package_manager".into(), AttrValue::String("npm".into()));
    attrs.insert("ecosystem".into(), AttrValue::String("npm".into()));
    if publish {
        attrs.insert("action".into(), AttrValue::String("publish".into()));
        attrs.insert("selection".into(), AttrValue::String("unknown".into()));
    }
    if let Some(tag) = parsed
        .text("tag")
        .or_else(|| config.and_then(|v| v.get("tag")).and_then(|v| v.as_str()))
    {
        attrs.insert("tag".into(), AttrValue::String(tag.into()));
    }
    if let Some(private) = selected_manifest
        .and_then(|v| v.get("private"))
        .and_then(|v| v.as_bool())
    {
        attrs.insert("private".into(), AttrValue::Bool(private));
    }
    if publish && !tarball {
        boundary(
            builder,
            node,
            &["filesystem"],
            BoundaryReason::MODEL_COVERAGE,
            "npm pack rules and packed file inventory are unmodeled",
        );
    }
    if !ignore_scripts
        && publish
        && let Some(manifest) = &manifest
    {
        for hook in [
            "prepublishOnly",
            "prepack",
            "prepare",
            "postpack",
            "publish",
            "postpublish",
        ] {
            if let Some(source) = manifest
                .get("scripts")
                .and_then(|v| v.get(hook))
                .and_then(|v| v.as_str())
            {
                let runtime_cwd = crate::paths::join_file(ctx.runtime_cwd, &directory);
                {
                    let cwd_resource = Some(ctx.resolve_fs_word(&Word::literal(&directory)));
                    let cwd_node = (cwd_resource.as_ref() == ctx.cwd_resource.as_ref())
                        .then_some(ctx.cwd_node)
                        .flatten();
                    ctx.nest.nest(
                        builder,
                        Transition::file(Subject::Shell {
                            source: source.into(),
                            cwd: ctx.cwd.map(|cwd| crate::paths::join_cwd(cwd, &directory)),
                            context: Default::default(),
                        })
                        .origin(format!("{directory}/package.json"))
                        .kind(ExecutionEdgeKind::PackageHook)
                        .source_cwd(runtime_cwd.as_deref())
                        .runtime_cwd(runtime_cwd.as_deref())
                        .cwd(cwd_resource, cwd_node),
                        &[source_node],
                        ctx.depth,
                    );
                };
            }
        }
    }
    if !(dry_run
        || (publish
            && !unsettled
            && manifest
                .as_ref()
                .and_then(|v| v.get("private"))
                .and_then(|v| v.as_bool())
                == Some(true)))
    {
        mutation(
            builder,
            ctx,
            node,
            (source_node != node).then_some(source_node),
            operand.unwrap_or(subindex),
            if publish {
                "artifact.publish"
            } else {
                "artifact.delete"
            },
            artifact(ArtifactEcosystem::Npm, endpoint, name, reference),
            attrs,
            Some(effinterp_proto::RequestAssurance::Exact),
        );
    } else {
        let endpoint = match &endpoint {
            ResourceExpr::Literal { value } => crate::models::net::parse_endpoint(value)
                .map(|identity| ResourceExpr::Concrete { identity }),
            _ => None,
        }
        .unwrap_or(unresolved_resource("network"));
        arg_effect(
            builder,
            ctx,
            source_node,
            operand.unwrap_or(subindex) as u32,
            "network.request",
            endpoint,
            Attrs::new(),
        );
        environment_boundary(
            builder,
            node,
            &["network", "filesystem"],
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            "npm registry checks can occur without direct publication or deletion",
        );
    }
    true
}

impl CommandModel for GithubRelease {
    fn domains(&self) -> &'static [&'static str] {
        &[
            "artifact",
            "environment",
            "filesystem",
            "git",
            "network",
            "process",
        ]
    }

    fn id(&self) -> &'static str {
        "p18b/devtools/gh@v2"
    }
    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<super::ModelCausalBinding> {
        let mut bindings = match gist_public_spelled_out(argv) {
            Some(argv) => self.owner.causal_bindings(&argv),
            None => self.owner.causal_bindings(argv),
        };
        let notes_stdin = argv
            .iter()
            .any(|word| word.as_literal() == Some("--notes-file=-"))
            || argv.windows(2).any(|pair| {
                matches!(pair[0].as_literal(), Some("--notes-file" | "-F"))
                    && pair[1].as_literal() == Some("-")
            });
        if notes_stdin && argv.iter().any(|word| word.as_literal() == Some("release")) {
            bindings.push(super::ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: super::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
                to: super::ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
            });
        }
        // The gh document binds stdin to a gist conservatively; a literal
        // `gh gist create` whose files are missing or `-` uploads stdin itself.
        if gist_create_reads_stdin(argv) {
            bindings.push(super::ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: super::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
                to: super::ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
            });
        }
        if argv.iter().any(|word| word.as_literal() == Some("release"))
            && argv
                .iter()
                .any(|word| matches!(word.as_literal(), Some("create" | "new")))
        {
            bindings.push(super::ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: super::ModelBindingEnd::Effect {
                    operation: "filesystem.read".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
                to: super::ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
            });
        }
        bindings
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let mut parsed = options(
            ctx,
            1,
            &[
                "--draft",
                "--prerelease",
                "--verify-tag",
                "--yes",
                "--cleanup-tag",
            ],
            &["--repo", "--target", "--title", "--notes", "--notes-file"],
            &[
                ("-R", "--repo"),
                ("-d", "--draft"),
                ("-p", "--prerelease"),
                ("-y", "--yes"),
                ("-t", "--title"),
                ("-n", "--notes"),
                ("-F", "--notes-file"),
            ],
        );
        let command: Vec<_> = parsed
            .operands
            .iter()
            .take(2)
            .map(|i| ctx.argv[*i].as_literal())
            .collect();
        let create = matches!(
            command.as_slice(),
            [Some("release"), Some("create" | "new")]
        );
        if matches!(command.as_slice(), [Some("release"), Some("delete")]) {
            let start = builder.effects_len();
            let owner_node = super::model_application_node(builder, self.owner.as_ref(), &[node]);
            self.owner.apply(builder, ctx, owner_node);
            // The declarative leaf owns deletion syntax and controls. Preserve the
            // artifact effect only when that leaf accepted a release deletion.
            let accepted = (start..builder.effects_len()).find(|&index| {
                builder.effect_string_attribute(index, "hosted_object_kind") == Some("release")
            });
            let Some(effect) = accepted else {
                return;
            };
            let tag = builder
                .effect_string_attribute(effect, "hosted_target")
                .unwrap()
                .to_string();
            let repo = builder.effect_string_attribute(effect, "hosted_repository");
            let (endpoint, name) = match repo
                .map(|repo| repo.split('/').collect::<Vec<_>>())
                .as_deref()
            {
                Some([host, owner, repo]) => (literal(host), literal(&format!("{owner}/{repo}"))),
                Some([owner, repo]) => (unknown(), literal(&format!("{owner}/{repo}"))),
                _ => (unknown(), unknown()),
            };
            builder.declare_coverage(Domain::new("artifact"), CoverageLevel::Full);
            if endpoint == unknown() {
                boundary(
                    builder,
                    owner_node,
                    &["artifact"],
                    BoundaryReason::MODEL_COVERAGE,
                    "GitHub release endpoint requires repository or host context",
                );
            }
            let index = parsed.operands[2];
            arg_effect(
                builder,
                ctx,
                owner_node,
                index as u32,
                "artifact.delete",
                artifact(
                    ArtifactEcosystem::GithubRelease,
                    endpoint,
                    name,
                    ArtifactReference::Tag {
                        value: literal(&tag),
                    },
                ),
                Attrs::new(),
            );
            return;
        }
        if !create {
            let start = builder.effects_len();
            let node = super::model_application_node(builder, self.owner.as_ref(), &[node]);
            match gist_public_spelled_out(ctx.argv) {
                Some(argv) => {
                    let ctx = InvocationCtx {
                        argv: &argv,
                        stdin: ctx.stdin,
                        argv_provenance: ctx.argv_provenance,
                        cwd: ctx.cwd,
                        cwd_resource: ctx.cwd_resource.clone(),
                        runtime_cwd: ctx.runtime_cwd,
                        scope: ctx.scope,
                        cwd_node: ctx.cwd_node,
                        nest: ctx.nest,
                        depth: ctx.depth,
                        model_stack: ctx.model_stack.clone(),
                    };
                    self.owner.apply(builder, &ctx, node);
                }
                None => self.owner.apply(builder, ctx, node),
            }
            super::gh_refs::api_ref_request(builder, ctx, node, start);
            release_download_assets(builder, ctx, node, start);
            return;
        }
        let node = reviewed(
            builder,
            ctx,
            node,
            "gh/release@2026-09-09:https://cli.github.com/manual/gh_release_create;https://cli.github.com/manual/gh_release_delete",
        );
        parsed.operands.drain(..2);
        if parsed.invalid
            || parsed.values.contains_key("--yes")
            || parsed.values.contains_key("--cleanup-tag")
            || (parsed.values.contains_key("--notes") && parsed.values.contains_key("--notes-file"))
        {
            boundary(
                builder,
                node,
                &["artifact", "network", "git", "filesystem"],
                BoundaryReason::MODEL_COVERAGE,
                "unmodeled or conflicting gh release options",
            );
            return;
        }
        for variable in ["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_CONFIG_DIR"] {
            arg_effect(
                builder,
                ctx,
                node,
                0,
                "environment.read",
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable {
                        name: variable.into(),
                    },
                },
                Attrs::new(),
            );
        }
        let config_paths = [
            ("GH_CONFIG_DIR", "/hosts.yml"),
            ("XDG_CONFIG_HOME", "/gh/hosts.yml"),
            ("HOME", "/.config/gh/hosts.yml"),
        ]
        .into_iter()
        .map(|(variable, suffix)| {
            ctx.resolve_fs_word(&Word::new(vec![
                crate::word::WordPart::Env(variable.into()),
                crate::word::WordPart::Literal(suffix.into()),
            ]))
        })
        .collect();
        arg_effect(
            builder,
            ctx,
            node,
            0,
            "filesystem.read",
            ResourceExpr::Union {
                alternatives: config_paths,
            },
            Attrs::new(),
        );
        environment_boundary(
            builder,
            node,
            &["environment"],
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            "GitHub CLI configuration may read additional environment inputs",
        );
        let mut endpoint = unknown();
        let mut name = unknown();
        if let Some(repo) = parsed.text("--repo") {
            let pieces: Vec<_> = repo.split('/').collect();
            if pieces.iter().all(|s| !s.is_empty()) {
                match pieces.as_slice() {
                    [owner, repo] => {
                        endpoint = literal("github.com");
                        name = literal(&format!("{owner}/{repo}"));
                    }
                    [host, owner, repo] => {
                        endpoint = literal(host);
                        name = literal(&format!("{owner}/{repo}"));
                    }
                    _ => {}
                }
            }
        }
        if endpoint == unknown() {
            boundary(
                builder,
                node,
                &["artifact", "network"],
                BoundaryReason::MODEL_COVERAGE,
                "GitHub repository evidence is missing or symbolic",
            );
        }
        let index = parsed.operands.first().copied().unwrap_or(0);
        let tag = parsed
            .operands
            .first()
            .map(|index| word_resource(&ctx.argv[*index]))
            .unwrap_or_else(unknown);
        if parsed.operands.is_empty() || ctx.argv[index].as_literal().is_none_or(str::is_empty) {
            boundary(
                builder,
                node,
                &["artifact"],
                BoundaryReason::MODEL_COVERAGE,
                "GitHub release tag is interactive or symbolic",
            );
        }
        if create {
            for &index in parsed.operands.iter().skip(1) {
                let Some(path) = ctx.argv[index].as_literal() else {
                    boundary(
                        builder,
                        node,
                        &["filesystem", "network"],
                        BoundaryReason::MODEL_COVERAGE,
                        "symbolic GitHub release asset inventory",
                    );
                    continue;
                };
                let path = path.split('#').next().unwrap();
                arg_effect(
                    builder,
                    ctx,
                    node,
                    index as u32,
                    "filesystem.read",
                    ctx.resolve_fs_word(&Word::literal(path)),
                    super::common::program_input_attrs(),
                );
            }
            if let Some(notes) = parsed.values.get("--notes-file") {
                if notes.as_literal() == Some("-") {
                    if let Some(stdin) = ctx.stdin {
                        let _ = builder.node(
                            ProvenanceKind::ModelApplication {
                                model: "gh/release-notes-stdin@v1".into(),
                            },
                            &stdin.provenance,
                        );
                    }
                } else {
                    arg_effect(
                        builder,
                        ctx,
                        node,
                        0,
                        "filesystem.read",
                        ctx.resolve_fs_word(notes),
                        super::common::program_input_attrs(),
                    );
                }
            }
            if !parsed.boolean("--verify-tag") {
                boundary(
                    builder,
                    node,
                    &["git"],
                    BoundaryReason::MODEL_COVERAGE,
                    "gh may create a remote Git tag; GitRepository cannot locate remote refs",
                );
            }
        }
        let attrs = parsed
            .values
            .iter()
            .filter_map(|(key, value)| {
                value.as_literal().map(|v| {
                    (
                        key.trim_start_matches('-').into(),
                        AttrValue::String(v.into()),
                    )
                })
            })
            .collect();
        mutation(
            builder,
            ctx,
            node,
            None,
            index,
            if parsed.boolean("--draft") {
                "artifact.create"
            } else {
                "artifact.publish"
            },
            artifact(
                ArtifactEcosystem::GithubRelease,
                endpoint,
                name,
                ArtifactReference::Tag {
                    value: if tag == literal("") { unknown() } else { tag },
                },
            ),
            attrs,
            None,
        );
    }
}
