//! git: subcommand dispatch with a small effect taxonomy mapped from nah's
//! guard families. Operations (domain "git"): read, index_write,
//! worktree_write, worktree_discard, ref_update, history_rewrite,
//! recovery_destroy, config_write, remote_sync.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionInputRole, ExecutionPhase, ExecutionSelector, Modality, Operation,
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceFamily, ResourceIdentity,
};

use crate::models::args::{FlagSpec, Scanned, matches_long_option, scan, scan_literal};

use crate::builder::PlanBuilder;
use crate::models::common::{
    Attrs, RuntimeSourceLanguage, arg_node, attrs, fs_arg_effect, fs_arg_node, opaque_source,
    program_output_attrs, runtime_searched_source,
};
use crate::models::net::parse_endpoint;
use crate::models::{CommandModel, InvocationCtx};
use crate::paths::{fs_word_uses_cwd, resolve_fs_word, resolve_fs_word_with_cwd};
use crate::resource_transfer::TransferBinding;
use crate::word::{Word, WordPart};

pub(super) fn git_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(Git), Box::new(GitFilterRepo)]
}

const ALL_DOMAINS: [&str; effinterp_proto::DOMAINS.len()] = effinterp_proto::DOMAINS;

struct Git;

fn request_attrs(pairs: &[(&str, bool)]) -> Attrs {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), AttrValue::Bool(*value)))
        .collect()
}

/// One destination of a push request, as far as the model knows it.
pub(super) struct PushedRef<'a> {
    /// The destination ref without a `refs/heads/` prefix.
    pub(super) destination: Option<String>,
    /// Empty for a deletion.
    pub(super) source: Option<&'a str>,
    pub(super) forced: Option<bool>,
    pub(super) deleted: Option<bool>,
    /// Git certainly pushes this destination with these properties. A
    /// configured mapping that an unread or unestablished setting may change
    /// is not certain.
    pub(super) certain: bool,
}

/// A refspec word whose leading `+` is certain: a literal one, or one whose
/// literal start or unquoted pattern begins with it. `+` is not a pattern
/// character, so every pathname a pattern expands to keeps it, as does the
/// pattern git receives when nothing matches.
fn refspec_word_forced(word: &Word) -> bool {
    match word.parts.first() {
        Some(WordPart::Literal(text) | WordPart::Glob(text)) => text.starts_with('+'),
        _ => false,
    }
}

/// The destination ref as the push guards compare it.
pub(super) fn normalize_push_ref(reference: &str) -> String {
    reference
        .strip_prefix("refs/heads/")
        .unwrap_or(reference)
        .to_string()
}

/// Insert the per-property destination lists of a push, each a list of
/// destination names joined per destination here, so no query has to align
/// lists by index.
///
/// When the destination set is `complete`, four lists enumerate it, each left
/// out when its property is unknown for any destination:
/// - `updated_destinations`: not deleted, with a non-empty source;
/// - `deleted_destinations`;
/// - `leased_destinations`: updated, and a lease is requested for it, whether
///   or not an explicit force overrides that lease;
/// - `unleased_forced_destinations`: forced, not deleted, and no lease
///   requested for it.
///
/// `HEAD` and `@` push the current branch, whose name the model does not
/// know, so a destination spelled that way leaves out each list that
/// selects it.
///
/// Whatever the set, `known_updated_destinations`,
/// `known_deleted_destinations`, `known_leased_destinations` and
/// `known_unleased_forced_destinations` name the certain destinations known
/// to have that property, `HEAD` and `@` as spelled. A forced destination the
/// model cannot name, such as the branches a forced matching `+:` push
/// selects, is the empty string: its force and lease are known without its
/// name. A deletion is a witness only by its name, as a symbolic `--delete`
/// operand is spelled empty. The witness lists are sound only for a match:
/// an empty one says nothing about the destinations the model does not know.
///
/// `possibly_unleased_forced` is true when some forced, not deleted
/// destination may be unleased where no witness can say so: a destination
/// that is not certain and would be forced without a lease, or a certain,
/// named destination whose lease is unknown and whose named lease targets
/// none of them spells. The lease is unknown for `HEAD` and `@`, whose branch
/// may still be a lease target, and, when a target is spelled with characters
/// no ref name holds, for every destination no other target spells; comparing
/// the spelling over-reports exactly as the push guards have.
///
/// `leases` is the all-refs flag and the lease targets as spelled, or `None`
/// when the options that state them are unknown; `lease_targets_known` says
/// whether each spelled target names a ref. A destination the model does not
/// know is `None`.
pub(super) fn push_destination_lists(
    attrs: &mut Attrs,
    destinations: &[PushedRef<'_>],
    leases: Option<(bool, &[&str])>,
    lease_targets_known: bool,
    complete: bool,
) {
    let current_branch = |name: &str| matches!(name, "HEAD" | "@");
    // Without a name, only an all-refs lease or no lease target decides it.
    // A target spelling the name proves its lease even beside unreadable
    // targets; only a miss needs every target known.
    let leased = |name: Option<&str>| {
        let (all_refs, targets) = leases?;
        match name {
            _ if all_refs => Some(true),
            Some(name)
                if !current_branch(name)
                    && targets
                        .iter()
                        .any(|target| normalize_push_ref(target) == name) =>
            {
                Some(true)
            }
            _ if !lease_targets_known => None,
            _ if targets.is_empty() => Some(false),
            Some(name) if !current_branch(name) => Some(false),
            _ => None,
        }
    };
    let updated = |destination: &PushedRef<'_>| {
        Some(!destination.deleted? && !destination.source?.is_empty())
    };
    let deleted = |destination: &PushedRef<'_>| destination.deleted;
    let unleased_forced = |destination: &PushedRef<'_>| {
        Some(
            destination.forced?
                && !destination.deleted?
                && !leased(destination.destination.as_deref())?,
        )
    };
    let known = |has: &dyn Fn(&PushedRef<'_>) -> Option<bool>, unnamed: bool| {
        AttrValue::List(
            destinations
                .iter()
                .filter(|destination| destination.certain && has(destination) == Some(true))
                .filter_map(|destination| {
                    let name = destination.destination.clone();
                    Some(AttrValue::String(if unnamed {
                        name.unwrap_or_default()
                    } else {
                        name.filter(|name| !name.is_empty())?
                    }))
                })
                .collect(),
        )
    };
    let leased_update = |destination: &PushedRef<'_>| {
        Some(updated(destination)? && leased(destination.destination.as_deref())?)
    };
    attrs.insert("known_deleted_destinations".into(), known(&deleted, false));
    attrs.insert(
        "known_unleased_forced_destinations".into(),
        known(&unleased_forced, true),
    );
    attrs.insert("known_updated_destinations".into(), known(&updated, false));
    attrs.insert(
        "known_leased_destinations".into(),
        known(&leased_update, false),
    );
    // A named lease compared with the destination's spelling where the lease
    // is unknown, as the push guards have compared it.
    let spelled_unleased = |destination: &PushedRef<'_>| {
        let (all_refs, targets) = leases?;
        let name = destination.destination.as_deref()?;
        Some(
            leased(Some(name)).is_none()
                && !all_refs
                && !targets.is_empty()
                && !targets
                    .iter()
                    .any(|target| normalize_push_ref(target) == name),
        )
    };
    attrs.insert(
        "possibly_unleased_forced".into(),
        AttrValue::Bool(destinations.iter().any(|destination| {
            destination.forced == Some(true)
                && destination.deleted == Some(false)
                && if destination.certain {
                    spelled_unleased(destination) == Some(true)
                } else {
                    unleased_forced(destination) == Some(true)
                }
        })),
    );
    if !complete {
        return;
    }
    // Only a destination a list selects needs its name.
    let list = |has: &dyn Fn(&PushedRef<'_>) -> Option<bool>| {
        let mut selected = Vec::new();
        for destination in destinations {
            if has(destination)? {
                let name = destination
                    .destination
                    .as_deref()
                    .filter(|name| !current_branch(name))?;
                selected.push(AttrValue::String(name.into()));
            }
        }
        Some(AttrValue::List(selected))
    };
    for (key, value) in [
        ("updated_destinations", list(&updated)),
        ("deleted_destinations", list(&deleted)),
        ("leased_destinations", list(&leased_update)),
        ("unleased_forced_destinations", list(&unleased_forced)),
    ] {
        if let Some(value) = value {
            attrs.insert(key.into(), value);
        }
    }
}

fn string_list(values: &[impl AsRef<str>]) -> AttrValue {
    AttrValue::List(
        values
            .iter()
            .map(|value| AttrValue::String(value.as_ref().into()))
            .collect(),
    )
}

/// Global options collected before the subcommand.
struct GlobalPath {
    index: u32,
    word: Word,
}

struct Globals {
    /// Last -C path (git chains them; sequential relative resolution is out
    /// of scope, so a symbolic or repeated-relative chain widens).
    repo_dir: Option<GlobalPath>,
    work_tree: Option<GlobalPath>,
    git_dir: Option<GlobalPath>,
    /// The configuration the invocation reads, in precedence order, lowest
    /// first: earlier `git config` writes in this subject by scope (system,
    /// global, local, worktree), then the environment's settings, then -c
    /// key=value pairs.
    configs: Vec<ConfigEntry>,
    /// The `GIT_CONFIG_PARAMETERS` value git hands the commands it runs when
    /// -c options add to it: `None` when there are none (the inherited value
    /// passes through), `Some(None)` when it is not statically known.
    command_parameters: Option<Option<String>>,
    /// -c alias.<name>=<expansion> pairs, with the argv position of the value.
    aliases: Vec<Alias>,
    /// A -c was not statically resolvable.
    opaque_config: bool,
    /// `--literal-pathspecs`, `--no-literal-pathspecs`, `--glob-pathspecs`
    /// or `--noglob-pathspecs`, in argument order.
    pathspec_options: Vec<&'static str>,
}

/// One setting the invocation may read.
struct ConfigEntry {
    /// The key, empty when the model cannot read it: such a setting may be
    /// any key, and its value is unknown.
    key: String,
    /// The value, `None` when the model cannot read it.
    value: Option<String>,
    /// The setting certainly reaches this invocation, replacing what lower
    /// entries leave: the environment's settings and -c. An earlier
    /// `git config` write only adds a possible value.
    replaces: bool,
    /// An include whose file the model could not read: it may set any key
    /// to any value, which the model does not take as a possible value of
    /// its own.
    unobserved: bool,
}

/// What an invocation's configuration may hold for one key.
struct ConfigValues<'a> {
    /// Each value some execution may leave; `None` for one the model cannot
    /// read.
    values: Vec<Option<&'a str>>,
    /// The key may still hold whatever the unobserved configuration files
    /// hold, which the model takes as unset.
    unset: bool,
    /// An include the model could not read may set the key after `values`.
    unknown: bool,
}

impl<'a> ConfigValues<'a> {
    /// The one value every execution leaves, when there is one.
    fn certain(&self) -> Option<Option<&'a str>> {
        match self.values.as_slice() {
            [first, rest @ ..] if !self.unset && rest.iter().all(|value| value == first) => {
                Some(*first)
            }
            _ => None,
        }
    }
}

struct Alias {
    name: String,
    expansion: String,
    value_index: Option<u32>,
    source_node: Option<ProvenanceRef>,
}

/// git looks an alias up only for a name it has no command for, so an alias
/// never shadows one of these.
const GIT_SUBCOMMANDS: &[&str] = &[
    "add",
    "am",
    "annotate",
    "apply",
    "archive",
    "bisect",
    "blame",
    "branch",
    "bundle",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "checkout",
    "checkout-index",
    "cherry",
    "cherry-pick",
    "clean",
    "clone",
    "column",
    "commit",
    "commit-tree",
    "config",
    "count-objects",
    "credential",
    "describe",
    "diff",
    "diff-files",
    "diff-index",
    "diff-tree",
    "difftool",
    "fast-export",
    "fast-import",
    "fetch",
    "fetch-pack",
    "filter-branch",
    "fmt-merge-msg",
    "for-each-ref",
    "for-each-repo",
    "format-patch",
    "fsck",
    "gc",
    "grep",
    "hash-object",
    "help",
    "hook",
    "index-pack",
    "init",
    "interpret-trailers",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "mailinfo",
    "mailsplit",
    "maintenance",
    "merge",
    "merge-base",
    "merge-file",
    "merge-index",
    "merge-tree",
    "mergetool",
    "mktag",
    "mktree",
    "multi-pack-index",
    "mv",
    "name-rev",
    "notes",
    "pack-objects",
    "pack-refs",
    "patch-id",
    "prune",
    "prune-packed",
    "pull",
    "push",
    "range-diff",
    "read-tree",
    "rebase",
    "reflog",
    "remote",
    "repack",
    "replace",
    "request-pull",
    "rerere",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "revert",
    "rm",
    "send-pack",
    "shortlog",
    "show",
    "show-branch",
    "show-index",
    "show-ref",
    "sparse-checkout",
    "stash",
    "status",
    "stripspace",
    "submodule",
    "switch",
    "symbolic-ref",
    "tag",
    "unpack-file",
    "unpack-objects",
    "update-index",
    "update-ref",
    "update-server-info",
    "upload-archive",
    "upload-pack",
    "var",
    "verify-commit",
    "verify-pack",
    "verify-tag",
    "whatchanged",
    "worktree",
    "write-tree",
];

/// An alias may name another alias; git stops at a bounded chain and so does
/// this walk.
const GIT_ALIAS_DEPTH: usize = 4;

/// Git's split_cmdline removes quotes and escapes without shell expansion.
/// Even shell metacharacters are ordinary argument bytes in a non-shell alias.
fn split_alias(expansion: &str) -> Option<Vec<String>> {
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
fn repository_aliases(
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
fn expand_includes(
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
fn config_values<'a>(globals: &'a Globals, key: &str) -> ConfigValues<'a> {
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
fn config_value<'a>(globals: &'a Globals, key: &str) -> Option<Option<&'a str>> {
    let found = config_values(globals, key);
    if found.values.is_empty() {
        return None;
    }
    Some(found.certain().flatten())
}

/// One value `remote_settings` finds.
#[derive(Clone, Copy)]
enum RemoteSetting<'a> {
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
fn remote_settings<'a>(
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
fn inherited_configs(
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

/// A repository expression and the foreach call that binds the
/// `<git_submodule>` it names; each call binds its own submodules.
#[derive(Clone, Copy)]
struct ScopedRepo<'a> {
    expr: &'a ResourceExpr,
    binding: Option<usize>,
}

impl<'a> ScopedRepo<'a> {
    fn new(expr: &'a ResourceExpr, binding: Option<usize>) -> Self {
        Self {
            expr,
            binding: binding.filter(|_| names_submodule(expr)),
        }
    }
}

/// The variables that select a repository or the configuration files git
/// reads, besides discovery from the cwd.
const REPOSITORY_SELECTORS: &[&str] = &[
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
];

/// Whether the invocation finds its repository and configuration only by
/// discovery from its cwd: no -C, --git-dir or --work-tree, none of
/// `REPOSITORY_SELECTORS` beyond the `GIT_DIR=.git` a foreach command runs
/// with, no `include` setting from -c or `GIT_CONFIG_PARAMETERS`, and no
/// injected environment or earlier export of an unknown name that may set
/// any of them.
fn selects_by_discovery(builder: &PlanBuilder, ctx: &InvocationCtx<'_>, globals: &Globals) -> bool {
    let include = |key: &str| {
        key.is_empty()
            || key
                .get(..7)
                .is_some_and(|section| section.eq_ignore_ascii_case("include"))
    };
    let foreach_git_dir = builder.git_foreach_binding().is_some()
        && matches!(
            ctx.environment_value("GIT_DIR"),
            Some(ResourceExpr::Literal { value }) if value == ".git"
        );
    globals.repo_dir.is_none()
        && globals.git_dir.is_none()
        && globals.work_tree.is_none()
        && !globals.configs.iter().any(|entry| include(&entry.key))
        && ctx.nest.injected_environment_node().is_none()
        && !builder.environment_names_unknown()
        && REPOSITORY_SELECTORS.iter().all(|name| {
            ctx.environment_value(name).is_none() || *name == "GIT_DIR" && foreach_git_dir
        })
        && match ctx.environment_value("GIT_CONFIG_PARAMETERS") {
            None => true,
            Some(ResourceExpr::Literal { value }) => config_parameters(&value)
                .is_some_and(|pairs| !pairs.iter().any(|(key, _)| include(key))),
            Some(_) => false,
        }
}

/// Whether one repository expression is a `submodule foreach` submodule and
/// the other its superproject, whose own repository file the submodule does
/// not read. That holds only while the submodule's git dir is the one
/// foreach selects and the superproject expression is resolved, since equal
/// unresolved expressions may name different paths. Nothing else separates
/// configuration: different paths, worktrees or git dirs may share one
/// repository's configuration through discovery, a common dir or includes.
fn superproject_and_submodule(builder: &PlanBuilder, a: ScopedRepo<'_>, b: ScopedRepo<'_>) -> bool {
    [(a, b), (b, a)].into_iter().any(|(outer, inner)| {
        inner.binding.is_some_and(|binding| {
            let foreach = builder.git_foreach(binding);
            let superproject = ScopedRepo::new(&foreach.superproject, foreach.parent);
            git_dir_resource(inner.expr) == Some(&foreach_git_dir())
                && outer.expr == superproject.expr
                && outer.binding == superproject.binding
                && resolved(outer.expr)
        })
    })
}

/// Whether `expr` names one path: no part of it is unresolved, one of
/// several alternatives, or an unbound parameter.
fn resolved(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Literal { .. } => true,
        ResourceExpr::Parameter { .. } => *expr == foreach_submodule(),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { .. },
        } => true,
        ResourceExpr::Concrete {
            identity:
                ResourceIdentity::GitRepository {
                    worktree,
                    git_dir,
                    pathspec,
                },
        } => [worktree, git_dir, pathspec]
            .into_iter()
            .flatten()
            .all(|part| resolved(part)),
        ResourceExpr::Join { parts } => parts.iter().all(resolved),
        _ => false,
    }
}

/// The submodule a `submodule foreach` command runs in.
fn foreach_submodule() -> ResourceExpr {
    ResourceExpr::Parameter {
        name: "git_submodule".into(),
    }
}

/// The git dir foreach selects for its command with `GIT_DIR=.git`.
fn foreach_git_dir() -> ResourceExpr {
    resolve_fs_word_with_cwd(&Word::literal(".git"), Some(foreach_submodule()))
}

/// Whether `expr` names the submodule a foreach call binds.
fn names_submodule(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Parameter { .. } => *expr == foreach_submodule(),
        ResourceExpr::Concrete {
            identity:
                ResourceIdentity::GitRepository {
                    worktree, git_dir, ..
                },
        } => [worktree, git_dir]
            .into_iter()
            .flatten()
            .any(|part| names_submodule(part)),
        ResourceExpr::Join { parts } => parts.iter().any(names_submodule),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(names_submodule),
        ResourceExpr::Property { base, .. } => names_submodule(base),
        _ => false,
    }
}

fn git_dir_resource(repo: &ResourceExpr) -> Option<&ResourceExpr> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                git_dir: Some(git_dir),
                ..
            },
    } = repo
    else {
        return None;
    };
    Some(git_dir.as_ref())
}

/// Parse `GIT_CONFIG_PARAMETERS` the way git's `parse_config_env_list`
/// does: whitespace-separated single-quoted `'key'='value'` pairs, the
/// implicit boolean `'key'=`, or the older `'key=value'` form. A key
/// without a value is a boolean true. `None` for text git refuses.
fn config_parameters(text: &str) -> Option<Vec<(String, String)>> {
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
fn git_bool(value: &str) -> Option<bool> {
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

/// Expiry selectors that expire everything at once, whatever its age. Git
/// hands a value other than its exact keywords to approxidate, which reads
/// `now` in any case.
fn immediate_expiry(value: &str) -> bool {
    matches!(value, "all" | "0") || value.eq_ignore_ascii_case("now")
}

/// `:/` or its long-magic spelling `:(top)`: the whole working tree. So is
/// a top-anchored pattern that matches every path under the pathspec mode in
/// effect, such as `:/*` or `:(top,glob)**/*`; a mode the model cannot read
/// may leave it matching everything, so it counts too.
fn is_worktree_root_pathspec(s: &SubCtx<'_>, path: &Word) -> bool {
    let Some(text) = path.as_literal() else {
        return false;
    };
    let top_anchored = if let Some(rest) = text.strip_prefix(":/") {
        // Further short magic (`:/!`, `:/^`, `:/:`) is not a plain top anchor.
        (!rest.starts_with(['!', '^', ':'])).then_some((rest, false))
    } else {
        text.strip_prefix(":(")
            .and_then(|magic| magic.split_once(')'))
            .and_then(|(magic, rest)| {
                let magic = magic.split(',').collect::<Vec<_>>();
                (magic.contains(&"top") && magic.iter().all(|word| matches!(*word, "top" | "glob")))
                    .then(|| (rest, magic.contains(&"glob")))
            })
    };
    match top_anchored {
        None => false,
        Some(("", _)) => true,
        Some((rest, true)) => {
            matches_everything(s, &Word::literal(format!(":(glob){rest}"))) != Some(false)
        }
        Some((rest, false)) => matches_everything(s, &Word::literal(rest)) != Some(false),
    }
}

/// `:/<path>` or `:(top)<path>`: a path below the top of the working tree,
/// with no further magic such as `:/!` or `:/^` exclusion.
fn positive_top_relative_pathspec(path: &Word) -> bool {
    path.as_literal()
        .and_then(|text| text.strip_prefix(":/").or(text.strip_prefix(":(top)")))
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with(['!', '^', ':']))
}

fn worktree_resource(repo: &ResourceExpr) -> Option<&ResourceExpr> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                ..
            },
    } = repo
    else {
        return None;
    };
    Some(worktree.as_ref())
}

fn environment_path(
    ctx: &InvocationCtx<'_>,
    name: &str,
    base: Option<ResourceExpr>,
) -> Option<ResourceExpr> {
    match ctx.environment_value(name) {
        Some(ResourceExpr::Literal { value }) => Some(resolve_fs_word_with_cwd(
            &Word::literal(value),
            base.or_else(|| ctx.cwd_resource()),
        )),
        Some(_) => Some(ResourceExpr::Unresolved {
            family: effinterp_proto::ResourceFamily::new("filesystem"),
        }),
        None => None,
    }
}

/// Git discovers the repository upward from the worktree its request
/// names: no work tree or git dir is named, only a start directory.
fn discovers_from_worktree(globals: &Globals, ctx: &InvocationCtx<'_>) -> bool {
    globals.work_tree.is_none()
        && globals.git_dir.is_none()
        && ctx.environment_value("GIT_WORK_TREE").is_none()
        && ctx.environment_value("GIT_DIR").is_none()
}

/// Git discovers the repository from the invocation's own directory: it
/// discovers from the worktree, and any `-C` spells that same directory.
fn root_uses_invocation_cwd(globals: &Globals, ctx: &InvocationCtx<'_>) -> bool {
    discovers_from_worktree(globals, ctx)
        && globals
            .repo_dir
            .as_ref()
            .is_none_or(|dir| ctx.resolve_fs_word(&dir.word) == invocation_directory(ctx))
}

fn worktree_base(globals: &Globals, ctx: &InvocationCtx) -> ResourceExpr {
    match &globals.repo_dir {
        Some(dir) => ctx.resolve_fs_word(&dir.word),
        None => invocation_directory(ctx),
    }
}

/// With no -C/--git-dir the repo is wherever the process runs. A relative
/// ambient cwd descends from discovery's script-directory assumption, and
/// resolving it would fabricate a repo path from the entry file's own
/// location (`git push` in script/release is not a push of <cwd>/script).
/// Only an absolute cwd (an explicit `cd /path`) is real.
fn invocation_directory(ctx: &InvocationCtx) -> ResourceExpr {
    match ctx.cwd {
        // The cwd itself names the platform its spelling is resolved on.
        Some(cwd) if crate::paths::is_absolute(cwd) => {
            resolve_fs_word(&Word::literal(cwd), Some(cwd))
        }
        Some(_) => ResourceExpr::Parameter {
            name: "cwd".to_string(),
        },
        None => ctx
            .cwd_resource()
            .unwrap_or_else(|| ResourceExpr::Parameter {
                name: "cwd".to_string(),
            }),
    }
}

fn repo_expr(globals: &Globals, ctx: &InvocationCtx) -> ResourceExpr {
    let base = worktree_base(globals, ctx);
    let worktree = globals
        .work_tree
        .as_ref()
        .map(|worktree| resolve_fs_word_with_cwd(&worktree.word, Some(base.clone())))
        .or_else(|| environment_path(ctx, "GIT_WORK_TREE", Some(base.clone())))
        .unwrap_or(base.clone());
    let git_dir = globals
        .git_dir
        .as_ref()
        .map(|git_dir| resolve_fs_word_with_cwd(&git_dir.word, Some(base.clone())));
    let git_dir = git_dir.or_else(|| environment_path(ctx, "GIT_DIR", Some(base.clone())));
    ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: Some(Box::new(worktree)),
            git_dir: git_dir.map(Box::new),
            pathspec: None,
        },
    }
}

fn repo_uses_cwd(globals: &Globals) -> bool {
    let base_uses_cwd = globals
        .repo_dir
        .as_ref()
        .is_none_or(|repo_dir| fs_word_uses_cwd(&repo_dir.word));
    let worktree_uses_cwd = globals
        .work_tree
        .as_ref()
        .map_or(base_uses_cwd, |worktree| {
            base_uses_cwd && fs_word_uses_cwd(&worktree.word)
        });
    let git_dir_uses_cwd = globals
        .git_dir
        .as_ref()
        .is_some_and(|git_dir| base_uses_cwd && fs_word_uses_cwd(&git_dir.word));
    worktree_uses_cwd || git_dir_uses_cwd
}

/// cwd for resolving pathspecs: -C changes it.
fn effective_cwd<'a>(globals: &'a Globals, ctx: &'a InvocationCtx) -> Option<String> {
    match (&globals.work_tree, &globals.repo_dir) {
        (Some(work_tree), _) => {
            match resolve_fs_word_with_cwd(&work_tree.word, Some(worktree_base(globals, ctx))) {
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } => Some(path),
                _ => None,
            }
        }
        (None, Some(dir)) => {
            match environment_path(ctx, "GIT_WORK_TREE", Some(worktree_base(globals, ctx))) {
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                }) => Some(path),
                Some(_) => None,
                None => match ctx.resolve_fs_word(&dir.word) {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => Some(path),
                    _ => None,
                },
            }
        }
        (None, None) => {
            match environment_path(ctx, "GIT_WORK_TREE", Some(worktree_base(globals, ctx))) {
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                }) => Some(path),
                Some(_) => None,
                None => ctx.cwd.map(str::to_string),
            }
        }
    }
}

/// The one external `git-<name>` program this model dispatches.
const GIT_FILTER_REPO: &str = "filter-repo";

/// `git filter-repo` execs the `git-filter-repo` program found on PATH, so
/// running that program directly is the same rewrite of the repository at the
/// working directory.
struct GitFilterRepo;

impl CommandModel for GitFilterRepo {
    fn domains(&self) -> &'static [&'static str] {
        Git.domains()
    }

    fn id(&self) -> &'static str {
        "git/git-filter-repo@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["git-filter-repo"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let globals = Globals {
            repo_dir: None,
            work_tree: None,
            git_dir: None,
            configs: Vec::new(),
            command_parameters: None,
            aliases: Vec::new(),
            opaque_config: false,
            pathspec_options: Vec::new(),
        };
        let sub_ctx = SubCtx {
            globals: &globals,
            ctx,
            model_node,
            repo: repo_expr(&globals, ctx),
            cwd: effective_cwd(&globals, ctx),
            rest: &ctx.argv[1..],
            rest_offset: 1,
            sub_index: 0,
        };
        dispatch(builder, "filter-repo", &sub_ctx);
    }
}

impl CommandModel for Git {
    fn domains(&self) -> &'static [&'static str] {
        &["environment", "filesystem", "git", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "git/git@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["git"]
    }

    /// `git show` and `git cat-file` print what they read from the
    /// repository, so a redirection or pipe receives the historical content,
    /// the way `cat` hands its file on. An alias never shadows these names.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        let scanned = crate::models::args::scan_literal_options(
            argv,
            &FlagSpec {
                value_flags: &["-C", "--work-tree", "--git-dir", "-c", "--config-env"],
                known_flags: &[],
                allow_abbreviation: false,
            },
            false,
        );
        let sub = scanned.operands.iter().find(|(_, word)| {
            word.as_literal()
                .is_some_and(|value| !value.starts_with('-'))
        });
        if let Some((index, word)) = sub
            && word.as_literal() == Some("diff")
        {
            let rest = &argv[*index as usize + 1..];
            if !(diff_no_index(rest) || may_be_implicit_no_index(rest)) || summarized(rest) {
                return Vec::new();
            }
            return vec![crate::models::ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: crate::models::ModelBindingEnd::Effect {
                    operation: "filesystem.read".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
                to: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdout),
            }];
        }
        let prints_objects = sub
            .and_then(|(_, word)| word.as_literal())
            .is_some_and(|sub| matches!(sub, "show" | "cat-file"));
        if !prints_objects {
            return Vec::new();
        }
        vec![crate::models::ModelCausalBinding {
            assurance: effinterp_proto::CausalAssurance::Conservative,
            from: crate::models::ModelBindingEnd::Effect {
                operation: "git.read".into(),
                selection: effinterp_model_schema::EffectSelection::All,
            },
            to: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdout),
        }]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut globals = Globals {
            repo_dir: None,
            work_tree: None,
            git_dir: None,
            configs: Vec::new(),
            command_parameters: None,
            aliases: Vec::new(),
            opaque_config: false,
            pathspec_options: Vec::new(),
        };
        // The -c pairs, in order, for the configuration git hands the
        // commands it runs.
        let mut command_pairs: Vec<(String, Option<String>)> = Vec::new();
        let scanned = crate::models::args::scan_literal_options(
            ctx.argv,
            &FlagSpec {
                value_flags: &["-C", "--work-tree", "--git-dir", "-c", "--config-env"],
                known_flags: &[],
                allow_abbreviation: false,
            },
            false,
        );
        let subcommand = scanned.operands.iter().find_map(|(index, word)| {
            word.as_literal()
                .filter(|value| !value.starts_with('-'))
                .map(|value| (*index, value.to_string()))
        });
        let end = subcommand
            .as_ref()
            .map_or(ctx.argv.len(), |(index, _)| *index as usize);
        for flag in scanned
            .flags
            .iter()
            .filter(|flag| (flag.index as usize) < end)
        {
            if ctx.argv[flag.index as usize].as_literal().is_none()
                || !flag.name.starts_with("--")
                    && ctx.argv[flag.index as usize].as_literal() != Some(flag.name)
            {
                globals.opaque_config = true;
                continue;
            }
            let Some(value) = &flag.value else {
                continue;
            };
            let path = GlobalPath {
                index: flag.value_index.unwrap(),
                word: value.clone(),
            };
            let setting = match flag.name {
                "-C" => {
                    globals.repo_dir = Some(path);
                    continue;
                }
                "--work-tree" => {
                    globals.work_tree = Some(path);
                    continue;
                }
                "--git-dir" => {
                    globals.git_dir = Some(path);
                    continue;
                }
                "-c" => config_option_setting(value),
                "--config-env" => config_env_setting(ctx, value),
                _ => unreachable!(),
            };
            let Some((key, value)) = setting else {
                globals.opaque_config = true;
                continue;
            };
            // Config section names are case-insensitive; only a name in the
            // `alias` section can rename a subcommand.
            if let Some(name) = key
                .get(..6)
                .filter(|section| section.eq_ignore_ascii_case("alias."))
                .and_then(|_| key.get(6..))
            {
                let Some(expansion) = &value else {
                    globals.opaque_config = true;
                    continue;
                };
                globals.aliases.push(Alias {
                    name: name.to_string(),
                    expansion: expansion.clone(),
                    value_index: Some(path.index),
                    source_node: None,
                });
            }
            globals.configs.push(ConfigEntry {
                key: key.clone(),
                value: value.clone(),
                replaces: true,
                unobserved: false,
            });
            command_pairs.push((key, value));
        }
        globals.opaque_config |= scanned
            .unknown_flags
            .iter()
            .any(|(index, flag)| (*index as usize) < end && !flag.starts_with("--"))
            || scanned.operands.iter().any(|(index, word)| {
                (*index as usize) < end
                    && (word.as_literal().is_none() || word.as_literal() == Some("-"))
            });
        let discovered = selects_by_discovery(builder, ctx, &globals);
        let mut configs = inherited_configs(builder, ctx, &repo_expr(&globals, ctx), discovered);
        configs.append(&mut globals.configs);
        globals.configs = expand_includes(builder, ctx, model_node, configs, None, 0);
        globals.command_parameters = command_parameters(ctx, &command_pairs);
        globals.pathspec_options = ctx.argv[..end]
            .iter()
            .filter_map(|word| match word.as_literal() {
                Some("--literal-pathspecs") => Some("--literal-pathspecs"),
                Some("--no-literal-pathspecs") => Some("--no-literal-pathspecs"),
                Some("--glob-pathspecs") => Some("--glob-pathspecs"),
                Some("--noglob-pathspecs") => Some("--noglob-pathspecs"),
                _ => None,
            })
            .collect();
        builder.declare_coverage(Domain::new("git"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);

        // The git(1) wrapper grammar ends its own options at the first
        // non-option word; it has no `--` separator. A `--` before the
        // subcommand is an unknown option, so git prints its usage and no
        // subcommand runs.
        if scanned
            .unknown_flags
            .iter()
            .any(|(index, flag)| (*index as usize) < end && flag == "--")
        {
            return;
        }

        if globals.opaque_config {
            // A `-c` this model cannot read can define an alias, which
            // redefines subcommands; nothing after it can be trusted.
            unresolved_alias_boundary(
                builder,
                model_node,
                "a global option that can define an alias was not statically resolvable",
            );
            return;
        }

        let Some((sub_index, mut sub)) = subcommand else {
            return; // bare `git` prints help
        };

        // `git -c alias.<name>=<command>` renames a subcommand for this one
        // invocation. The expansion is a git command line unless it starts
        // with `!`, which hands it to the shell instead.
        let mut alias_argv: Option<Vec<Word>> = None;
        let mut alias_provenance: Option<Vec<Vec<ProvenanceRef>>> = None;
        let mut observed_aliases = None;
        for depth in 0.. {
            if GIT_SUBCOMMANDS.contains(&sub.as_str()) {
                break;
            }
            let inline = globals
                .aliases
                .iter()
                .rev()
                .find(|alias| alias.name.eq_ignore_ascii_case(&sub));
            if inline.is_none() && observed_aliases.is_none() {
                match repository_aliases(builder, ctx, &globals, model_node, sub_index) {
                    Ok(Some(aliases)) => observed_aliases = Some(aliases),
                    Ok(None) => break,
                    Err(detail) => {
                        // An installed git-filter-repo runs whatever alias
                        // the unread config defines (see below).
                        if sub == GIT_FILTER_REPO {
                            dispatch_invocation(
                                builder,
                                ctx,
                                &globals,
                                model_node,
                                sub_index,
                                &sub,
                                alias_argv.as_deref(),
                                alias_provenance.as_deref(),
                            );
                        }
                        unresolved_alias_boundary(builder, model_node, detail);
                        return;
                    }
                }
            }
            let Some(alias) = inline.or_else(|| {
                observed_aliases
                    .as_ref()?
                    .iter()
                    .rev()
                    .find(|alias| alias.name.eq_ignore_ascii_case(&sub))
            }) else {
                break;
            };
            // git runs an installed `git-<name>` before it looks up an alias
            // of that name, and whether `git-filter-repo` is installed is not
            // observed: plan both the tool and the alias.
            if sub == GIT_FILTER_REPO {
                dispatch_invocation(
                    builder,
                    ctx,
                    &globals,
                    model_node,
                    sub_index,
                    &sub,
                    alias_argv.as_deref(),
                    alias_provenance.as_deref(),
                );
                unresolved_alias_boundary(
                    builder,
                    model_node,
                    "git runs an installed git-filter-repo instead of this alias, and whether it is installed is not observed",
                );
            }
            let alias_node = alias
                .source_node
                .unwrap_or_else(|| arg_node(builder, ctx, alias.value_index.unwrap()));
            if depth == GIT_ALIAS_DEPTH {
                unresolved_alias_boundary(builder, model_node, "alias chain is too deep");
                return;
            }
            if let Some(source) = alias.expansion.strip_prefix('!') {
                let base = alias_argv.as_deref().unwrap_or(ctx.argv);
                let command_node = alias_provenance.as_ref().map_or_else(
                    || ctx.arg_antecedents(sub_index),
                    |provenance| provenance[sub_index as usize].clone(),
                );
                let command_node =
                    builder.node(ProvenanceKind::Argument { index: sub_index }, &command_node);
                let invokes_shell = source.contains([
                    '|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', ' ', '\t', '\n',
                    '*', '?', '[', '#', '~', '=', '%',
                ]);
                // Git runs a shell alias through its compiled-in SHELL_PATH
                // (`/bin/sh` by default), not an `sh` found on PATH; an alias
                // without shell syntax is exec'd directly and searched on PATH.
                let mut argv = if invokes_shell {
                    vec![
                        Word::literal("/bin/sh"),
                        Word::literal("-c"),
                        // Git appends "$@" only when extra arguments are supplied.
                        Word::literal(if base.len() > sub_index as usize + 1 {
                            format!("{source} \"$@\"")
                        } else {
                            source.to_string()
                        }),
                        Word::literal(source),
                    ]
                } else {
                    vec![Word::literal(source)]
                };
                let mut provenance = vec![vec![model_node, alias_node, command_node]; argv.len()];
                argv.extend_from_slice(&base[sub_index as usize + 1..]);
                for index in sub_index as usize + 1..base.len() {
                    provenance.push(
                        alias_provenance
                            .as_ref()
                            .map(|provenance| provenance[index].clone())
                            .unwrap_or_else(|| vec![arg_node(builder, ctx, index as u32)]),
                    );
                }
                // A shell alias starts at the repository root, which is not
                // established by the invocation cwd (it may be a subdirectory).
                ctx.nest.nest(
                    builder,
                    crate::nest::Transition::exec(
                        argv.iter().map(crate::nest::word_resource).collect(),
                        argv,
                    )
                    .cwd(
                        ResourceExpr::Parameter {
                            name: "git_toplevel".into(),
                        },
                        None,
                    )
                    .runtime_cwd(None)
                    .environment(
                        [("GIT_PREFIX".to_string(), None)].into(),
                        Default::default(),
                        Default::default(),
                    )
                    .stdin(ctx.stdin)
                    .argv_provenance(Some(&provenance)),
                    &[model_node, alias_node, command_node],
                    ctx.depth,
                );
                return;
            }
            let Some(words) = split_alias(&alias.expansion) else {
                unresolved_alias_boundary(
                    builder,
                    model_node,
                    "alias has an unclosed quote or ends with a backslash",
                );
                return;
            };
            let base = alias_argv.take().unwrap_or_else(|| ctx.argv.to_vec());
            let head = sub_index as usize;
            let mut expanded = base[..head].to_vec();
            expanded.extend(words.iter().map(Word::literal));
            expanded.extend_from_slice(&base[head + 1..]);
            alias_provenance = alias_provenance
                .take()
                .or_else(|| {
                    Some(
                        (0..base.len())
                            .map(|index| vec![arg_node(builder, ctx, index as u32)])
                            .collect(),
                    )
                })
                .filter(|provenance| provenance.len() == base.len())
                .map(|provenance| {
                    let mut derived = provenance[head].clone();
                    derived.push(alias_node);
                    let mut next = provenance[..head].to_vec();
                    next.extend(words.iter().map(|_| derived.clone()));
                    next.extend_from_slice(&provenance[head + 1..]);
                    next
                });
            sub = words[0].clone();
            alias_argv = Some(expanded);
        }

        dispatch_invocation(
            builder,
            ctx,
            &globals,
            model_node,
            sub_index,
            &sub,
            alias_argv.as_deref(),
            alias_provenance.as_deref(),
        );
    }
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
fn config_option_setting(word: &Word) -> Option<(String, Option<String>)> {
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
fn config_env_setting(ctx: &InvocationCtx<'_>, word: &Word) -> Option<(String, Option<String>)> {
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

fn command_parameters(
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

/// Run the subcommand `sub` at `sub_index`, over the alias-expanded argv
/// when an alias renamed it.
#[allow(clippy::too_many_arguments)]
fn dispatch_invocation(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    globals: &Globals,
    model_node: ProvenanceRef,
    sub_index: u32,
    sub: &str,
    alias_argv: Option<&[Word]>,
    alias_provenance: Option<&[Vec<ProvenanceRef>]>,
) {
    let expanded_ctx;
    let ctx = match alias_argv {
        Some(argv) => {
            expanded_ctx = InvocationCtx {
                argv,
                stdin: ctx.stdin,
                argv_provenance: alias_provenance,
                cwd: ctx.cwd,
                cwd_resource: ctx.cwd_resource.clone(),
                runtime_cwd: ctx.runtime_cwd,
                scope: ctx.scope,
                cwd_node: ctx.cwd_node,
                nest: ctx.nest,
                depth: ctx.depth,
                model_stack: ctx.model_stack.clone(),
            };
            &expanded_ctx
        }
        None => ctx,
    };
    let rest_offset = sub_index + 1;
    let rest = &ctx.argv[rest_offset as usize..];

    let cwd = effective_cwd(globals, ctx);
    let sub_ctx = SubCtx {
        globals,
        ctx,
        model_node,
        repo: repo_expr(globals, ctx),
        cwd,
        rest,
        rest_offset,
        sub_index,
    };
    let first_effect = builder.effects_len();
    dispatch(builder, sub, &sub_ctx);
    // git locates the repository from its own environment before it reads
    // argv: `GIT_DIR` and `GIT_WORK_TREE` override discovery from the
    // working directory. A discard acts on whichever tree that resolution
    // picked, so the model declares the reads; without the declaration an
    // inherited value stays invisible and the working directory stands in
    // for a tree it does not name.
    if (first_effect..builder.effects_len())
        .any(|index| matches!(builder.effect_operation(index), Some("git.clean_request")))
    {
        for name in ["GIT_WORK_TREE", "GIT_DIR"] {
            crate::models::common::environment_input(builder, ctx, model_node, name);
        }
    }
}

struct SubCtx<'a> {
    globals: &'a Globals,
    ctx: &'a InvocationCtx<'a>,
    model_node: ProvenanceRef,
    repo: ResourceExpr,
    cwd: Option<String>,
    rest: &'a [Word],
    rest_offset: u32,
    sub_index: u32,
}

impl SubCtx<'_> {
    fn scanned<'a>(&'a self, names: &'a [&'a str]) -> Scanned<'a> {
        crate::models::args::scan_flag_occurrences(
            &self.ctx.argv[self.rest_offset as usize - 1..],
            &FlagSpec {
                value_flags: &[],
                known_flags: names,
                allow_abbreviation: true,
            },
        )
    }

    /// The value of the last `--name=VALUE`, `prefix` being `--name=`: git
    /// keeps the last value a repeated option gives.
    fn flag_with_prefix(&self, prefix: &str) -> Option<String> {
        let name = prefix.strip_suffix('=').unwrap();
        self.rest.iter().rev().find_map(|w| {
            w.as_literal()
                .and_then(|t| t.split_once('='))
                .filter(|(flag, _)| matches_long_option(flag, &[name]))
                .map(|(_, value)| value.to_string())
        })
    }

    /// Non-flag words after the subcommand; `after_double_dash` restricts to
    /// pathspecs following `--`.
    fn operands(&self, after_double_dash: bool) -> Vec<(u32, &Word)> {
        let scanned = scan_literal(
            &self.ctx.argv[self.rest_offset as usize - 1..],
            &FlagSpec {
                value_flags: &[],
                known_flags: &[],
                allow_abbreviation: false,
            },
        );
        scanned
            .operands
            .into_iter()
            .filter(|(index, word)| {
                word.as_literal() != Some("--")
                    && !(word.as_literal() == Some("-")
                        && scanned.dashdash.is_none_or(|dd| *index < dd))
                    && (!after_double_dash || scanned.dashdash.is_some_and(|dd| *index > dd))
            })
            .map(|(index, word)| (self.rest_offset - 1 + index, word))
            .collect()
    }

    fn repo_global_nodes(&self, builder: &mut PlanBuilder) -> Vec<ProvenanceRef> {
        if !self.ctx.tracks_host_context_environment() {
            return Vec::new();
        }
        let base_contributes = self
            .globals
            .work_tree
            .as_ref()
            .is_none_or(|worktree| fs_word_uses_cwd(&worktree.word))
            || self
                .globals
                .git_dir
                .as_ref()
                .is_some_and(|git_dir| fs_word_uses_cwd(&git_dir.word));
        let mut nodes = Vec::new();
        if base_contributes && let Some(repo_dir) = &self.globals.repo_dir {
            nodes.push(fs_arg_node(
                builder,
                self.ctx,
                repo_dir.index,
                &repo_dir.word,
            ));
        }
        nodes.extend(
            self.globals
                .work_tree
                .iter()
                .chain(&self.globals.git_dir)
                .map(|path| fs_arg_node(builder, self.ctx, path.index, &path.word)),
        );
        nodes
    }

    fn repo_effect(&self, builder: &mut PlanBuilder, operation: &str, attributes: Attrs) {
        self.repo_effect_slot(builder, operation, attributes);
    }

    fn request_effect(&self, builder: &mut PlanBuilder, operation: &str, attributes: Attrs) {
        let mut attributes = attributes;
        attributes
            .entry("active".into())
            .or_insert(AttrValue::Bool(true));
        attributes
            .entry("abort".into())
            .or_insert(AttrValue::Bool(false));
        attributes
            .entry("dry_run".into())
            .or_insert(AttrValue::Bool(false));
        let mut antecedents = self.ctx.arg_antecedents(self.sub_index);
        if repo_uses_cwd(self.globals) {
            antecedents.extend(self.ctx.cwd_node);
        }
        let arg = builder.node(
            ProvenanceKind::Argument {
                index: self.sub_index,
            },
            &antecedents,
        );
        let mut provenance = vec![arg];
        provenance.extend(self.repo_global_nodes(builder));
        provenance.push(self.model_node);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: self.repo.clone(),
            attributes,
            modality: Modality::MustOnSuccess,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }

    /// A repository-scoped effect, reporting its slot so a transfer emitter
    /// can pair the endpoint it just produced.
    fn repo_effect_slot(
        &self,
        builder: &mut PlanBuilder,
        operation: &str,
        attributes: Attrs,
    ) -> Option<u32> {
        let mut antecedents = self.ctx.arg_antecedents(self.sub_index);
        if repo_uses_cwd(self.globals) {
            antecedents.extend(self.ctx.cwd_node);
        }
        let arg = builder.node(
            ProvenanceKind::Argument {
                index: self.sub_index,
            },
            &antecedents,
        );
        let mut provenance = vec![arg];
        provenance.extend(self.repo_global_nodes(builder));
        provenance.push(self.model_node);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: self.repo.clone(),
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        })
    }

    /// A filesystem effect on a repository path operand. The returned slot
    /// lets a transfer emitter pair the endpoint it just produced.
    fn filesystem_path_effect(
        &self,
        builder: &mut PlanBuilder,
        index: u32,
        path: &Word,
        operation: &str,
        mut attributes: Attrs,
    ) -> Option<u32> {
        if operation == "filesystem.write" {
            attributes.extend(program_output_attrs());
        }
        let resource = if is_worktree_root_pathspec(self, path) {
            worktree_resource(&self.repo)?.clone()
        } else {
            resolve_fs_word(path, self.cwd.as_deref())
        };
        fs_arg_effect(
            builder,
            self.ctx,
            self.model_node,
            index,
            path,
            operation,
            resource,
            attributes,
        )
    }

    fn object_read(
        &self,
        builder: &mut PlanBuilder,
        index: u32,
        object: &str,
        mut attributes: Attrs,
        disclosure: &str,
    ) {
        let mut provenance = vec![self.model_node, arg_node(builder, self.ctx, index)];
        provenance.extend(self.repo_global_nodes(builder));
        provenance.extend(self.ctx.cwd_node);
        // Colons inside reflog dates or commit-message selectors are not the
        // separator between a revision and its tree path.
        let mut braces: usize = 0;
        let selector = object.char_indices().find_map(|(index, c)| match c {
            '{' => {
                braces += 1;
                None
            }
            '}' => {
                braces = braces.saturating_sub(1);
                None
            }
            ':' if braces == 0 => Some((&object[..index], &object[index + 1..])),
            _ => None,
        });
        if let Some((revision, path)) = selector.filter(|(revision, path)| {
            !revision.is_empty() && !path.is_empty() && !path.starts_with('/')
        }) {
            // This is a path within the selected Git tree, not a host file.
            attributes.insert("revision".into(), AttrValue::String(revision.into()));
            attributes.insert("path".into(), AttrValue::String(path.into()));
            attributes.insert("historical".into(), AttrValue::Bool(true));
            attributes.insert("disclosure".into(), AttrValue::String(disclosure.into()));
        }
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("git.read"),
            resource: self.repo.clone(),
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance,
        });
    }

    /// A repository read that prints one path's file content. `path` names
    /// the operand as written, the way an object selector's tree path does;
    /// `historical` separates recorded content from the working tree.
    fn path_read(&self, builder: &mut PlanBuilder, index: u32, path: &Word, historical: bool) {
        let Some(text) = path.as_literal() else {
            self.repo_effect(builder, "git.read", Attrs::new());
            return;
        };
        let mut provenance = vec![self.model_node, arg_node(builder, self.ctx, index)];
        provenance.extend(self.repo_global_nodes(builder));
        provenance.extend(self.ctx.cwd_node);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("git.read"),
            resource: self.repo.clone(),
            attributes: Attrs::from([
                ("path".into(), AttrValue::String(text.into())),
                ("historical".into(), AttrValue::Bool(historical)),
                ("disclosure".into(), AttrValue::String("contents".into())),
            ]),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance,
        });
    }

    fn git_path_effect(
        &self,
        builder: &mut PlanBuilder,
        index: u32,
        path: &Word,
        operation: &str,
        attributes: Attrs,
    ) {
        let ResourceExpr::Concrete {
            identity:
                ResourceIdentity::GitRepository {
                    worktree, git_dir, ..
                },
        } = self.repo.clone()
        else {
            return;
        };
        let pathspec = if is_worktree_root_pathspec(self, path) {
            resolve_fs_word(&Word::literal("."), Some(""))
        } else {
            resolve_fs_word(path, Some(""))
        };
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec: Some(Box::new(pathspec)),
            },
        };
        let mut provenance = vec![arg_node(builder, self.ctx, index)];
        if self.ctx.tracks_host_context_environment() && repo_uses_cwd(self.globals) {
            provenance.extend(self.ctx.cwd_node);
        }
        provenance.extend(self.repo_global_nodes(builder));
        provenance.push(self.model_node);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }

    fn hooks_boundary(&self, builder: &mut PlanBuilder) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_HOOKS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("process")],
            provenance: vec![self.model_node],
            limit: None,
            detail: Some("git hooks may run arbitrary programs".to_string()),
        });
    }

    fn pre_commit_hook(&self, builder: &mut PlanBuilder) {
        if self
            .scanned(&["--no-verify", "-n"])
            .has(&["--no-verify", "-n"])
        {
            return;
        }
        let Some(worktree) = self.cwd.as_deref().or(self.ctx.runtime_cwd) else {
            self.hooks_boundary(builder);
            return;
        };
        let hook_dir = if let Some(Some(configured)) = config_value(self.globals, "core.hooksPath")
        {
            if configured.starts_with('/') {
                configured.to_string()
            } else {
                crate::paths::join_cwd(worktree, configured)
            }
        } else {
            // Repository, global, and included configuration can override the
            // default hook directory. Only an explicit override proves it here.
            crate::models::common::runtime_unobserved_input(
                builder,
                self.ctx,
                "core.hooksPath",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::VcsHook,
                ExecutionSelector::Convention {
                    name: "git-pre-commit-hook@2".to_string(),
                },
                effinterp_proto::ExecutionInputReason::Ambiguous,
            );
            return;
        };
        runtime_searched_source(
            builder,
            self.ctx,
            self.model_node,
            "pre-commit",
            vec![format!("{hook_dir}/pre-commit")],
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::VcsHook,
            ExecutionSelector::Convention {
                name: "git-pre-commit-hook@2".to_string(),
            },
            RuntimeSourceLanguage::Executable,
            false,
        );
    }

    /// The remote endpoint interaction for a transfer with a Git remote. The
    /// returned slot lets the caller pair it with the repository side.
    fn remote_network(&self, builder: &mut PlanBuilder, operation: &str) -> Option<u32> {
        // The remote's endpoint lives in config unless given as a URL.
        let push_scan = PushArgs::scan(self);
        let operands = if operation == "network.upload" {
            push_scan
                .remote
                .filter(|_| push_scan.complete)
                .into_iter()
                .collect()
        } else {
            self.operands(false)
        };
        let endpoint = operands.iter().find_map(|(index, word)| {
            word.as_literal()
                .and_then(parse_endpoint)
                .map(|identity| (*index, identity))
        });
        let resource = match &endpoint {
            Some((_, identity)) => ResourceExpr::Concrete {
                identity: identity.clone(),
            },
            None => ResourceExpr::Unresolved {
                family: ResourceFamily::new("network"),
            },
        };
        let arg = arg_node(builder, self.ctx, self.sub_index);
        let mut provenance = vec![arg];
        if self.ctx.tracks_host_context_environment()
            && let Some((index, _)) = endpoint
        {
            provenance.push(arg_node(builder, self.ctx, index));
        }
        provenance.push(self.model_node);
        let slot = builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        slot
    }
}

fn dispatch(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    match sub {
        "merge-base" | "ls-tree" | "diff-tree" | "show-ref" => {
            let spec = match sub {
                "merge-base" => crate::models::args::FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &[],
                    known_flags: &[
                        "-a",
                        "--all",
                        "--octopus",
                        "--independent",
                        "--is-ancestor",
                        "--fork-point",
                    ],
                },
                "ls-tree" => crate::models::args::FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &["--format", "--abbrev"],
                    known_flags: &[
                        "-d",
                        "-r",
                        "-t",
                        "-l",
                        "-z",
                        "--name-only",
                        "--name-status",
                        "--object-only",
                        "--full-name",
                        "--full-tree",
                        "--long",
                    ],
                },
                "diff-tree" => crate::models::args::FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &["--diff-filter", "--format", "--pretty", "--abbrev"],
                    known_flags: &[
                        "-r",
                        "-t",
                        "-z",
                        "-p",
                        "-s",
                        "-m",
                        "-c",
                        "--cc",
                        "--root",
                        "--no-commit-id",
                        "--name-only",
                        "--name-status",
                        "--raw",
                        "--stat",
                        "--numstat",
                        "--shortstat",
                        "--summary",
                        "--quiet",
                        "--exit-code",
                        "--no-renames",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--no-patch",
                        "--patch",
                        "--binary",
                        "--full-index",
                    ],
                },
                _ => crate::models::args::FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &[],
                    known_flags: &[
                        "--head",
                        "--heads",
                        "--branches",
                        "--tags",
                        "--verify",
                        "--exists",
                        "--quiet",
                        "-q",
                        "--hash",
                        "-s",
                        "--dereference",
                        "-d",
                        "--exclude-existing",
                    ],
                },
            };
            let mut parsed = crate::models::args::scan(&s.ctx.argv[s.sub_index as usize..], &spec);
            for (index, _) in &mut parsed.unknown_flags {
                *index += s.sub_index;
            }
            crate::models::common::unrecognized_arguments_boundary(
                builder,
                s.model_node,
                &ALL_DOMAINS,
                &parsed.unknown_flags,
            );
            s.repo_effect(builder, "git.read", Attrs::new());
        }
        "archive" => {
            let mut parsed = crate::models::args::scan_with_value_indices(
                &s.ctx.argv[s.sub_index as usize..],
                &crate::models::args::FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &[
                        "-o",
                        "--output",
                        "--format",
                        "--prefix",
                        "--remote",
                        "--exec",
                        "--add-file",
                        "--add-virtual-file",
                    ],
                    known_flags: &[
                        "-v",
                        "--verbose",
                        "-l",
                        "--list",
                        "--worktree-attributes",
                        "-0",
                        "-1",
                        "-2",
                        "-3",
                        "-4",
                        "-5",
                        "-6",
                        "-7",
                        "-8",
                        "-9",
                    ],
                },
                true,
            );
            for flag in &parsed.flags {
                if flag.value.is_none()
                    && matches!(flag.name, "-o" | "--output" | "--remote" | "--exec")
                {
                    parsed
                        .unknown_flags
                        .push((flag.index, flag.name.to_string()));
                }
            }
            for (index, _) in &mut parsed.unknown_flags {
                *index += s.sub_index;
            }
            crate::models::common::unrecognized_arguments_boundary(
                builder,
                s.model_node,
                &ALL_DOMAINS,
                &parsed.unknown_flags,
            );
            if !parsed.unknown_flags.is_empty() {
                return;
            }
            if parsed.has(&["--remote", "--exec", "--add-file", "--add-virtual-file"]) {
                crate::models::common::unrecognized_arguments_boundary(
                    builder,
                    s.model_node,
                    &ALL_DOMAINS,
                    &[(
                        s.sub_index,
                        "archive external input or remote execution".to_string(),
                    )],
                );
                return;
            }
            s.repo_effect(builder, "git.read", Attrs::new());
            if let Some((index, file)) = parsed.values_of(&["-o", "--output"]).last() {
                s.filesystem_path_effect(
                    builder,
                    s.sub_index + *index,
                    file,
                    "filesystem.write",
                    Attrs::new(),
                );
            }
        }
        "cat-file" => {
            if matches!(s.rest, [mode] if mode.as_literal().is_some_and(|arg| {
                matches!(
                    arg.split('=').next(),
                    Some("--batch" | "--batch-check" | "--batch-command")
                )
            })) {
                builder.boundary(Boundary {
                    reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(s.repo.clone()),
                    callee: None,
                    domains: vec![Domain::new("git"), Domain::new("filesystem")],
                    provenance: vec![s.model_node],
                    limit: None,
                    detail: Some("git cat-file batch object selectors come from stdin".into()),
                });
                return;
            }
            let [mode, object] = s.rest else {
                crate::models::common::unrecognized_arguments_boundary(
                    builder,
                    s.model_node,
                    &ALL_DOMAINS,
                    &[(
                        s.sub_index,
                        "cat-file requires a mode and one object".into(),
                    )],
                );
                return;
            };
            let Some(mode @ ("blob" | "tree" | "commit" | "tag" | "-p" | "-t" | "-s" | "-e")) =
                mode.as_literal()
            else {
                crate::models::common::unrecognized_arguments_boundary(
                    builder,
                    s.model_node,
                    &ALL_DOMAINS,
                    &[(
                        s.rest_offset,
                        "cat-file object selection or conversion is unmodeled".into(),
                    )],
                );
                return;
            };
            let Some(object) = object.as_literal() else {
                let node = arg_node(builder, s.ctx, s.rest_offset + 1);
                builder.boundary(Boundary {
                    reason: BoundaryReason::DYNAMIC_SOURCE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(s.repo.clone()),
                    callee: None,
                    domains: vec![Domain::new("git")],
                    provenance: vec![s.model_node, node],
                    limit: None,
                    detail: Some("git cat-file object selector is dynamic".into()),
                });
                return;
            };
            if object.is_empty() || object.starts_with('-') {
                git_argument_boundary(builder, s, "cat-file requires an object selector");
                return;
            }
            let mut attributes = Attrs::from([
                ("object".into(), AttrValue::String(object.into())),
                ("mode".into(), AttrValue::String(mode.into())),
            ]);
            if !matches!(mode, "-t" | "-s" | "-e") {
                attributes.insert("output".into(), AttrValue::String("stdout".into()));
            }
            s.object_read(
                builder,
                s.rest_offset + 1,
                object,
                attributes,
                if matches!(mode, "-t" | "-s" | "-e" | "tree") {
                    "metadata"
                } else {
                    "contents"
                },
            );
        }
        "show" if matches!(s.rest, [object] if object.as_literal().is_some_and(|v| !v.starts_with('-') && v.contains(':'))) =>
        {
            let object = s.rest[0].as_literal().unwrap();
            s.object_read(
                builder,
                s.rest_offset,
                object,
                Attrs::from([
                    ("object".into(), AttrValue::String(object.into())),
                    ("output".into(), AttrValue::String("stdout".into())),
                ]),
                "contents",
            );
        }
        // `git diff --no-index <path> <path>` compares two host files, not
        // pathspecs, and its patch prints both files' lines.
        "diff" if diff_no_index(s.rest) || implicit_no_index(s) => {
            let attributes = if summarized(s.rest) {
                Attrs::new()
            } else {
                super::common::program_input_attrs()
            };
            for (index, path) in s.operands(false) {
                s.filesystem_path_effect(
                    builder,
                    index,
                    path,
                    "filesystem.read",
                    attributes.clone(),
                );
            }
        }
        "status" | "log" | "diff" | "show" | "blame" | "rev-parse" | "describe" | "shortlog"
        | "ls-files" | "grep" | "rev-list" | "name-rev" | "whatchanged" | "branch" | "tag"
        | "remote" | "stash" | "reflog" | "config" | "worktree"
            if is_read_form(sub, s) =>
        {
            let disclosed = disclosed_paths(sub, s);
            if disclosed.is_empty() {
                s.repo_effect(builder, "git.read", Attrs::new());
            } else {
                for (index, path, historical) in disclosed {
                    s.path_read(builder, index, path, historical);
                }
            }
        }
        "add" => {
            s.repo_effect(builder, "git.index_write", Attrs::new());
            // Staging hashes each file's contents into the object store; a
            // dry run only lists what it would add.
            let staged = if s.scanned(&["-n", "--dry-run"]).has(&["-n", "--dry-run"]) {
                Attrs::new()
            } else {
                super::common::program_input_attrs()
            };
            for (index, path) in s.operands(false) {
                s.filesystem_path_effect(builder, index, path, "filesystem.read", staged.clone());
            }
        }
        "rm" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &["--pathspec-from-file"],
                    known_flags: &[
                        "-f",
                        "--force",
                        "--no-force",
                        "-n",
                        "--dry-run",
                        "--no-dry-run",
                        "-r",
                        "--cached",
                        "--ignore-unmatch",
                        "--sparse",
                        "-q",
                        "--quiet",
                        "--pathspec-file-nul",
                    ],
                    allow_abbreviation: true,
                },
            );
            // git-rm(1) `-n` lists what it would remove and returns before
            // it removes a file or writes the index.
            if git_controls_known(&parsed)
                && parsed_effective_flag(&parsed, &["-n", "--dry-run"], &["--no-dry-run"])
            {
                s.repo_effect(builder, "git.read", Attrs::new());
                return;
            }
            s.repo_effect(builder, "git.index_write", Attrs::new());
            if !s.scanned(&["--cached"]).has(&["--cached"]) {
                // Recursion alone makes the removal recursive: even without
                // -f, git rm unlinks unmerged entries and a clean submodule
                // with its ignored and untracked content (builtin/rm.c
                // `check_local_mod`). git rm has no long spelling of -r, so
                // only an unknown short cluster may add it.
                let unknown_cluster = parsed.unknown_flags.iter().any(|(index, flag)| {
                    !flag.starts_with("--")
                        && !parsed.operands.iter().any(|(operand, _)| operand == index)
                });
                if unknown_cluster {
                    git_argument_boundary(builder, s, "git rm options are not fully known");
                }
                let recursive = parsed.has(&["-r"]) || unknown_cluster;
                for (index, path) in s.operands(false) {
                    s.filesystem_path_effect(
                        builder,
                        index,
                        path,
                        "filesystem.delete",
                        attrs(&[("recursive", recursive)]),
                    );
                }
            }
        }
        // `git mv` moves each source entry to the destination: the source
        // entry is deleted and the destination entry written, with no source
        // content read to invent. `filesystem.move` is the semantic layer.
        "mv" => {
            s.repo_effect(builder, "git.index_write", Attrs::new());
            let operands = s.operands(false);
            if let Some(((dest_index, dest), sources)) = operands.split_last() {
                let mut source_slots = Vec::with_capacity(sources.len());
                for (index, source) in sources {
                    s.filesystem_path_effect(
                        builder,
                        *index,
                        source,
                        "filesystem.move",
                        Attrs::new(),
                    );
                    source_slots.push(s.filesystem_path_effect(
                        builder,
                        *index,
                        source,
                        "filesystem.delete",
                        Attrs::new(),
                    ));
                }
                if !sources.is_empty() {
                    let destination = s.filesystem_path_effect(
                        builder,
                        *dest_index,
                        dest,
                        "filesystem.write",
                        Attrs::new(),
                    );
                    builder.transfer_bindings(&crate::resource_transfer::pair_slots(
                        &source_slots,
                        &[destination],
                    ));
                }
            }
        }
        "commit" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &["-m", "--message"],
                    known_flags: &["--amend", "-n", "--no-verify"],
                    allow_abbreviation: true,
                },
            );
            if s.scanned(&["--amend"]).has(&["--amend"]) {
                s.repo_effect(
                    builder,
                    "git.history_rewrite",
                    attrs(&[
                        ("amend", true),
                        (
                            "no_verify",
                            s.scanned(&["-n", "--no-verify"])
                                .has(&["-n", "--no-verify"]),
                        ),
                    ]),
                );
                if git_controls_known(&parsed) {
                    let mut request = request_attrs(&[
                        ("amend", true),
                        (
                            "no_verify",
                            s.scanned(&["-n", "--no-verify"])
                                .has(&["-n", "--no-verify"]),
                        ),
                        ("target_complete", true),
                    ]);
                    request.insert(
                        "history_operation".into(),
                        AttrValue::String("amend".into()),
                    );
                    s.request_effect(builder, "git.history_rewrite_request", request);
                }
            } else {
                s.repo_effect(
                    builder,
                    "git.ref_update",
                    attrs(&[(
                        "no_verify",
                        s.scanned(&["-n", "--no-verify"])
                            .has(&["-n", "--no-verify"]),
                    )]),
                );
            }
            s.pre_commit_hook(builder);
            // prepare-commit-msg, commit-msg, and post-commit remain outside
            // the modeled pre-commit selector, including under --no-verify.
            s.hooks_boundary(builder);
        }
        "checkout" | "restore" | "switch" => checkout(builder, sub, s),
        "reset" => reset(builder, s),
        "clean" => clean(builder, s),
        "branch" | "tag" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &[],
                    known_flags: if sub == "branch" {
                        // Listing and remote-tracking selection leave a
                        // deletion a deletion, and may share its cluster
                        // (`-vrd`).
                        &[
                            "-d",
                            "-D",
                            "--delete",
                            "--no-delete",
                            "-f",
                            "--force",
                            "--no-force",
                            "-r",
                            "--remotes",
                            "-v",
                            "--verbose",
                            "-q",
                            "--quiet",
                        ]
                    } else {
                        &[
                            "-d",
                            "-D",
                            "--delete",
                            "--no-delete",
                            "-f",
                            "--force",
                            "--no-force",
                        ]
                    },
                    allow_abbreviation: true,
                },
            );
            let delete =
                parsed_effective_flag(&parsed, &["-d", "-D", "--delete"], &["--no-delete"]);
            let a = attrs(&[
                ("delete", delete),
                (
                    "force",
                    parsed_effective_flag(&parsed, &["-D", "-f", "--force"], &["--no-force"]),
                ),
            ]);
            if delete {
                for (_, word) in s.operands(false) {
                    let mut a = a.clone();
                    if let Some(name) = word.as_literal() {
                        a.insert("ref".into(), AttrValue::String(name.into()));
                        if git_controls_known(&parsed) {
                            let mut request = request_attrs(&[(
                                "force",
                                matches!(a.get("force"), Some(AttrValue::Bool(true))),
                            )]);
                            request.insert("ref".into(), AttrValue::String(name.into()));
                            request.insert("delete".into(), AttrValue::Bool(true));
                            request.insert("scope".into(), AttrValue::String("selected".into()));
                            request.insert("broad".into(), AttrValue::Bool(false));
                            s.request_effect(builder, "git.ref_delete_request", request);
                        }
                    }
                    s.repo_effect(builder, "git.ref_update", a);
                }
            } else {
                s.repo_effect(builder, "git.ref_update", a);
            }
        }
        "push" => push(builder, s),
        // Fetching moves objects from the remote into the repository: the
        // remote read pairs with the most atomic local destination the modeled
        // operation has — a pull's worktree write, otherwise the repository
        // sync itself.
        "fetch" | "pull" => {
            let synced = s.repo_effect_slot(builder, "git.remote_sync", attrs(&[("fetch", true)]));
            let mut destination = synced;
            if sub == "pull" {
                destination = s.repo_effect_slot(builder, "git.worktree_write", Attrs::new());
                let (rebases, certain) = pull_rebases(s);
                if !certain {
                    git_argument_boundary(
                        builder,
                        s,
                        "whether git pull rebases is not statically known",
                    );
                }
                if rebases && certain {
                    s.repo_effect(builder, "git.history_rewrite", attrs(&[("force", false)]));
                    let mut request = request_attrs(&[("force", false), ("target_complete", true)]);
                    request.insert("rewrite".into(), AttrValue::String("rebase".into()));
                    request.insert(
                        "history_operation".into(),
                        AttrValue::String("rebase".into()),
                    );
                    request.insert("scope".into(), AttrValue::String("targeted".into()));
                    request.insert("broad".into(), AttrValue::Bool(false));
                    s.request_effect(builder, "git.history_rewrite_request", request);
                }
                s.hooks_boundary(builder);
            }
            let source = s.remote_network(builder, "network.download");
            if let (Some(source), Some(destination)) = (source, destination) {
                builder.transfer_binding(TransferBinding::new(source, destination));
            }
        }
        // Cloning downloads the remote into a new local directory.
        "clone" => {
            s.repo_effect(builder, "git.remote_sync", attrs(&[("clone", true)]));
            let source = s.remote_network(builder, "network.download");
            let operands = s.operands(false);
            let dest = match operands.as_slice() {
                // `clone <url> <dir>` — unless the last operand is itself a
                // URL (a value-consuming flag like -b shifted the operands).
                [_, .., (index, dest)] if dest.as_literal().and_then(parse_endpoint).is_none() => {
                    Some((*index, (*dest).clone()))
                }
                [.., (index, url)] => url
                    .as_literal()
                    .and_then(|u| {
                        u.trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .map(|b| b.trim_end_matches(".git").to_string())
                    })
                    .map(|b| (*index, Word::literal(b))),
                _ => None,
            };
            if let Some((index, dest)) = dest {
                let destination = s.filesystem_path_effect(
                    builder,
                    index,
                    &dest,
                    "filesystem.write",
                    Attrs::new(),
                );
                if let (Some(source), Some(destination)) = (source, destination) {
                    builder.transfer_binding(TransferBinding::new(source, destination));
                }
            }
        }
        "gc" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &["--prune"],
                    // Reporting does not select what is pruned, so it leaves
                    // the recovery request exact.
                    known_flags: &[
                        "--no-prune",
                        "--aggressive",
                        "--no-aggressive",
                        "--auto",
                        "--force",
                        "--quiet",
                    ],
                    allow_abbreviation: true,
                },
            );
            // git-gc(1) keeps only the last `--prune[=<date>]` or
            // `--no-prune` and refuses an empty final date before collecting
            // anything; an empty date a later option overrides is never read.
            let empty_expiry = parsed
                .flags
                .iter()
                .rev()
                .find(|flag| matches!(flag.name, "--prune" | "--no-prune"))
                .is_some_and(|flag| {
                    flag.value_index == Some(flag.index)
                        && flag.value.as_ref().and_then(Word::as_literal) == Some("")
                });
            // git-gc(1): `--prune=<date>` expires unreachable objects older
            // than the date, so the selector is what the collection destroys.
            // git reads the configured expiry before any option and refuses
            // an empty one, even when `--prune` or `--no-prune` overrides it.
            let configured = config_values(s.globals, "gc.pruneExpire");
            if git_help_requested(&parsed)
                || empty_expiry
                || empty_repository_global(s)
                || configured.certain() == Some(Some(""))
            {
                return;
            }
            // When executions may leave different expiries, one some path
            // leaves immediate is the collection planned, with a boundary.
            let possible_immediate = configured
                .certain()
                .is_none()
                .then(|| {
                    configured
                        .values
                        .iter()
                        .flatten()
                        .copied()
                        .find(|value| immediate_expiry(value))
                })
                .flatten();
            let configured_expiry = match possible_immediate {
                Some(value) => Some(Some(value)),
                None if configured.values.is_empty() => None,
                None => Some(configured.certain().flatten()),
            };
            // `--no-prune` keeps every unreachable object, overriding the
            // configured expiry and any earlier `--prune`.
            let no_prune = parsed
                .flags
                .iter()
                .rev()
                .find(|flag| matches!(flag.name, "--prune" | "--no-prune"))
                .is_some_and(|flag| flag.name == "--no-prune");
            let explicit_prune = s.flag_with_prefix("--prune=");
            if possible_immediate.is_some() && explicit_prune.is_none() && !no_prune {
                git_argument_boundary(
                    builder,
                    s,
                    "git gc expiry configuration differs between the paths that reach it",
                );
            }
            let prune = explicit_prune
                .or_else(|| configured_expiry.flatten().map(str::to_string))
                .filter(|_| !no_prune);
            // A configured expiry the model cannot read decides what the
            // collection destroys just as `--prune=<date>` does.
            let expiry_known =
                no_prune || prune.is_some() || !matches!(configured_expiry, Some(None));
            if !expiry_known {
                git_argument_boundary(
                    builder,
                    s,
                    "git gc expiry configuration is not statically resolvable",
                );
            }
            let prune_now = prune.as_deref().is_some_and(immediate_expiry);
            // `--aggressive` repacks more aggressively, rewriting the object
            // store rather than only collecting it.
            let aggressive =
                parsed_effective_flag(&parsed, &["--aggressive"], &["--no-aggressive"]);
            let valid_operands = s.operands(false).is_empty();
            // Without pruning, gc still expires reflog entries past
            // gc.reflogExpire and repacks, so it still destroys recovery data.
            s.repo_effect(
                builder,
                "git.recovery_destroy",
                attrs(&[("immediate", prune_now)]),
            );
            if git_controls_known(&parsed) && valid_operands && expiry_known {
                let mut request = request_attrs(&[
                    ("immediate", prune_now),
                    ("recovery", true),
                    ("aggressive", aggressive),
                ]);
                request.insert(
                    "scope".into(),
                    AttrValue::String(if prune_now { "whole" } else { "named" }.into()),
                );
                request.insert("broad".into(), AttrValue::Bool(prune_now));
                if let Some(prune) = prune {
                    request.insert("prune".into(), AttrValue::String(prune));
                }
                s.request_effect(builder, "git.recovery_destroy_request", request);
            }
        }
        "reflog" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &["--expire", "--expire-unreachable"],
                    // `--single-worktree` (expire and drop only) skips only
                    // the other worktrees' own HEAD logs: the current
                    // worktree's ref store also yields every shared branch
                    // log, so `--all` stays whole.
                    known_flags: if matches!(
                        s.rest.first().and_then(Word::as_literal),
                        Some("expire" | "drop")
                    ) {
                        &[
                            "delete",
                            "expire",
                            "--all",
                            "--single-worktree",
                            "-n",
                            "--dry-run",
                        ]
                    } else {
                        &["delete", "expire", "--all", "-n", "--dry-run"]
                    },
                    allow_abbreviation: true,
                },
            );
            // git reports an empty ref as pointing nowhere and goes on to the
            // next one, so only a list of nothing but empty refs, without
            // `--all`, leaves every reflog alone.
            let refs = s.operands(false);
            let only_empty_refs = refs.len() > 1
                && refs
                    .iter()
                    .skip(1)
                    .all(|(_, word)| word.as_literal() == Some(""));
            if empty_option_value(&parsed)
                || empty_repository_global(s)
                || only_empty_refs && !s.scanned(&["--all"]).has(&["--all"])
            {
                return;
            }
            // is_read_form filtered `reflog [show|list]`; the actions that
            // change reflogs land here. `drop` (git 2.50) deletes whole
            // reflogs, every entry whatever its age, as an immediate expiry
            // does.
            let drop = s.rest.first().and_then(Word::as_literal) == Some("drop");
            let immediate = drop
                || s.flag_with_prefix("--expire=")
                    .or_else(|| s.flag_with_prefix("--expire-unreachable="))
                    .map(|v| immediate_expiry(&v))
                    .unwrap_or(false);
            let dry_run = parsed.has(&["-n", "--dry-run"]);
            let mut attributes = attrs(&[("immediate", immediate), ("reflog", true)]);
            if let Some(action @ ("expire" | "delete")) = s.rest.first().and_then(Word::as_literal)
            {
                attributes.insert("action".into(), AttrValue::String(action.into()));
            }
            if parsed.unknown_flags.is_empty() && git_controls_known(&parsed) {
                // Scope names the reflogs selected, independently of entry age.
                attributes.insert(
                    "scope".into(),
                    AttrValue::String(
                        if parsed.has(&["--all"]) {
                            "whole"
                        } else {
                            "named"
                        }
                        .into(),
                    ),
                );
                attributes.insert("dry_run".into(), AttrValue::Bool(dry_run));
            }
            let action = attributes.get("action").cloned();
            s.repo_effect(builder, "git.recovery_destroy", attributes);
            if !dry_run && git_controls_known(&parsed) {
                let operands = s.operands(false);
                // expire, delete and drop take any number of refs or
                // entries; `exists` takes one ref and `write` one entry.
                let valid_operands = operands.len() <= 2
                    || matches!(
                        s.rest.first().and_then(Word::as_literal),
                        Some("expire" | "delete" | "drop")
                    );
                let all_refs = s.scanned(&["--all"]).has(&["--all"]);
                let target_complete = operands
                    .iter()
                    .skip(1)
                    .all(|(_, word)| word.as_literal().is_some());
                let mut request = request_attrs(&[("immediate", immediate), ("reflog", true)]);
                if let Some(action) = action.clone() {
                    request.insert("action".into(), action);
                }
                request.insert("target_complete".into(), AttrValue::Bool(target_complete));
                // `--all` expires every reflog before git looks up any named
                // ref, so a named ref beside it narrows nothing.
                request.insert(
                    "scope".into(),
                    AttrValue::String(
                        if immediate && all_refs {
                            "whole"
                        } else if target_complete && operands.len() > 1 {
                            "selected"
                        } else {
                            "named"
                        }
                        .into(),
                    ),
                );
                request.insert("broad".into(), AttrValue::Bool(immediate && all_refs));
                if target_complete
                    && let [_, (_, target)] = operands.as_slice()
                    && let Some(target) = target.as_literal()
                {
                    request.insert("target".into(), AttrValue::String(target.into()));
                }
                // `--expire=never` and `--expire-unreachable=never` (or
                // `false`) together keep every entry, so expiring one named
                // ref's reflog then prunes nothing.
                let keeps_every_entry = action == Some(AttrValue::String("expire".into()))
                    && ["--expire", "--expire-unreachable"].iter().all(|name| {
                        parsed
                            .values_of(&[name])
                            .last()
                            .and_then(|(_, value)| value.as_literal())
                            .is_some_and(|value| matches!(value, "never" | "false"))
                    });
                let selected = request.get("scope") == Some(&AttrValue::String("selected".into()));
                // `drop` refuses refs named beside `--all` ("references
                // specified along with --all").
                let drop_usage = drop && all_refs && operands.len() > 1;
                if valid_operands && !(keeps_every_entry && selected) && !drop_usage {
                    s.request_effect(builder, "git.recovery_destroy_request", request);
                }
            }
        }
        "rebase" | "filter-branch" | "filter-repo" => {
            // Sequencer steps resume the rewrite already in progress, and a
            // filter-repo path filter selects commits, not a second operand.
            // Both leave the rewrite itself exactly as certified.
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: match sub {
                        "filter-repo" => FILTER_REPO_VALUE_FLAGS,
                        "filter-branch" => FILTER_BRANCH_VALUE_FLAGS,
                        _ => &["--onto", "-x", "--exec"],
                    },
                    // The todo-list, base and ref-bookkeeping options choose
                    // which commits are replayed and how, never whether the
                    // current branch is rewritten.
                    known_flags: match sub {
                        "rebase" => &[
                            "-f",
                            "--force",
                            "--no-force",
                            "--no-verify",
                            "-i",
                            "--interactive",
                            "--autosquash",
                            "--no-autosquash",
                            "--root",
                            "--keep-base",
                            "--update-refs",
                            "--no-update-refs",
                            "-r",
                            "--rebase-merges",
                            "--no-rebase-merges",
                            "--autostash",
                            "--no-autostash",
                            "--continue",
                            "--skip",
                            "--abort",
                            "--quit",
                            "--edit-todo",
                            "--show-current-patch",
                        ],
                        "filter-repo" => &[
                            "-f",
                            "--force",
                            "--no-force",
                            "--invert-paths",
                            "--analyze",
                            "--dry-run",
                            "--version",
                            "--use-base-name",
                            "--partial",
                        ],
                        _ => &["-f", "--force", "--no-force", "--prune-empty"],
                    },
                    allow_abbreviation: true,
                },
            );
            let mut parsed = parsed;
            if sub == "rebase" {
                // `-r<mode>` is the short spelling of `--rebase-merges=<mode>`,
                // and git-rebase(1) names the two modes it accepts.
                parsed.unknown_flags.retain(|(index, _)| {
                    !s.ctx.argv[(s.rest_offset - 1 + index) as usize]
                        .as_literal()
                        .and_then(|text| text.strip_prefix("-r"))
                        .is_some_and(|mode| matches!(mode, "rebase-cousins" | "no-rebase-cousins"))
                });
            }
            if git_help_requested(&parsed) {
                return;
            }
            if sub == "rebase" {
                // git-rebase(1) states the in-progress actions as
                // alternatives to starting a rewrite. `--abort` puts the
                // original branch and worktree back; `--quit`, `--edit-todo`,
                // and `--show-current-patch` leave HEAD, the index, and the
                // worktree as they are. Only `--continue` and `--skip` go on
                // replaying commits.
                if parsed.has(&["--abort"]) {
                    s.repo_effect(builder, "git.worktree_write", Attrs::new());
                    s.repo_effect(builder, "git.ref_update", Attrs::new());
                    s.hooks_boundary(builder);
                    return;
                }
                if parsed.has(&["--quit", "--edit-todo", "--show-current-patch"]) {
                    s.repo_effect(builder, "git.read", Attrs::new());
                    return;
                }
            }
            if sub == "filter-repo" {
                // git-filter-repo documents `--version` as printing the
                // version, and `--analyze` and `--dry-run` as reporting on
                // history without changing the repository.
                if parsed.has(&["--version"]) {
                    return;
                }
                if parsed.has(&["--analyze", "--dry-run"]) {
                    s.repo_effect(builder, "git.read", Attrs::new());
                    return;
                }
            }
            if sub == "filter-branch" {
                // git-filter-branch walks its options by exact spelling until
                // the first operand or `--`. Every other dashed word takes
                // the next word as its value, and an unknown option or a
                // missing value exits with usage before anything is touched.
                let mut force = false;
                let mut prune_empty = false;
                let mut commit_filter = false;
                let mut tempdir = None;
                let mut code = Vec::new();
                let mut words = s.rest.iter().zip(s.rest_offset..);
                while let Some((word, index)) = words.next() {
                    let Some(text) = word.as_literal() else {
                        break;
                    };
                    match text {
                        "--" => break,
                        "-f" | "--force" => force = true,
                        "--prune-empty" => prune_empty = true,
                        "--remap-to-ancestor" => {}
                        option if option.starts_with('-') => {
                            let Some((value, value_index)) = words.next() else {
                                return;
                            };
                            if !FILTER_BRANCH_VALUE_FLAGS.contains(&option) {
                                return;
                            }
                            match option {
                                "-d" => tempdir = Some((value, value_index)),
                                "--commit-filter" => commit_filter = true,
                                _ => {}
                            }
                            if FILTER_BRANCH_CODE_FLAGS.contains(&option) {
                                code.push((index, option));
                            }
                        }
                        _ => break,
                    }
                }
                if prune_empty && commit_filter {
                    return;
                }
                for (index, option) in code {
                    filter_code_boundary(builder, s, index, option);
                }
                // The last `-d` names the scratch directory. Without `--force`
                // an existing one stops the rewrite, and the directory it then
                // creates is all it removes on exit; `--force` first removes
                // whatever already exists there with `rm -rf`.
                if force && let Some((value, index)) = tempdir {
                    s.filesystem_path_effect(
                        builder,
                        index,
                        value,
                        "filesystem.delete",
                        attrs(&[("recursive", true)]),
                    );
                }
            }
            if sub == "filter-repo" {
                // argparse rejects a missing value or a detached option
                // where a value is required, before rewriting any history.
                if parsed.flags.iter().any(|flag| {
                    FILTER_REPO_VALUE_FLAGS.contains(&flag.name)
                        && (flag.value.is_none()
                            || flag.value_index != Some(flag.index)
                                && flag.value.as_ref().and_then(Word::as_literal).is_some_and(
                                    |value| {
                                        let negative_number =
                                            value.strip_prefix('-').is_some_and(|n| {
                                                let digits = |text: &str| {
                                                    text.bytes().all(|b| b.is_ascii_digit())
                                                };
                                                n.split_once('.').map_or_else(
                                                    || !n.is_empty() && digits(n),
                                                    |(whole, fraction)| {
                                                        !fraction.is_empty()
                                                            && digits(whole)
                                                            && digits(fraction)
                                                    },
                                                )
                                            });
                                        value.starts_with('-')
                                            && value != "-"
                                            && !value.contains(' ')
                                            && !negative_number
                                    },
                                ))
                }) {
                    return;
                }
                for flag in &parsed.flags {
                    if FILTER_REPO_FILE_FLAGS.contains(&flag.name)
                        && let Some(value) = &flag.value
                    {
                        s.filesystem_path_effect(
                            builder,
                            s.sub_index + flag.value_index.unwrap(),
                            value,
                            "filesystem.read",
                            Attrs::new(),
                        );
                    }
                }
            }
            s.repo_effect(
                builder,
                "git.history_rewrite",
                attrs(&[
                    (
                        "force",
                        git_effective_flag(s, &["-f", "--force"], &["--no-force"]),
                    ),
                    (
                        "no_verify",
                        sub == "rebase" && s.scanned(&["--no-verify"]).has(&["--no-verify"]),
                    ),
                ]),
            );
            // A dynamic option value (`--path "$DIR"`, `--onto "$BASE"`)
            // selects what is rewritten, never whether: the rewrite and its
            // force stay exact, and only the target is incomplete. An empty
            // revision, rebase's empty base or exec command, filter-repo's
            // empty `--path-rename` (it needs `OLD:NEW`), and an empty
            // `--git-dir` or `--work-tree` word stop the command before it
            // rewrites anything; filter-repo and filter-branch take an empty
            // path or filter as given, and `-C ''` stays in the cwd. rebase
            // reads only its last `--onto`, so an empty one before it is
            // never used.
            let last_onto = parsed.flags.iter().rposition(|flag| flag.name == "--onto");
            let empty_argument = parsed
                .operands
                .iter()
                .any(|(_, word)| word.as_literal() == Some(""))
                || parsed.flags.iter().enumerate().any(|(position, flag)| {
                    (sub == "rebase" && (flag.name != "--onto" || Some(position) == last_onto)
                        || flag.name == "--path-rename" && flag.value_index != Some(flag.index))
                        && flag.value.as_ref().and_then(Word::as_literal) == Some("")
                })
                || empty_repository_global(s);
            // git-rebase refuses `--keep-base` beside `--onto` or `--root`,
            // and an exec command with a newline or only whitespace
            // (`check_exec_cmd`), before replaying or running anything.
            let rebase_rejected = sub == "rebase"
                && (parsed.has(&["--keep-base"]) && parsed.has(&["--onto", "--root"])
                    || parsed.flags.iter().any(|flag| {
                        matches!(flag.name, "-x" | "--exec")
                            && flag.value.as_ref().and_then(Word::as_literal).is_some_and(
                                |command| {
                                    command.contains('\n')
                                        || command
                                            .trim_matches([' ', '\t', '\r', '\x0c', '\x0b'])
                                            .is_empty()
                                },
                            )
                    }));
            if git_options_known(&parsed) && !empty_argument && !rebase_rejected {
                let mut request = request_attrs(&[(
                    "force",
                    git_effective_flag(s, &["-f", "--force"], &["--no-force"]),
                )]);
                request.insert("rewrite".into(), AttrValue::String(sub.into()));
                request.insert("history_operation".into(), AttrValue::String(sub.into()));
                request.insert("scope".into(), AttrValue::String("targeted".into()));
                request.insert("broad".into(), AttrValue::Bool(false));
                request.insert(
                    "target_complete".into(),
                    AttrValue::Bool(
                        git_operands_known(&parsed) && git_option_values_known(&parsed),
                    ),
                );
                s.request_effect(builder, "git.history_rewrite_request", request);
                if sub == "rebase" {
                    rebase_exec_commands(builder, s, &parsed);
                }
            }
            s.hooks_boundary(builder);
        }
        "stash" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &[],
                    known_flags: &["-q", "--quiet"],
                    allow_abbreviation: true,
                },
            );
            let action = s
                .operands(false)
                .first()
                .and_then(|(_, w)| w.as_literal())
                .unwrap_or("push");
            match action {
                // git refuses an empty stash entry ("is not a valid
                // reference") before dropping anything.
                "drop" | "clear"
                    if empty_repository_global(s)
                        || action == "drop"
                            && s.operands(false).get(1).and_then(|(_, w)| w.as_literal())
                                == Some("") => {}
                "drop" | "clear" => {
                    s.repo_effect(builder, "git.recovery_destroy", attrs(&[("stash", true)]));
                    if git_controls_known(&parsed) {
                        let operands = s.operands(false);
                        let valid_operands = match action {
                            "clear" => operands.len() == 1,
                            "drop" => operands.len() <= 2,
                            _ => false,
                        };
                        let target_complete = operands
                            .iter()
                            .skip(1)
                            .all(|(_, word)| word.as_literal().is_some());
                        let mut request = request_attrs(&[("stash", true)]);
                        request.insert("target_complete".into(), AttrValue::Bool(target_complete));
                        request.insert(
                            "scope".into(),
                            AttrValue::String(
                                if action == "clear" {
                                    "whole"
                                } else {
                                    "selected"
                                }
                                .into(),
                            ),
                        );
                        request.insert("broad".into(), AttrValue::Bool(action == "clear"));
                        if target_complete
                            && let Some((_, target)) = operands.get(1)
                            && let Some(target) = target.as_literal()
                        {
                            request.insert("target".into(), AttrValue::String(target.into()));
                        }
                        if valid_operands {
                            s.request_effect(
                                builder,
                                "git.recovery_destroy_request",
                                request.clone(),
                            );
                            request.insert("delete".into(), AttrValue::Bool(true));
                            request.insert("ref".into(), AttrValue::String("refs/stash".into()));
                            request.insert(
                                "selection_complete".into(),
                                AttrValue::Bool(target_complete),
                            );
                            if target_complete {
                                s.request_effect(builder, "git.ref_delete_request", request);
                            } else {
                                git_argument_boundary(
                                    builder,
                                    s,
                                    "git stash entry is dynamic and may change option parsing",
                                );
                            }
                        }
                    }
                }
                _ => s.repo_effect(builder, "git.worktree_write", attrs(&[("stash", true)])),
            }
        }
        "init" => {
            let target = s
                .operands(false)
                .first()
                .map(|(i, w)| (*i, (*w).clone()))
                .unwrap_or((s.sub_index, Word::literal(".")));
            s.filesystem_path_effect(
                builder,
                target.0,
                &target.1,
                "filesystem.create",
                Attrs::new(),
            );
        }
        "config" => {
            // is_read_form filtered pure reads.
            s.repo_effect(builder, "git.config_write", Attrs::new());
            record_config_write(builder, s);
        }
        "remote" => remote(builder, s),
        "worktree" => {
            // `--` here terminates global options before the subcommand. Git
            // therefore sees `remove` as an unknown subcommand and performs
            // no worktree operation.
            if s.rest.first().and_then(Word::as_literal) == Some("--") {
                return;
            }
            let remove = s.rest.first().and_then(Word::as_literal) == Some("remove");
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: if remove { &[] } else { &["--expire"] },
                    known_flags: if remove {
                        &["-f", "--force", "--no-force", "-h", "--help"]
                    } else {
                        &[
                            "-f",
                            "--force",
                            "--no-force",
                            "-n",
                            "--dry-run",
                            "-v",
                            "--verbose",
                            "-q",
                            "--quiet",
                        ]
                    },
                    allow_abbreviation: true,
                },
            );
            if remove {
                if !parsed.unknown_flags.is_empty() {
                    git_argument_boundary(
                        builder,
                        s,
                        "git worktree remove arguments are not fully known",
                    );
                    return;
                }
                // Help and invalid arity terminate before worktree removal.
                if parsed.has(&["-h", "--help"]) || parsed.operands.len() != 2 {
                    return;
                }
            }
            let dry_run = parsed.has(&["-n", "--dry-run"]);
            let force = parsed_effective_flag(&parsed, &["-f", "--force"], &["--no-force"]);
            let operands = s.operands(false);
            match operands.first().and_then(|(_, w)| w.as_literal()) {
                Some("remove") if operands.len() > 1 => {
                    let mut a = attrs(&[("worktree_remove", true), ("force", force)]);
                    a.insert(
                        "discard_mode".into(),
                        AttrValue::String("worktree_remove".into()),
                    );
                    let mut selection = Vec::new();
                    for (i, w) in operands.iter().skip(1) {
                        let path = w
                            .as_literal()
                            .zip(s.cwd.as_deref().or(s.ctx.runtime_cwd))
                            .map(|(path, cwd)| Word::literal(crate::paths::join_cwd(cwd, path)));
                        let word = path.as_ref().unwrap_or(w);
                        s.git_path_effect(builder, *i, word, "git.worktree_discard", a.clone());
                        selection.extend(git_request_path(s, word));
                    }
                    // `git worktree remove` takes exactly one worktree; more
                    // operands, or one that is not a plain path, is a form
                    // this model cannot certify.
                    if git_controls_known(&parsed)
                        && operands.len() == 2
                        && selection.len() == 1
                        && git_operands_are_not_options(s, &operands)
                    {
                        let mut request = request_attrs(&[
                            ("force", force),
                            ("selection_complete", true),
                            (
                                "root_uses_invocation_cwd",
                                root_uses_invocation_cwd(s.globals, s.ctx),
                            ),
                            (
                                "discovers_from_worktree",
                                discovers_from_worktree(s.globals, s.ctx),
                            ),
                        ]);
                        request.insert(
                            "discard_mode".into(),
                            AttrValue::String("worktree_remove".into()),
                        );
                        request.insert("scope".into(), AttrValue::String("selected".into()));
                        request.insert("broad".into(), AttrValue::Bool(false));
                        request.insert("selections".into(), string_list(&selection));
                        s.request_effect(builder, "git.worktree_discard_request", request);
                    }
                }
                // A pruning dry run only reports the stale worktrees.
                Some("prune") if dry_run => s.repo_effect(builder, "git.read", Attrs::new()),
                Some("prune") => {
                    s.repo_effect(
                        builder,
                        "git.worktree_discard",
                        attrs(&[("worktree_prune", true)]),
                    );
                    // The literal scan cannot tell `--expire <time>` from an
                    // extra operand; the option scan consumes the value.
                    if git_controls_known(&parsed) && parsed.operands.len() == 1 {
                        let mut request = request_attrs(&[
                            ("force", force),
                            ("selection_complete", true),
                            (
                                "root_uses_invocation_cwd",
                                root_uses_invocation_cwd(s.globals, s.ctx),
                            ),
                            (
                                "discovers_from_worktree",
                                discovers_from_worktree(s.globals, s.ctx),
                            ),
                        ]);
                        request.insert(
                            "discard_mode".into(),
                            AttrValue::String("worktree_prune".into()),
                        );
                        request.insert("scope".into(), AttrValue::String("whole".into()));
                        request.insert("broad".into(), AttrValue::Bool(true));
                        s.request_effect(builder, "git.worktree_discard_request", request);
                    }
                }
                _ => s.repo_effect(builder, "git.worktree_write", Attrs::new()),
            }
        }
        "update-ref" if s.scanned(&["--stdin"]).has(&["--stdin"]) => {
            if !update_ref_stdin(builder, s) {
                unmodeled_subcommand_boundary(
                    builder,
                    s,
                    "git update-ref --stdin input is not a literal list of ref commands",
                );
            }
        }
        "update-ref"
            if !s.scanned(&["--stdin"]).has(&["--stdin"])
                && s.operands(false).len()
                    >= if s.scanned(&["-d"]).has(&["-d"]) {
                        1
                    } else {
                        2
                    } =>
        {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &[],
                    known_flags: &["-d", "--no-deref", "--no-create-reflog"],
                    allow_abbreviation: true,
                },
            );
            let delete = parsed.has(&["-d"]);
            let mut a = attrs(&[("delete", delete)]);
            if let Some(name) = s.operands(false).first().and_then(|(_, w)| w.as_literal()) {
                a.insert("ref".into(), AttrValue::String(name.into()));
                // An optional old value only makes the deletion conditional.
                if delete
                    && name == STASH_REF
                    && git_controls_known(&parsed)
                    && s.operands(false).len() <= 2
                {
                    stash_destroyed(builder, s);
                }
                if delete && git_controls_known(&parsed) && s.operands(false).len() == 1 {
                    let mut request = request_attrs(&[("delete", true)]);
                    request.insert("ref".into(), AttrValue::String(name.into()));
                    request.insert("target_complete".into(), AttrValue::Bool(true));
                    request.insert("scope".into(), AttrValue::String("selected".into()));
                    request.insert("broad".into(), AttrValue::Bool(false));
                    s.request_effect(builder, "git.ref_delete_request", request);
                }
            }
            s.repo_effect(builder, "git.ref_update", a);
        }
        "submodule"
            if s.operands(false).first().and_then(|(_, w)| w.as_literal()) == Some("deinit")
                && (s.scanned(&["--all"]).has(&["--all"]) || s.operands(false).len() > 1) =>
        {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &[],
                    known_flags: &[
                        "-f",
                        "--force",
                        "--no-force",
                        "--all",
                        "-q",
                        "--quiet",
                        "--cached",
                    ],
                    allow_abbreviation: true,
                },
            );
            let (all, force, operands, controls_known) = match submodule_deinit_arguments(s) {
                DeinitArguments::Usage => return,
                DeinitArguments::Known {
                    all,
                    force,
                    operands,
                } => (all, force, operands, true),
                DeinitArguments::Unknown => {
                    let operands = s.operands(false);
                    let known =
                        git_controls_known(&parsed) && git_operands_are_not_options(s, &operands);
                    (
                        parsed.has(&["--all"]),
                        parsed_effective_flag(&parsed, &["-f", "--force"], &["--no-force"]),
                        operands,
                        known,
                    )
                }
            };
            // Git rejects combining all submodules with an explicit pathspec.
            if all && operands.len() > 1 && parsed.unknown_flags.is_empty() {
                return;
            }
            let mut a = attrs(&[("submodule", true), ("force", force)]);
            a.insert(
                "discard_mode".into(),
                AttrValue::String("submodule_deinit".into()),
            );
            let mut request = request_attrs(&[
                ("force", force),
                (
                    "root_uses_invocation_cwd",
                    root_uses_invocation_cwd(s.globals, s.ctx),
                ),
                (
                    "discovers_from_worktree",
                    discovers_from_worktree(s.globals, s.ctx),
                ),
            ]);
            request.insert(
                "discard_mode".into(),
                AttrValue::String("submodule_deinit".into()),
            );
            if all {
                s.repo_effect(builder, "git.worktree_discard", a);
                request.insert("selection_complete".into(), AttrValue::Bool(true));
                request.insert("scope".into(), AttrValue::String("whole".into()));
                request.insert("broad".into(), AttrValue::Bool(true));
                // `--all` deinitializes every submodule; naming one as well
                // is a form git rejects.
                if controls_known && operands.len() == 1 {
                    s.request_effect(builder, "git.worktree_discard_request", request);
                }
            } else {
                let mut selection = Vec::new();
                for (i, w) in operands.iter().skip(1) {
                    s.git_path_effect(builder, *i, w, "git.worktree_discard", a.clone());
                    selection.extend(git_request_path(s, w));
                }
                request.insert(
                    "selection_complete".into(),
                    AttrValue::Bool(selection.len() + 1 == operands.len()),
                );
                request.insert("scope".into(), AttrValue::String("selected".into()));
                request.insert("broad".into(), AttrValue::Bool(false));
                request.insert("selections".into(), string_list(&selection));
                if controls_known && selection.len() + 1 == operands.len() {
                    s.request_effect(builder, "git.worktree_discard_request", request);
                }
            }
        }
        "read-tree" => {
            if !read_tree(builder, s) {
                unmodeled_subcommand_boundary(builder, s, "git read-tree form is not modeled");
            }
        }
        "checkout-index" => {
            if !checkout_index(builder, s) {
                unmodeled_subcommand_boundary(builder, s, "git checkout-index form is not modeled");
            }
        }
        "send-pack" => {
            if !send_pack(builder, s) {
                unmodeled_subcommand_boundary(builder, s, "git send-pack form is not modeled");
            }
        }
        "submodule"
            if s.operands(false).first().and_then(|(_, w)| w.as_literal()) == Some("foreach") =>
        {
            if !submodule_foreach(builder, s) {
                unmodeled_subcommand_boundary(
                    builder,
                    s,
                    "git submodule foreach options are not statically known",
                );
            }
        }
        "repack" => {
            if !repack(builder, s) {
                unmodeled_subcommand_boundary(
                    builder,
                    s,
                    "git repack form that keeps unreachable objects is not modeled",
                );
            }
        }
        "maintenance" => {
            if !maintenance(builder, s) {
                unmodeled_subcommand_boundary(builder, s, "git maintenance form is not modeled");
            }
        }
        "merge" | "cherry-pick" | "revert" | "am" | "apply" => {
            s.repo_effect(builder, "git.worktree_write", Attrs::new());
            s.repo_effect(builder, "git.ref_update", Attrs::new());
            s.hooks_boundary(builder);
        }
        "prune" => {
            let parsed = git_options(
                s,
                &FlagSpec {
                    value_flags: &["--expire"],
                    known_flags: &["-n", "--dry-run"],
                    allow_abbreviation: true,
                },
            );
            if empty_option_value(&parsed) || empty_repository_global(s) {
                return;
            }
            // A bare `git prune` has no grace period and removes every
            // unreachable object. `--expire` restricts that set by age.
            if s.scanned(&["-n", "--dry-run"]).has(&["-n", "--dry-run"]) {
                s.repo_effect(builder, "git.read", Attrs::new());
            } else {
                let valid_operands = parsed.operands.is_empty();
                let immediate = parsed
                    .value_of(&["--expire"])
                    .and_then(Word::as_literal)
                    .map(immediate_expiry)
                    .unwrap_or(!parsed.has(&["--expire"]));
                s.repo_effect(
                    builder,
                    "git.recovery_destroy",
                    attrs(&[("immediate", immediate)]),
                );
                if git_controls_known(&parsed) && valid_operands {
                    let mut request = request_attrs(&[("immediate", immediate)]);
                    request.insert(
                        "scope".into(),
                        AttrValue::String(if immediate { "whole" } else { "named" }.into()),
                    );
                    request.insert("broad".into(), AttrValue::Bool(immediate));
                    s.request_effect(builder, "git.recovery_destroy_request", request);
                }
            }
        }
        _ => unmodeled_subcommand_boundary(
            builder,
            s,
            &format!("git subcommand {sub:?} (possibly an alias)"),
        ),
    }
}

/// How git-submodule(1)'s script reads `submodule ... deinit ...`.
enum DeinitArguments<'a> {
    /// The script prints its usage and deinitializes nothing.
    Usage,
    /// A dynamic word before the paths may be an option.
    Unknown,
    /// `operands` is the `deinit` word followed by every path.
    Known {
        all: bool,
        force: bool,
        operands: Vec<(u32, &'a Word)>,
    },
}

/// The script reads `[-q | --quiet]... deinit`, then deinit's options one
/// exact word at a time up to `--` or the first path, and prints its usage
/// for any other option word: `--cached`, `--no-force`, an abbreviation or a
/// cluster (`-qf`). It hands every later word to git as a pathspec, so
/// `deinit lib --force` deinitializes `lib` unforced, together with any
/// submodule registered at `--force`; git fails without deinitializing
/// anything when a pathspec matches none, which the request's success path
/// already covers. `--all` beside a path is a usage error too.
fn submodule_deinit_arguments<'a>(s: &'a SubCtx<'a>) -> DeinitArguments<'a> {
    let mut words = (s.rest_offset..).zip(s.rest);
    let deinit = loop {
        match words.next() {
            Some((_, word)) if matches!(word.as_literal(), Some("-q" | "--quiet")) => {}
            Some((index, word)) if word.as_literal() == Some("deinit") => break (index, word),
            Some((_, word)) if word.as_literal().is_some() => return DeinitArguments::Usage,
            _ => return DeinitArguments::Unknown,
        }
    };
    let (mut all, mut force) = (false, false);
    let mut operands = vec![deinit];
    while let Some((index, word)) = words.next() {
        match word.as_literal() {
            Some("-f" | "--force") => force = true,
            Some("-q" | "--quiet") => {}
            Some("--all") => all = true,
            Some("--") => {
                operands.extend(words);
                break;
            }
            Some(text) if text.starts_with('-') => return DeinitArguments::Usage,
            Some(_) => {
                operands.push((index, word));
                operands.extend(words);
                break;
            }
            None => return DeinitArguments::Unknown,
        }
    }
    if all && operands.len() > 1 {
        return DeinitArguments::Usage;
    }
    DeinitArguments::Known {
        all,
        force,
        operands,
    }
}

/// git-pull(1) options, with the fetch and merge options it passes on, that
/// take the next word as their value when none is attached.
const PULL_VALUE_OPTIONS: &[&str] = &[
    "--cleanup",
    "--strategy",
    "--strategy-option",
    "--upload-pack",
    "--jobs",
    "--depth",
    "--shallow-since",
    "--shallow-exclude",
    "--deepen",
    "--refmap",
    "--server-option",
    "--negotiation-tip",
];

/// git-pull(1) options that take no value, or only an attached one.
const PULL_FLAG_OPTIONS: &[&str] = &[
    "--verbose",
    "--quiet",
    "--progress",
    "--recurse-submodules",
    "--stat",
    "--summary",
    "--compact-summary",
    "--log",
    "--signoff",
    "--squash",
    "--commit",
    "--edit",
    "--ff",
    "--ff-only",
    "--verify",
    "--verify-signatures",
    "--autostash",
    "--gpg-sign",
    "--allow-unrelated-histories",
    "--all",
    "--append",
    "--force",
    "--tags",
    "--prune",
    "--keep",
    "--unshallow",
    "--update-shallow",
    "--ipv4",
    "--ipv6",
    "--show-forced-updates",
    "--set-upstream",
];

/// Whether `git pull` rebases the current branch onto what it fetched, and
/// whether that is certain. Only the command line decides certainly: the
/// last `-r[<mode>]`, `--rebase[=<mode>]` or `--no-rebase` (or their unique
/// abbreviations `--reb…`, `--no-reb…`), with `--dry-run` stopping after the
/// fetch. Options that take a value consume it first, so an option-shaped
/// value (`-o --no-rebase`) decides nothing. Without a command-line control,
/// an inline `pull.rebase` or `branch.<name>.rebase` may select a rebase,
/// which the model does not resolve; nor does it resolve a dynamic word, an
/// option it does not know (it may be an abbreviation that takes a value),
/// a short option letter it does not know, or a mode it cannot classify.
/// Repository configuration is not read.
fn pull_rebases(s: &SubCtx) -> (bool, bool) {
    let mut certain = true;
    let mut rebase = None;
    // git reads the mode as a boolean, then as merges or interactive.
    let mode = |value: &str, rebase: &mut Option<bool>, certain: &mut bool| match git_bool(value) {
        Some(value) => *rebase = Some(value),
        None if matches!(value, "merges" | "m" | "interactive" | "i") => *rebase = Some(true),
        None => {
            *rebase = None;
            *certain = false;
        }
    };
    let mut dry_run = false;
    let mut words = s.rest.iter();
    while let Some(word) = words.next() {
        let Some(text) = word.as_literal() else {
            certain = false;
            continue;
        };
        if text == "--" {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (format!("--{name}"), Some(value)),
                None => (text.to_string(), None),
            };
            match name.as_str() {
                name if name.len() >= 5 && "--rebase".starts_with(name) => {
                    mode(value.unwrap_or("true"), &mut rebase, &mut certain)
                }
                name if name.len() >= 8 && "--no-rebase".starts_with(name) && value.is_none() => {
                    rebase = Some(false)
                }
                "--dry-run" if value.is_none() => dry_run = true,
                name if PULL_VALUE_OPTIONS.contains(&name) => {
                    if value.is_none() && words.next().is_none() {
                        certain = false;
                    }
                }
                name if PULL_FLAG_OPTIONS.contains(&name)
                    || name.strip_prefix("--no-").is_some_and(|flag| {
                        PULL_FLAG_OPTIONS.contains(&format!("--{flag}").as_str())
                    }) => {}
                _ => certain = false,
            }
            continue;
        }
        let Some(cluster) = text.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            continue;
        };
        for (index, c) in cluster.char_indices() {
            let attached = &cluster[index + c.len_utf8()..];
            match c {
                'v' | 'q' | 'n' | 'a' | 'f' | 't' | 'p' | 'k' | '4' | '6' => continue,
                'r' => mode(
                    if attached.is_empty() {
                        "true"
                    } else {
                        attached
                    },
                    &mut rebase,
                    &mut certain,
                ),
                'S' => {}
                's' | 'X' | 'j' | 'o' => {
                    if attached.is_empty() && words.next().is_none() {
                        certain = false;
                    }
                }
                _ => certain = false,
            }
            break;
        }
    }
    if rebase.is_none()
        && s.globals.configs.iter().any(|ConfigEntry { key, .. }| {
            key.is_empty()
                || key.split_once('.').is_some_and(|(section, rest)| {
                    section.eq_ignore_ascii_case("pull") && rest.eq_ignore_ascii_case("rebase")
                        || section.eq_ignore_ascii_case("branch")
                            && rest.rsplit_once('.').is_some_and(|(_, variable)| {
                                variable.eq_ignore_ascii_case("rebase")
                            })
                })
        })
    {
        certain = false;
    }
    (rebase == Some(true) && !dry_run, certain)
}

/// `git maintenance run --task=<task>...` runs the named tasks in order, and
/// without `--task` the tasks its configuration and strategy select. The gc task runs
/// `git gc` as a child that inherits this invocation's `-c` settings, passing
/// on `--auto` and `--quiet`; the `--no-detach` and `--no-quiet` it may add
/// select nothing gc destroys. Returns false for the forms left to the
/// unmodeled-subcommand boundary: other actions, `--schedule`, and dynamic
/// task names.
fn maintenance(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--task", "--schedule"],
            known_flags: &["--auto", "--quiet", "--no-quiet"],
            allow_abbreviation: true,
        },
    );
    let tasks = parsed.values_of(&["--task"]);
    // The action is the word right after `maintenance`.
    if s.rest.first().and_then(Word::as_literal) != Some("run")
        || !matches!(parsed.operands.as_slice(), [(_, action)] if action.as_literal() == Some("run"))
        || !git_controls_known(&parsed)
        || parsed.has(&["--schedule"])
    {
        return false;
    }
    // git matches task names case-insensitively and refuses the whole list,
    // before running any task, when one names no task or one is named twice.
    let mut names = tasks
        .iter()
        .map(|(_, task)| task.as_literal().unwrap().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if names.is_empty() {
        // Without `--task`, the tasks come from `maintenance.<task>.enabled`
        // over a default strategy that changed between releases: gc in
        // 2.39, geometric (no gc) in 2.55. Only a setting that git reads as
        // true certainly selects gc; repository configuration, which can
        // select other tasks or the strategy, is not observed.
        if config_value(s.globals, "maintenance.gc.enabled")
            .flatten()
            .and_then(git_bool)
            == Some(true)
        {
            names.push("gc".into());
        }
        unmodeled_subcommand_boundary(
            builder,
            s,
            "git maintenance tasks selected by configuration or the default strategy are not observed",
        );
    }
    if names
        .iter()
        .enumerate()
        .any(|(index, name)| names[..index].contains(name))
    {
        return true;
    }
    // Every task some git release defines; a name outside them may still
    // be one a later release adds.
    if let Some(name) = names.iter().find(|name| {
        !matches!(
            name.as_str(),
            "gc" | "commit-graph"
                | "prefetch"
                | "loose-objects"
                | "incremental-repack"
                | "pack-refs"
                | "reflog-expire"
                | "worktree-prune"
                | "rerere-gc"
        )
    }) {
        unmodeled_subcommand_boundary(builder, s, &format!("git maintenance task {name:?}"));
        return true;
    }
    for name in names {
        if name != "gc" {
            unmodeled_subcommand_boundary(builder, s, &format!("git maintenance task {name:?}"));
            continue;
        }
        // With `--auto` the task runs only when `git gc --auto` would
        // collect, which a nonpositive `gc.auto` turns off (`need_to_gc`).
        // A value that is not a plain integer, or that the model cannot
        // read, leaves open whether the task runs.
        if parsed.has(&["--auto"])
            && let Some(value) = config_value(s.globals, "gc.auto")
            && let limit = value.and_then(|value| value.parse::<i64>().ok())
            && limit.is_none_or(|limit| limit <= 0)
        {
            if limit.is_none() {
                git_argument_boundary(
                    builder,
                    s,
                    "git gc.auto configuration is not a statically known integer",
                );
            }
            continue;
        }
        let offset = s.rest_offset as usize;
        let mut argv = s.ctx.argv[..offset - 1].to_vec();
        argv.push(Word::literal("gc"));
        for flag in ["--auto", "--quiet"] {
            if parsed.has(&[flag]) {
                argv.push(Word::literal(flag));
            }
        }
        let provenance = (0..argv.len())
            .map(|index| {
                vec![arg_node(
                    builder,
                    s.ctx,
                    if index < offset - 1 {
                        index as u32
                    } else {
                        s.sub_index
                    },
                )]
            })
            .collect::<Vec<_>>();
        let ctx = InvocationCtx {
            argv: &argv,
            stdin: s.ctx.stdin,
            argv_provenance: Some(&provenance),
            cwd: s.ctx.cwd,
            cwd_resource: s.ctx.cwd_resource.clone(),
            runtime_cwd: s.ctx.runtime_cwd,
            scope: s.ctx.scope,
            cwd_node: s.ctx.cwd_node,
            nest: s.ctx.nest,
            depth: s.ctx.depth,
            model_stack: s.ctx.model_stack.clone(),
        };
        let gc = SubCtx {
            globals: s.globals,
            ctx: &ctx,
            model_node: s.model_node,
            repo: s.repo.clone(),
            cwd: s.cwd.clone(),
            rest: &argv[offset..],
            rest_offset: s.rest_offset,
            sub_index: s.sub_index,
        };
        dispatch(builder, "gc", &gc);
    }
    true
}

/// git-checkout-index(1) writes index entries over the working tree: `-a`
/// every entry below the cwd (checkout-index.c `checkout_all` skips entries
/// outside the prefix), as `checkout -- .` selects, or the named files. It
/// replaces an existing file only with `-f`. `--temp`, `--prefix` and
/// `--stdin` write elsewhere or read their paths elsewhere and are not
/// modeled. Returns false for a form the model does not read.
fn checkout_index(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--stage"],
            known_flags: &[
                "-a",
                "--all",
                "-f",
                "--force",
                "-u",
                "--index",
                "-q",
                "--quiet",
                "-n",
                "--no-create",
                "--ignore-skip-worktree-bits",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) || empty_repository_global(s) {
        return true;
    }
    if !git_controls_known(&parsed) {
        return false;
    }
    let all = parsed.has(&["-a", "--all"]);
    let operands = s.operands(false);
    // git dies on `--all` beside file names before writing anything.
    if all && !operands.is_empty() {
        return true;
    }
    if !parsed.has(&["-f", "--force"]) {
        s.repo_effect(builder, "git.worktree_write", Attrs::new());
        return true;
    }
    let default_path = Word::literal(".");
    let paths = if all {
        vec![(s.sub_index, &default_path)]
    } else {
        operands
    };
    let mut discard = attrs(&[("force", true)]);
    discard.insert("discard_mode".into(), AttrValue::String("checkout".into()));
    for (index, path) in &paths {
        s.git_path_effect(
            builder,
            *index,
            path,
            "git.worktree_discard",
            discard.clone(),
        );
        s.filesystem_path_effect(builder, *index, path, "filesystem.write", Attrs::new());
    }
    // Named operands are file names, not pathspecs: one spelled like
    // pathspec magic is not read as a selection.
    let whole_tree = all && foreach_whole_tree(builder, s, &paths);
    let selection_paths = if whole_tree {
        Some(Vec::new())
    } else {
        paths
            .iter()
            .map(|(_, path)| {
                path.as_literal()
                    .filter(|text| all || !text.starts_with(':'))
                    .and_then(|_| git_request_path(s, path))
            })
            .collect::<Option<Vec<_>>>()
    };
    let Some(selection_paths) = selection_paths.filter(|_| !paths.is_empty()) else {
        git_argument_boundary(
            builder,
            s,
            "git checkout-index file selection is not a known plain path",
        );
        return true;
    };
    let mut request = request_attrs(&[
        ("force", true),
        ("selection_complete", true),
        (
            "root_uses_invocation_cwd",
            root_uses_invocation_cwd(s.globals, s.ctx),
        ),
        (
            "discovers_from_worktree",
            discovers_from_worktree(s.globals, s.ctx),
        ),
    ]);
    request.insert("discard_mode".into(), AttrValue::String("checkout".into()));
    insert_selection(&mut request, whole_tree, &selection_paths);
    s.request_effect(builder, "git.worktree_discard_request", request);
    true
}

/// git-send-pack(1) pushes refs over the Git protocol as `git push` does,
/// without remotes or push configuration: `--force` drops the fast-forward
/// check for every ref, `--mirror` force-updates every ref, a `+` ref drops it
/// for that ref, and `--dry-run` sends nothing. The refs a push updates are not
/// enumerated, and a lease is not modeled. Returns false for a form the model
/// does not read.
fn send_pack(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--receive-pack", "--exec", "--push-option"],
            known_flags: &[
                "-f",
                "--force",
                "--no-force",
                "-n",
                "--dry-run",
                "--no-dry-run",
                "--mirror",
                "--no-mirror",
                "--all",
                "--no-all",
                "-v",
                "--verbose",
                "-q",
                "--quiet",
                "--thin",
                "--no-thin",
                "--atomic",
                "--no-atomic",
                "--signed",
                "--no-signed",
                "--progress",
                "--no-progress",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) {
        return true;
    }
    if !git_controls_known(&parsed) {
        return false;
    }
    let operands = s.operands(false);
    // Without a repository to push to, git prints its usage.
    let Some((_, refs)) = operands.split_first() else {
        return true;
    };
    let force = parsed_effective_flag(&parsed, &["-f", "--force"], &["--no-force"]);
    let mirror = parsed_effective_flag(&parsed, &["--mirror"], &["--no-mirror"]);
    s.remote_network(builder, "network.upload");
    if parsed_effective_flag(&parsed, &["-n", "--dry-run"], &["--no-dry-run"]) {
        return true;
    }
    let mut request = request_attrs(&[
        ("push", true),
        ("dry_run", false),
        ("controls_complete", true),
        ("destination_complete", false),
        ("explicit_force", force),
        ("force", force || mirror),
        ("mirror", mirror),
        (
            "all",
            parsed_effective_flag(&parsed, &["--all"], &["--no-all"]),
        ),
        ("lease_requested", false),
        ("all_refs_lease", false),
        ("prune", false),
    ]);
    let destinations = refs
        .iter()
        .map(|(_, word)| {
            // As for `git push`, `:` and `+:` push the matching refs and
            // delete nothing, a word whose literal start is not `:` deletes
            // nothing either, and every deletion is forced.
            let prefix = word.literal_prefix();
            let deleted = word
                .as_literal()
                .is_none_or(|text| text.strip_prefix('+').unwrap_or(text) != ":")
                && prefix.strip_prefix('+').unwrap_or(prefix).starts_with(':');
            PushedRef {
                destination: None,
                source: None,
                forced: Some(force || mirror || deleted || refspec_word_forced(word)),
                deleted: Some(deleted),
                certain: true,
            }
        })
        .collect::<Vec<_>>();
    push_destination_lists(&mut request, &destinations, Some((false, &[])), true, false);
    s.request_effect(builder, "git.push_request", request);
    true
}

/// git-read-tree(1) reads trees into the index, and with `-u` checks the
/// result out. `--reset -u` does so even when that loses working tree
/// changes or untracked files in the way, which is `git reset --hard` to the
/// tree without moving HEAD; `-m -u` refuses to lose them. Returns false for
/// the forms left to the unmodeled-subcommand boundary.
fn read_tree(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--index-output", "--prefix", "--exclude-per-directory"],
            known_flags: &[
                "-m",
                "--trivial",
                "--aggressive",
                "--reset",
                "-u",
                "-i",
                "-n",
                "--dry-run",
                "--empty",
                "-v",
                "--verbose",
                "-q",
                "--quiet",
                "--no-sparse-checkout",
                "--debug-unpack",
                "--no-dry-run",
                "--no-debug-unpack",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) || empty_repository_global(s) {
        return true;
    }
    if !git_controls_known(&parsed) || parsed.operands.len() > 3 {
        return false;
    }
    // git-read-tree(1) dies on -u beside -i before reading any tree.
    if parsed.has(&["-u"]) && parsed.has(&["-i"]) {
        return true;
    }
    // A dry run and `--debug-unpack`, which prints each merge entry in place
    // of merging it, write neither the index nor the working tree; the last
    // of each switch and its negation wins.
    if parsed_effective_flag(&parsed, &["-n", "--dry-run"], &["--no-dry-run"])
        || parsed_effective_flag(&parsed, &["--debug-unpack"], &["--no-debug-unpack"])
    {
        s.repo_effect(builder, "git.read", Attrs::new());
        return true;
    }
    let update = parsed.has(&["-u"]);
    if !update || !parsed.has(&["--reset"]) {
        s.repo_effect(builder, "git.index_write", Attrs::new());
        if update {
            s.repo_effect(builder, "git.worktree_write", Attrs::new());
        }
        return true;
    }
    // git dies on --reset beside -m or --prefix before reading any tree.
    if parsed.has(&["-m", "--prefix"]) {
        return true;
    }
    let mut attributes: Attrs = [("hard", true), ("dry_run", false)]
        .into_iter()
        .map(|(key, value)| (key.into(), AttrValue::Bool(value)))
        .collect();
    attributes.insert("discard_mode".into(), AttrValue::String("reset".into()));
    attributes.insert("reset_mode".into(), AttrValue::String("hard".into()));
    s.repo_effect(builder, "git.index_write", Attrs::new());
    s.repo_effect(builder, "git.worktree_discard", attributes);
    let operands_known = git_operands_known(&parsed);
    let mut request = request_attrs(&[("hard", true), ("dry_run", false)]);
    request.insert("discard_mode".into(), AttrValue::String("reset".into()));
    request.insert("reset_mode".into(), AttrValue::String("hard".into()));
    request.insert("scope".into(), AttrValue::String("targeted".into()));
    request.insert("broad".into(), AttrValue::Bool(false));
    request.insert("target_complete".into(), AttrValue::Bool(operands_known));
    if operands_known
        && let [(_, target)] = parsed.operands.as_slice()
        && let Some(target) = target.as_literal()
    {
        request.insert("target".into(), AttrValue::String(target.into()));
    }
    s.request_effect(builder, "git.reset_request", request);
    true
}

/// git-submodule(1) `foreach [--recursive] <command>` runs the command in
/// each checked-out submodule, as git runs a shell alias: through the shell
/// when it has shell syntax, directly otherwise. A lone command word also
/// sees `$name`, `$sm_path`, `$displaypath`, `$sha1` and `$toplevel`. Which
/// submodules exist and where is not observed. Returns false when the words
/// before the command cannot be read.
fn submodule_foreach(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let Some(action) = s
        .rest
        .iter()
        .position(|word| word.as_literal() == Some("foreach"))
    else {
        return false;
    };
    if !s.rest[..action]
        .iter()
        .all(|word| matches!(word.as_literal(), Some("-q" | "--quiet")))
    {
        return false;
    }
    // Releases differ: 2.39's script takes `-q`, `--quiet` and
    // `--recursive` and prints its usage for any other option, `--`
    // included; later releases read them with parse-options, which also
    // takes `--`, `--no-` negations and unique abbreviations. The command is
    // analysed for every form some release runs.
    let mut start = action + 1;
    while let Some(word) = s.rest.get(start) {
        match word.as_literal() {
            Some("--") => {
                start += 1;
                break;
            }
            Some("-q") => start += 1,
            Some(text) if text.strip_prefix("--").is_some_and(foreach_option) => start += 1,
            Some(text) if text.starts_with('-') => return false,
            Some(_) => break,
            None => return false,
        }
    }
    let command = &s.rest[start..];
    let Some(first) = command.first() else {
        return true;
    };
    let base = s.rest_offset as usize + start;
    let command_node = arg_node(builder, s.ctx, base as u32);
    let mut provenance: Vec<Vec<ProvenanceRef>> = Vec::new();
    let mut argv = match first.as_literal() {
        Some(source)
            if source.contains([
                '|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', ' ', '\t', '\n', '*',
                '?', '[', '#', '~', '=', '%',
            ]) =>
        {
            let words = vec![
                Word::literal("/bin/sh"),
                Word::literal("-c"),
                Word::literal(if command.len() > 1 {
                    format!("{source} \"$@\"")
                } else {
                    source.to_string()
                }),
                Word::literal(source),
            ];
            provenance.extend(words.iter().map(|_| vec![s.model_node, command_node]));
            words
        }
        _ => {
            provenance.push(vec![command_node]);
            vec![first.clone()]
        }
    };
    for (offset, word) in command.iter().enumerate().skip(1) {
        argv.push(word.clone());
        provenance.push(vec![arg_node(builder, s.ctx, (base + offset) as u32)]);
    }
    let mut environment: std::collections::BTreeMap<String, Option<ResourceExpr>> =
        if command.len() == 1 {
            ["name", "sm_path", "displaypath", "sha1", "toplevel"]
                .into_iter()
                .map(|name| (name.to_string(), None))
                .collect()
        } else {
            Default::default()
        };
    // Each submodule's command runs with `GIT_DIR=.git` and git's other
    // repository-local variables unset, keeping the command-scope
    // configuration, -c included (run-command.c `prepare_other_repo_env`).
    environment.insert(
        "GIT_DIR".into(),
        Some(ResourceExpr::Literal {
            value: ".git".into(),
        }),
    );
    if let Some(parameters) = &s.globals.command_parameters {
        environment.insert(
            "GIT_CONFIG_PARAMETERS".into(),
            parameters
                .clone()
                .map(|value| ResourceExpr::Literal { value }),
        );
    }
    let unsets = GIT_LOCAL_REPO_ENV
        .iter()
        .filter(|name| {
            !matches!(
                **name,
                "GIT_DIR" | "GIT_CONFIG_PARAMETERS" | "GIT_CONFIG_COUNT"
            )
        })
        .map(|name| name.to_string())
        .collect();
    builder.push_git_foreach(s.repo.clone());
    s.ctx.nest.nest(
        builder,
        crate::nest::Transition::exec(argv.iter().map(crate::nest::word_resource).collect(), argv)
            .cwd(
                ResourceExpr::Parameter {
                    name: "git_submodule".into(),
                },
                None,
            )
            .runtime_cwd(None)
            .environment(environment, Default::default(), unsets)
            .stdin(s.ctx.stdin)
            .argv_provenance(Some(&provenance)),
        &[s.model_node, command_node],
        s.ctx.depth,
    );
    builder.pop_git_foreach();
    true
}

/// A `submodule foreach` long option some release accepts: `--quiet`,
/// `--recursive`, their `--no-` negations, or a unique prefix of one.
fn foreach_option(name: &str) -> bool {
    const NAMES: [&str; 4] = ["quiet", "recursive", "no-quiet", "no-recursive"];
    !name.is_empty()
        && (NAMES.contains(&name)
            || NAMES.iter().filter(|full| full.starts_with(name)).count() == 1)
}

/// git's `local_repo_env`: the variables that select the repository a git
/// command works on.
const GIT_LOCAL_REPO_ENV: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];

/// git-repack(1): with `-d`, packing everything into one pack (`-a`, `-A`
/// or `--cruft`) deletes the old packs, and with them each unreachable
/// object the new pack left out. `-a` leaves out every one of them, so they
/// are gone at once, as `git gc --prune=now` removes them; objects a reflog
/// reaches are packed and survive. `-A`, or `--unpack-unreachable` beside
/// any of them, turns them loose instead, except those older than its date;
/// `--cruft` packs them apart, except those older than `--cruft-expiration`;
/// `-k` keeps them in the new pack. Returns false, leaving the invocation to
/// the unmodeled-subcommand boundary, for every form that does not certainly
/// destroy them, including the combinations git refuses.
fn repack(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[
                "--cruft-expiration",
                "--unpack-unreachable",
                "--expire-to",
                "--window",
                "--window-memory",
                "--depth",
                "--threads",
                "--max-pack-size",
                "--keep-pack",
                "-g",
                "--geometric",
            ],
            known_flags: &[
                "-a",
                "-A",
                "--cruft",
                "--no-cruft",
                "-d",
                "-k",
                "--keep-unreachable",
                "--no-keep-unreachable",
                "-f",
                "-F",
                "-n",
                "-q",
                "--quiet",
                "-l",
                "--local",
                "-b",
                "--write-bitmap-index",
                "-i",
                "--delta-islands",
                "--pack-kept-objects",
                "-m",
                "--write-midx",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) || empty_repository_global(s) {
        return true;
    }
    if !git_controls_known(&parsed) || !parsed.operands.is_empty() || !parsed.has(&["-d"]) {
        return false;
    }
    let cruft = parsed_effective_flag(&parsed, &["--cruft"], &["--no-cruft"]);
    let keep = parsed_effective_flag(
        &parsed,
        &["-k", "--keep-unreachable"],
        &["--no-keep-unreachable"],
    );
    let last_immediate = |name: &str| {
        parsed
            .value_of(&[name])
            .and_then(Word::as_literal)
            .is_some_and(immediate_expiry)
    };
    let loosen = parsed.has(&["-A", "--unpack-unreachable"]);
    // git refuses these combinations before it packs anything.
    if keep && loosen || cruft && (loosen || keep) {
        return false;
    }
    let destroys = if cruft {
        last_immediate("--cruft-expiration") && !parsed.has(&["--expire-to"])
    } else if loosen {
        parsed.has(&["-a", "-A"]) && last_immediate("--unpack-unreachable")
    } else {
        parsed.has(&["-a"]) && !keep
    };
    if !destroys {
        return false;
    }
    s.repo_effect(
        builder,
        "git.recovery_destroy",
        attrs(&[("immediate", true)]),
    );
    let mut request = request_attrs(&[("immediate", true), ("recovery", true)]);
    request.insert("scope".into(), AttrValue::String("whole".into()));
    request.insert("broad".into(), AttrValue::Bool(true));
    s.request_effect(builder, "git.recovery_destroy_request", request);
    true
}

/// `git update-ref --stdin` reads one command per line (git-update-ref(1)).
/// Ref commands and `option no-deref` queue into a transaction. Without
/// `start`, the end of input commits it; after `start`, only `commit` does,
/// and `abort` or the end of input discards it. After `prepare` only
/// `commit` or `abort` may follow, and after either of those only `start`.
/// A transaction's effects are planned when it commits, so nothing later
/// takes them back. git dies at a line every supported release refuses,
/// discarding the open transaction. A line the model does not classify (a
/// verb such as the `symref-*` family that only some releases accept, a
/// quoted non-UTF-8 name) ends what the model reads: it adds the
/// unmodeled-subcommand boundary and asserts nothing about the open
/// transaction or the lines after it. Returns false, leaving the whole input
/// to that boundary, only for input or options the model cannot read at all
/// (`-z`, dynamic input).
fn update_ref_stdin(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Open,
        Started,
        Prepared,
        Closed,
    }
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-m"],
            known_flags: &["--stdin", "--no-deref", "--create-reflog"],
            allow_abbreviation: true,
        },
    );
    let Some(input) = s.ctx.stdin_literal() else {
        return false;
    };
    if !git_controls_known(&parsed) || !parsed.operands.is_empty() {
        return false;
    }
    // Only a full-length run of zeros, or an empty value, is the null object
    // ID; a shorter run is an object name git resolves (`refs/heads/0`).
    let null_oid = |value: &str| {
        value.is_empty() || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte == b'0')
    };
    let commit = |builder: &mut PlanBuilder, queued: &mut Vec<(&str, String, bool)>| {
        for (verb, name, delete) in queued.drain(..) {
            if verb == "verify" {
                s.repo_effect(builder, "git.read", Attrs::new());
                continue;
            }
            let mut a = attrs(&[("delete", delete)]);
            a.insert("ref".into(), AttrValue::String(name.clone()));
            s.repo_effect(builder, "git.ref_update", a);
            if delete {
                let mut request = request_attrs(&[("delete", true)]);
                request.insert("ref".into(), AttrValue::String(name.clone()));
                request.insert("target_complete".into(), AttrValue::Bool(true));
                request.insert("scope".into(), AttrValue::String("selected".into()));
                request.insert("broad".into(), AttrValue::Bool(false));
                s.request_effect(builder, "git.ref_delete_request", request);
                if name == STASH_REF {
                    stash_destroyed(builder, s);
                }
            }
        }
    };
    let mut state = State::Open;
    let mut queued: Vec<(&str, String, bool)> = Vec::new();
    let mut unread = None;
    let mut died = false;
    for (number, line) in input.lines().enumerate() {
        let (verb, arguments) = match line.split_once(' ') {
            Some((verb, rest)) => match update_ref_arguments(rest) {
                Some(Ok(arguments)) => (verb, arguments),
                Some(Err(())) => {
                    died = true;
                    break;
                }
                None => {
                    unread = Some(number + 1);
                    break;
                }
            },
            None => (line, Vec::new()),
        };
        let next = match verb {
            // `option` takes only `no-deref`, and only where a ref command
            // may appear.
            "option" => (line == "option no-deref"
                && matches!(state, State::Open | State::Started))
            .then_some(state),
            "start" | "prepare" | "commit" | "abort" if !arguments.is_empty() => None,
            "start" => matches!(state, State::Open | State::Closed).then_some(State::Started),
            "prepare" => matches!(state, State::Open | State::Started).then_some(State::Prepared),
            "commit" | "abort" if state == State::Closed => None,
            "commit" => {
                commit(builder, &mut queued);
                Some(State::Closed)
            }
            "abort" => {
                queued.clear();
                Some(State::Closed)
            }
            "update" | "create" | "delete" | "verify"
                if matches!(state, State::Open | State::Started) =>
            {
                let arity = match verb {
                    "update" => 2..=3,
                    "create" => 2..=2,
                    _ => 1..=2,
                };
                let (name, values) = match arguments.split_first() {
                    Some((name, values)) if arity.contains(&arguments.len()) => (name, values),
                    _ => {
                        died = true;
                        break;
                    }
                };
                // git refuses a delete whose old value or a create whose new
                // value is the null object ID, and a ref named twice in one
                // transaction. An update to the null ID deletes the ref,
                // unless its old value is null too, which only asserts the
                // ref is absent.
                let delete = match verb {
                    "delete" => values
                        .first()
                        .is_none_or(|old| !null_oid(old))
                        .then_some(true),
                    "create" => (!null_oid(&values[0])).then_some(false),
                    "update" => {
                        Some(null_oid(&values[0]) && values.get(1).is_none_or(|old| !null_oid(old)))
                    }
                    _ => Some(false),
                };
                match delete {
                    Some(delete) if queued.iter().all(|(_, queued, _)| queued != name) => {
                        queued.push((verb, name.clone(), delete));
                        Some(state)
                    }
                    _ => None,
                }
            }
            "update" | "create" | "delete" | "verify" => None,
            _ => {
                unread = Some(number + 1);
                break;
            }
        };
        let Some(next) = next else {
            died = true;
            break;
        };
        state = next;
    }
    if let Some(line) = unread {
        unmodeled_subcommand_boundary(
            builder,
            s,
            &format!("git update-ref --stdin line {line} and the lines after it are not modeled"),
        );
    } else if !died && state == State::Open {
        commit(builder, &mut queued);
    }
    true
}

/// The space-separated arguments of an update-ref `--stdin` line. An
/// argument may be C-quoted, which git unquotes; `Err` is a line git dies on
/// (a bad quote, or a character after the closing quote), and `None` a
/// quoted name that is not UTF-8.
fn update_ref_arguments(mut rest: &str) -> Option<Result<Vec<String>, ()>> {
    let mut arguments = Vec::new();
    loop {
        let (argument, after) = if let Some(quoted) = rest.strip_prefix('"') {
            let mut argument = Vec::new();
            let mut chars = quoted.char_indices();
            let end = loop {
                let Some((index, c)) = chars.next() else {
                    return Some(Err(()));
                };
                match c {
                    '"' => break index + 1,
                    '\\' => argument.push(match chars.next().map(|(_, c)| c) {
                        Some('a') => 0x07,
                        Some('b') => 0x08,
                        Some('f') => 0x0c,
                        Some('n') => b'\n',
                        Some('r') => b'\r',
                        Some('t') => b'\t',
                        Some('v') => 0x0b,
                        Some(c @ ('\\' | '"')) => c as u8,
                        Some(first @ '0'..='3') => {
                            let mut code = first as u8 - b'0';
                            for _ in 0..2 {
                                let Some(digit) = chars.next().and_then(|(_, c)| c.to_digit(8))
                                else {
                                    return Some(Err(()));
                                };
                                code = code * 8 + digit as u8;
                            }
                            code
                        }
                        _ => return Some(Err(())),
                    }),
                    c => argument.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                }
            };
            (String::from_utf8(argument).ok()?, &quoted[end..])
        } else {
            let (argument, after) = rest.split_at(rest.find(' ').unwrap_or(rest.len()));
            (argument.to_string(), after)
        };
        arguments.push(argument);
        match after.strip_prefix(' ') {
            Some(next) => rest = next,
            None if after.is_empty() => return Some(Ok(arguments)),
            None => return Some(Err(())),
        }
    }
}

fn unmodeled_subcommand_boundary(builder: &mut PlanBuilder, s: &SubCtx, detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNMODELED_SUBCOMMAND,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: vec![s.model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
    for domain in ["environment", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
    }
}

/// Subcommands that are only sometimes reads: bare/list forms.
fn is_read_form(sub: &str, s: &SubCtx) -> bool {
    match sub {
        "branch" | "tag" => {
            !s.scanned(&["-d", "-D", "--delete", "-m", "-M", "-c", "-C", "-f"])
                .has(&["-d", "-D", "--delete", "-m", "-M", "-c", "-C", "-f"])
                && s.operands(false).is_empty()
        }
        "remote" => {
            let first = s
                .operands(false)
                .first()
                .and_then(|(_, w)| w.as_literal().map(str::to_string));
            matches!(first.as_deref(), None | Some("show") | Some("get-url"))
        }
        "stash" => matches!(
            s.operands(false).first().and_then(|(_, w)| w.as_literal()),
            Some("list") | Some("show")
        ),
        // git-reflog(1) takes its action only as the word right after
        // `reflog`, and runs `reflog show` for any other word there, an
        // option included: `reflog --all expire` reads. `show` and `list`
        // read; every other action, including the `drop` and `write` later
        // releases add, keeps the recovery evidence below.
        "reflog" => !matches!(
            s.rest.first().and_then(Word::as_literal),
            Some("expire" | "delete" | "exists" | "drop" | "write")
        ),
        "config" => s
            .scanned(&["--get", "--list", "-l", "--get-all", "--get-regexp"])
            .has(&["--get", "--list", "-l", "--get-all", "--get-regexp"]),
        "worktree" => matches!(
            s.operands(false).first().and_then(|(_, w)| w.as_literal()),
            Some("list") | None
        ),
        "checkout" | "restore" | "switch" | "clean" | "gc" => false,
        _ => true, // status, log, diff, ... are always reads
    }
}

/// Output formats that replace the patch: under them git prints a summary
/// instead of the file content a patch would disclose.
const SUMMARY_FORMATS: &[&str] = &[
    "-s",
    "--no-patch",
    "--raw",
    "--stat",
    "--numstat",
    "--shortstat",
    "--dirstat",
    "--summary",
    "--compact-summary",
    "--name-only",
    "--name-status",
];

/// A summary output format before `--`: the command prints names or counts,
/// not file lines.
///
/// A patch option (`-p`, `-u`, `-U<n>`, `--patch`, ...) prints the patch
/// beside `--stat`, `--raw` and the other summaries, and even after
/// `-s`/`--no-patch` when it comes later; only `--name-only` and
/// `--name-status` keep it off whatever the order, so any patch option
/// without one of those counts as printing file lines.
fn summarized(rest: &[Word]) -> bool {
    let options = rest
        .iter()
        .take_while(|word| word.as_literal() != Some("--"))
        .filter_map(Word::as_literal)
        .map(|text| text.split('=').next().unwrap_or(text))
        .collect::<Vec<_>>();
    let patch = options.iter().any(|option| {
        matches!(
            *option,
            "-p" | "-u" | "--patch" | "--patch-with-stat" | "--patch-with-raw"
        ) || option.starts_with("-U")
            || option.starts_with("--unified")
    });
    let names = options
        .iter()
        .any(|option| matches!(*option, "--name-only" | "--name-status"));
    options
        .iter()
        .any(|option| SUMMARY_FORMATS.contains(option))
        && (!patch || names)
}

/// Git also compares two filesystem paths without `--no-index` when a diff
/// names exactly two paths and either lies outside the work tree
/// (builtin/diff.c `path_inside_repo`). Only a work tree and operands that
/// resolve to concrete paths settle which side they are on.
fn implicit_no_index(s: &SubCtx) -> bool {
    let operands = s.operands(false);
    let Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: worktree },
    }) = worktree_resource(&s.repo)
    else {
        return false;
    };
    !s.rest.iter().any(|word| word.as_literal() == Some("--"))
        && operands.len() == 2
        && operands.iter().any(|(_, path)| {
            path.as_literal().is_some()
                && matches!(
                    resolve_fs_word(path, s.cwd.as_deref()),
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path != *worktree
                        && !path.starts_with(&format!("{}/", worktree.trim_end_matches('/')))
                )
        })
}

/// The argv-only reading of [`implicit_no_index`] for causal bindings: two
/// literal operands, one absolute or climbing out with `..`. It admits every
/// implicit no-index diff; where git reads a pathspec instead, the model emits
/// no filesystem read for the binding to carry.
fn may_be_implicit_no_index(rest: &[Word]) -> bool {
    let operands = rest
        .iter()
        .filter(|word| !word.as_literal().is_some_and(|text| text.starts_with('-')))
        .collect::<Vec<_>>();
    !rest.iter().any(|word| word.as_literal() == Some("--"))
        && operands.len() == 2
        && operands.iter().any(|word| {
            word.as_literal().is_some_and(|text| {
                text.starts_with('/') || text == ".." || text.starts_with("../")
            })
        })
}

/// `--no-index` before `--`: diff compares two filesystem paths.
fn diff_no_index(rest: &[Word]) -> bool {
    rest.iter()
        .take_while(|word| word.as_literal() != Some("--"))
        .any(|word| word.as_literal() == Some("--no-index"))
}

/// The path operands whose file content a read form prints, and whether that
/// content comes from recorded history rather than the working tree.
///
/// `git diff [<commit>...] [--] [<path>...]` and `git log [<options>] [--]
/// [<path>...]` take pathspecs after the `--` separator git documents for
/// telling a path from a revision, so only those operands are certainly
/// paths. A plain `git log` prints commit metadata and its pathspec only
/// selects commits; the patch modes print the file. `git blame [<rev>] [--]
/// <file>` requires one file operand, so a lone operand is that file.
fn disclosed_paths<'a>(sub: &str, s: &'a SubCtx<'a>) -> Vec<(u32, &'a Word, bool)> {
    if summarized(s.rest) {
        return Vec::new();
    }
    match sub {
        "diff" => {
            let paths = s.operands(true);
            // Named commits and the staged tree are compared as recorded;
            // comparing neither compares the working tree.
            let historical = s.operands(false).len() > paths.len()
                || s.scanned(&["--cached", "--staged"])
                    .has(&["--cached", "--staged"]);
            paths
                .into_iter()
                .map(|(index, path)| (index, path, historical))
                .collect()
        }
        "log" | "whatchanged"
            if s.scanned(&["-p", "-u", "--patch"])
                .has(&["-p", "-u", "--patch"]) =>
        {
            s.operands(true)
                .into_iter()
                .map(|(index, path)| (index, path, true))
                .collect()
        }
        "blame" => {
            let separated = s.operands(true);
            let operands = s.operands(false);
            let file = if !separated.is_empty() {
                separated
            } else if operands.len() == 1 {
                operands
            } else {
                Vec::new()
            };
            file.into_iter()
                .map(|(index, path)| (index, path, true))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// git-filter-branch(1) options, each taking the next word as its value.
const FILTER_BRANCH_VALUE_FLAGS: &[&str] = &[
    "-d",
    "--setup",
    "--subdirectory-filter",
    "--env-filter",
    "--tree-filter",
    "--index-filter",
    "--parent-filter",
    "--msg-filter",
    "--commit-filter",
    "--tag-name-filter",
    "--original",
    "--state-branch",
];

/// git-filter-branch evaluates these values as shell code.
const FILTER_BRANCH_CODE_FLAGS: &[&str] = &[
    "--setup",
    "--env-filter",
    "--tree-filter",
    "--index-filter",
    "--parent-filter",
    "--msg-filter",
    "--commit-filter",
    "--tag-name-filter",
];

/// git-filter-repo(1) options that take a value, attached or detached.
/// `--refs` takes one or more; the scan binds the first.
const FILTER_REPO_VALUE_FLAGS: &[&str] = &[
    "--path",
    "--path-glob",
    "--path-regex",
    "--path-rename",
    "--paths-from-file",
    "--replace-text",
    "--replace-message",
    "--mailmap",
    "--strip-blobs-bigger-than",
    "--strip-blobs-with-ids",
    "--refs",
];

/// git-filter-repo reads each of these values as a file.
const FILTER_REPO_FILE_FLAGS: &[&str] = &[
    "--paths-from-file",
    "--replace-text",
    "--replace-message",
    "--mailmap",
    "--strip-blobs-with-ids",
];

/// Each `--exec` command runs after replaying a commit, from the top of the
/// working tree. Git's run-command execs a command without shell syntax
/// directly and hands any other to its compiled-in `/bin/sh -c`.
fn rebase_exec_commands(builder: &mut PlanBuilder, s: &SubCtx, parsed: &Scanned<'_>) {
    for flag in &parsed.flags {
        if !matches!(flag.name, "-x" | "--exec") {
            continue;
        }
        let (Some(index), Some(source)) = (
            flag.value_index,
            flag.value.as_ref().and_then(Word::as_literal),
        ) else {
            opaque_source(
                builder,
                s.model_node,
                "git rebase --exec command is dynamic",
            );
            continue;
        };
        let invokes_shell = source.contains([
            '|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', ' ', '\t', '\n', '*',
            '?', '[', '#', '~', '=', '%',
        ]);
        let argv = if invokes_shell {
            vec![
                Word::literal("/bin/sh"),
                Word::literal("-c"),
                Word::literal(source),
            ]
        } else {
            vec![Word::literal(source)]
        };
        let index = s.sub_index + index;
        let command_node = arg_node(builder, s.ctx, index);
        let provenance = vec![vec![s.model_node, command_node]; argv.len()];
        s.ctx.nest.nest(
            builder,
            crate::nest::Transition::exec(
                argv.iter().map(crate::nest::word_resource).collect(),
                argv,
            )
            .cwd(
                ResourceExpr::Parameter {
                    name: "git_toplevel".into(),
                },
                None,
            )
            .runtime_cwd(None)
            .argv_provenance(Some(&provenance)),
            &[s.model_node, command_node],
            s.ctx.depth,
        );
    }
}

/// A filter-branch filter runs as shell code in a scratch checkout, whose
/// effects the rewrite model does not plan.
fn filter_code_boundary(builder: &mut PlanBuilder, s: &SubCtx, index: u32, flag: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNMODELED_INLINE_CODE,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: vec![s.model_node],
        limit: None,
        detail: Some(format!(
            "git filter-branch {flag} at argument {index} runs shell code"
        )),
    });
}

/// Scan supported options together, preserving clusters, order and `--`.
fn git_options<'a>(s: &'a SubCtx, spec: &FlagSpec<'a>) -> Scanned<'a> {
    let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
    let mut parsed = scan(argv, spec);
    for flag in &parsed.flags {
        let word = &argv[flag.index as usize];
        if word.as_literal().is_none()
            || (spec.value_flags.contains(&flag.name) && flag.value.is_none())
            || (spec.known_flags.contains(&flag.name)
                && word
                    .as_literal()
                    .is_some_and(|text| text.starts_with("--") && text.contains('='))
                && !matches!(flag.name, "--force-with-lease" | "--signed")
                // git-rebase(1) names the two modes; any other exits first.
                && !word.as_literal().is_some_and(|text| {
                    flag.name == "--rebase-merges"
                        && text.split_once('=').is_some_and(|(_, mode)| {
                            matches!(mode, "rebase-cousins" | "no-rebase-cousins")
                        })
                }))
        {
            parsed.unknown_flags.push((flag.index, word.render_raw()));
        }
    }
    for (index, word) in &parsed.operands {
        if word.as_literal().is_none() && parsed.dashdash.is_none_or(|dd| *index < dd) {
            parsed.unknown_flags.push((*index, word.render_raw()));
        }
    }
    parsed
}

fn git_controls_known(parsed: &Scanned<'_>) -> bool {
    git_options_known(parsed) && git_option_values_known(parsed)
}

/// Every option is a supported spelling; a dynamic operand is still an operand.
fn git_options_known(parsed: &Scanned<'_>) -> bool {
    !parsed.unknown_flags.iter().any(|(index, _)| {
        !parsed
            .operands
            .iter()
            .any(|(operand_index, _)| operand_index == index)
    })
}

fn git_option_values_known(parsed: &Scanned<'_>) -> bool {
    parsed.flags.iter().all(|flag| {
        flag.value
            .as_ref()
            .is_none_or(|value| value.as_literal().is_some())
    })
}

fn git_operands_known(parsed: &Scanned<'_>) -> bool {
    parsed
        .operands
        .iter()
        .all(|(_, word)| word.as_literal().is_some())
}

fn git_operands_are_not_options(s: &SubCtx<'_>, operands: &[(u32, &Word)]) -> bool {
    let dashdash = s
        .rest
        .iter()
        .position(|word| word.as_literal() == Some("--"))
        .map(|index| s.rest_offset - 1 + index as u32);
    operands.iter().all(|(index, word)| {
        dashdash.is_some_and(|separator| *index > separator)
            || !word
                .as_literal()
                .is_some_and(|value| value.starts_with('-'))
    })
}

/// Git stops before running the subcommand on an empty `--git-dir` ("not a
/// git repository") or `--work-tree` ("the empty string is not a valid
/// path"), in either spelling; `-C ''` stays in the cwd.
fn empty_repository_global(s: &SubCtx<'_>) -> bool {
    [&s.globals.git_dir, &s.globals.work_tree]
        .into_iter()
        .flatten()
        .any(|global| global.word.as_literal() == Some(""))
}

/// Every option value prune and reflog expire take is an expiry date, and
/// git refuses an empty one, wherever it appears, before it expires
/// anything. gc reads only its last date, so it does not use this.
fn empty_option_value(parsed: &Scanned<'_>) -> bool {
    parsed
        .flags
        .iter()
        .any(|flag| flag.value.as_ref().and_then(Word::as_literal) == Some(""))
}

/// Last occurrence wins, over a scan that already separated options from
/// pathspecs, so a `--force` after `--` stays an operand.
fn parsed_effective_flag(parsed: &Scanned<'_>, positive: &[&str], negative: &[&str]) -> bool {
    parsed
        .flags
        .iter()
        .rev()
        .find_map(|flag| {
            if positive.contains(&flag.name) {
                Some(true)
            } else if negative.contains(&flag.name) {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(false)
}

fn git_effective_flag(s: &SubCtx<'_>, positive: &[&str], negative: &[&str]) -> bool {
    let names: Vec<_> = positive.iter().chain(negative).copied().collect();
    s.scanned(&names)
        .flags
        .iter()
        .rev()
        .find_map(|flag| {
            if positive.contains(&flag.name) {
                Some(true)
            } else if negative.contains(&flag.name) {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(false)
}

fn git_checkout_options_known(s: &SubCtx<'_>, sub: &str) -> bool {
    let creation: &[&str] = if sub == "restore" {
        &[]
    } else {
        branch_creation_flags(sub)
    };
    let value_options = if sub == "restore" {
        ["--source", "--conflict", ""].as_slice()
    } else {
        creation
    };
    // git's parse-options generates a `--no-` form for every switch; it
    // restores the default, so it selects nothing the default does not.
    let known = if sub == "restore" {
        ["--staged", "--worktree", "-m", "--no-progress"].as_slice()
    } else {
        [
            "-f",
            "--force",
            "--discard-changes",
            "--merge",
            "--no-force",
            "--no-merge",
            "--no-patch",
            "--detach",
            "--no-detach",
            "--no-progress",
            "-q",
            "--quiet",
        ]
        .as_slice()
    };
    s.rest
        .iter()
        .take_while(|word| word.as_literal() != Some("--"))
        .filter_map(Word::as_literal)
        // A bare `-` is git's previous-ref operand, never an option.
        .filter(|word| word.starts_with('-') && *word != "-")
        .all(|word| {
            if let Some((option, _)) = word.split_once('=') {
                value_options.contains(&option)
            } else {
                known.contains(&word)
                    || creation.contains(&word)
                    || (sub == "switch" && word == "-m")
            }
        })
}

/// `:/` selects the top of the working tree. Unless the work tree is named,
/// git discovers that top upward from the start directory, which the plan
/// cannot see: a selection keeps the start directory and states the
/// discovered top as `selects_top` for the host to resolve.
fn top_discovered(s: &SubCtx<'_>) -> bool {
    s.globals.work_tree.is_none() && s.ctx.environment_value("GIT_WORK_TREE").is_none()
}

/// A complete restore or checkout selection that names the discovered top.
fn insert_selects_top(request: &mut Attrs, s: &SubCtx<'_>, paths: &[(u32, &Word)]) {
    if top_discovered(s)
        && paths
            .iter()
            .any(|(_, path)| is_worktree_root_pathspec(s, path))
    {
        request.insert("selects_top".into(), AttrValue::Bool(true));
    }
}

/// A `submodule foreach` command starts in its submodule's top with
/// `GIT_DIR=.git` and no work tree named, so git takes that start directory
/// as the top of the working tree (git(1) `GIT_DIR`). Pathspecs selecting
/// everything below it select that whole submodule tree, though the plan
/// cannot name its path.
fn foreach_whole_tree(builder: &PlanBuilder, s: &SubCtx<'_>, paths: &[(u32, &Word)]) -> bool {
    builder.git_foreach_binding().is_some()
        && s.ctx.cwd_resource.as_ref() == Some(&foreach_submodule())
        && s.globals.repo_dir.is_none()
        && s.globals.work_tree.is_none()
        && s.globals.git_dir.is_none()
        && matches!(
            s.ctx.environment_value("GIT_DIR"),
            Some(ResourceExpr::Literal { value }) if value == ".git"
        )
        && s.ctx.environment_value("GIT_WORK_TREE").is_none()
        && !paths.is_empty()
        && paths.iter().all(|(_, path)| {
            matches!(path.as_literal(), Some("." | "./"))
                || is_worktree_root_pathspec(s, path)
                || matches_everything(s, path) == Some(true)
        })
}

fn git_request_path(s: &SubCtx<'_>, path: &Word) -> Option<String> {
    let text = path.as_literal()?;
    if is_worktree_root_pathspec(s, path) {
        return match worktree_resource(&s.repo)? {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if crate::paths::is_absolute(path) => Some(path.clone()),
            _ => None,
        };
    }
    if text.is_empty() || text.starts_with(':') || text.contains(['*', '?', '[', '\\']) {
        return None;
    }
    match resolve_fs_word(path, s.cwd.as_deref()) {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if crate::paths::is_absolute(&path) => Some(path),
        _ => None,
    }
}

/// The path a checkout or restore pathspec discards. `find P … -exec git
/// checkout -- {} +` hands git P itself or entries below it, and a pathspec
/// naming P already discards everything below it, so P bounds what each
/// found path discards. P stands for the found paths only when it is a
/// relative path below the cwd, so that no found path can be the top of the
/// working tree: whether `find .` selects the root itself depends on its
/// predicates (`-type f` does not), which this bound cannot tell.
fn git_discard_selection_path(
    builder: &mut PlanBuilder,
    s: &SubCtx<'_>,
    path: &Word,
) -> Option<String> {
    if let [WordPart::Union(alternatives)] = path.parts.as_slice()
        && let [root, descendants] = alternatives.as_slice()
        && let [WordPart::Glob(pattern)] = descendants.parts.as_slice()
    {
        let below_cwd = root.as_literal().is_some_and(|text| {
            !text.starts_with('/')
                && text.split('/').all(|part| part != "..")
                && text.split('/').any(|part| !matches!(part, "" | "."))
        });
        if !below_cwd {
            return None;
        }
        let root = git_request_path(s, root)?;
        return (*pattern == format!("{}/**", crate::paths::escape_fs_glob_path(&root)))
            .then_some(root);
    }
    // find also hands the entries its tests select as one glob per shape,
    // below the directory before the glob's first wildcard. That directory
    // bounds them when it lies below the cwd, for the same reason.
    if let [WordPart::Glob(pattern)] = path.parts.as_slice() {
        let first = pattern.find(['*', '?', '[', '\\'])?;
        let bound = &pattern[..pattern[..first].rfind('/')?];
        let cwd = s.cwd.as_deref()?;
        let below_cwd = bound
            .strip_prefix(cwd.trim_end_matches('/'))
            .is_some_and(|rest| rest.len() > 1 && rest.starts_with('/'));
        return below_cwd.then(|| bound.to_owned());
    }
    match matches_everything(s, path) {
        Some(true) => return git_request_path(s, &Word::literal(".")),
        None => {
            // A pathspec mode the model cannot read may leave the pattern
            // matching everything, so the whole selection is planned.
            git_argument_boundary(builder, s, "git pathspec mode is not statically known");
            return git_request_path(s, &Word::literal("."));
        }
        Some(false) => {}
    }
    git_request_path(s, path)
}

/// Whether `path` matches every path below the cwd under the pathspec mode
/// git(1)'s `--literal-pathspecs`, `--noglob-pathspecs` and
/// `--glob-pathspecs`, or their environment variables, select; `None` when
/// that mode is not known. Literal and noglob modes read `*` as a file
/// name, and glob mode's `*` stops at `/`; only literal mode disables the
/// `:(glob)` magic.
fn matches_everything(s: &SubCtx<'_>, path: &Word) -> Option<bool> {
    if !matches_everything_pathspec(path) {
        return Some(false);
    }
    // git(1) sets the variable from each option as it reads it, so the last
    // option wins over the environment.
    let mode = |option: &str, negation: &str, variable: &str| -> Option<bool> {
        if let Some(last) = s
            .globals
            .pathspec_options
            .iter()
            .rev()
            .find(|given| **given == option || **given == negation)
        {
            return Some(*last == option);
        }
        match s.ctx.environment_value(variable) {
            None => Some(false),
            Some(ResourceExpr::Literal { value }) => git_bool(&value),
            Some(_) => None,
        }
    };
    let mut modes = vec![mode(
        "--literal-pathspecs",
        "--no-literal-pathspecs",
        "GIT_LITERAL_PATHSPECS",
    )];
    if !path
        .as_literal()
        .is_some_and(|text| text.starts_with(":(glob)"))
    {
        modes.push(mode("--noglob-pathspecs", "", "GIT_NOGLOB_PATHSPECS"));
        modes.push(mode("--glob-pathspecs", "", "GIT_GLOB_PATHSPECS"));
    }
    if modes.contains(&Some(true)) {
        Some(false)
    } else if modes.contains(&None) {
        None
    } else {
        Some(true)
    }
}

/// A pathspec pattern that matches every path below the cwd, as `.` does:
/// gitglossary(7) matches a default pathspec's `*` across `/`, and a
/// `:(glob)` pathspec's `**` matches any number of directories.
fn matches_everything_pathspec(path: &Word) -> bool {
    path.as_literal().is_some_and(|text| {
        !text.is_empty() && text.bytes().all(|byte| byte == b'*')
            || matches!(text, ":(glob)**" | ":(glob)**/*")
    })
}

fn unresolved_alias_boundary(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRESOLVED_ALIAS,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
    for domain in ["environment", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
    }
}

/// git's parse-options answers a help request with the usage message and
/// exits before the command runs. It reads `-h` and `--help` only where it is
/// still reading options, matches them exactly rather than by the abbreviation
/// it allows a command's own options, and never sees one it has already taken
/// as an option value.
fn git_help_requested(parsed: &Scanned<'_>) -> bool {
    parsed
        .unknown_flags
        .iter()
        .any(|(_, flag)| flag == "-h" || flag == "--help")
}

fn git_argument_boundary(builder: &mut PlanBuilder, s: &SubCtx, detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: Some(s.repo.clone()),
        callee: None,
        domains: vec![Domain::new("git")],
        provenance: vec![s.model_node],
        limit: None,
        detail: Some(detail.into()),
    });
}

fn reset(builder: &mut PlanBuilder, s: &SubCtx) {
    if empty_repository_global(s) {
        return;
    }
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--pathspec-from-file"],
            known_flags: &[
                "--hard",
                "--merge",
                "--keep",
                "--soft",
                "--mixed",
                "-N",
                "--intent-to-add",
                "-p",
                "--patch",
                "-q",
                "--quiet",
                "--no-quiet",
                "--refresh",
                "--no-refresh",
                "--pathspec-file-nul",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) {
        return;
    }
    let unknown_control = parsed.unknown_flags.iter().any(|(index, _)| {
        !parsed
            .operands
            .iter()
            .any(|(operand_index, _)| operand_index == index)
    });
    if unknown_control {
        git_argument_boundary(builder, s, "git reset options are not fully known");
        return;
    }
    if !parsed.unknown_flags.is_empty() {
        git_argument_boundary(builder, s, "git reset target is not fully known");
    }
    let modes: Vec<_> = parsed
        .flags
        .iter()
        .filter(|flag| ["--hard", "--merge", "--keep", "--soft", "--mixed"].contains(&flag.name))
        .map(|flag| flag.name)
        .collect();
    if modes.iter().any(|mode| Some(mode) != modes.first()) {
        git_argument_boundary(builder, s, "git reset has incompatible modes");
        return;
    }
    let mode = modes.first().copied().unwrap_or("--mixed");
    let controls_known = parsed.flags.iter().all(|flag| {
        flag.value
            .as_ref()
            .is_none_or(|value| value.as_literal().is_some())
    });
    let operands_known = parsed
        .operands
        .iter()
        .all(|(_, word)| word.as_literal().is_some());
    if ["--hard", "--merge", "--keep"].contains(&mode) {
        let paths = parsed
            .operands
            .iter()
            .any(|(index, _)| parsed.dashdash.is_some_and(|dd| *index > dd))
            || parsed.operands.len() > 1;
        if paths || parsed.has(&["-p", "--patch", "--pathspec-from-file"]) {
            git_argument_boundary(
                builder,
                s,
                "git reset discard mode cannot select paths or patches",
            );
            return;
        }
        let mut attributes: Attrs = [("hard", mode == "--hard"), ("dry_run", false)]
            .into_iter()
            .map(|(key, value)| (key.into(), AttrValue::Bool(value)))
            .collect();
        attributes.insert("discard_mode".into(), AttrValue::String("reset".into()));
        attributes.insert("reset_mode".into(), AttrValue::String(mode[2..].into()));
        // Paths and patches already returned above, so the lone remaining
        // operand is a revision. Which commit it names cannot change that the
        // whole worktree is discarded, so a dynamic revision leaves the
        // effect exact and only the request's `target` unknown.
        s.repo_effect(builder, "git.worktree_discard", attributes);
        if controls_known {
            let mut request = request_attrs(&[("hard", mode == "--hard")]);
            request.insert("dry_run".into(), AttrValue::Bool(false));
            request.insert("discard_mode".into(), AttrValue::String("reset".into()));
            request.insert("reset_mode".into(), AttrValue::String(mode[2..].into()));
            request.insert("scope".into(), AttrValue::String("targeted".into()));
            request.insert("broad".into(), AttrValue::Bool(false));
            request.insert("target_complete".into(), AttrValue::Bool(operands_known));
            if operands_known
                && let Some((_, target)) = parsed.operands.first()
                && let Some(target) = target.as_literal()
            {
                request.insert("target".into(), AttrValue::String(target.into()));
            }
            s.request_effect(builder, "git.reset_request", request);
        }
    } else if parsed
        .operands
        .iter()
        .any(|(index, _)| parsed.dashdash.is_some_and(|dd| *index > dd))
        || parsed.operands.len() > 1
        || parsed.has(&["-p", "--patch", "--pathspec-from-file"])
    {
        if operands_known {
            s.repo_effect(builder, "git.index_write", Attrs::new());
        }
        if controls_known
            && operands_known
            && !parsed.has(&["-p", "--patch", "--pathspec-from-file"])
        {
            let mut request = request_attrs(&[
                ("hard", false),
                ("dry_run", false),
                ("selection_complete", true),
                ("target_complete", true),
            ]);
            request.insert("discard_mode".into(), AttrValue::String("reset".into()));
            request.insert("reset_mode".into(), AttrValue::String(mode[2..].into()));
            request.insert("scope".into(), AttrValue::String("selected".into()));
            request.insert("broad".into(), AttrValue::Bool(false));
            s.request_effect(builder, "git.reset_request", request);
        }
    } else {
        if operands_known {
            s.repo_effect(builder, "git.ref_update", Attrs::new());
        }
        if controls_known {
            let mut request = request_attrs(&[
                ("hard", false),
                ("dry_run", false),
                ("target_complete", operands_known),
            ]);
            request.insert("discard_mode".into(), AttrValue::String("reset".into()));
            request.insert("reset_mode".into(), AttrValue::String(mode[2..].into()));
            request.insert("scope".into(), AttrValue::String("targeted".into()));
            request.insert("broad".into(), AttrValue::Bool(false));
            if operands_known
                && let Some((_, target)) = parsed.operands.first()
                && let Some(target) = target.as_literal()
            {
                request.insert("target".into(), AttrValue::String(target.into()));
            }
            s.request_effect(builder, "git.reset_request", request);
        }
    }
}

fn clean(builder: &mut PlanBuilder, s: &SubCtx) {
    if empty_repository_global(s) {
        return;
    }
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-e", "--exclude"],
            known_flags: &[
                "-f",
                "--force",
                "--no-force",
                "-n",
                "--dry-run",
                "--no-dry-run",
                "-i",
                "--interactive",
                "--no-interactive",
                "-d",
                "-x",
                "-X",
                "-q",
                "--quiet",
                "--no-quiet",
                "-h",
                "--help",
            ],
            allow_abbreviation: true,
        },
    );
    if !parsed.unknown_flags.is_empty() {
        git_argument_boundary(builder, s, "git clean options are not fully known");
        return;
    }
    if parsed.has(&["-h", "--help"]) {
        return;
    }
    if parsed.has(&["-x"]) && parsed.has(&["-X"]) {
        git_argument_boundary(builder, s, "git clean has incompatible ignored-file modes");
        return;
    }
    let mut force = false;
    let mut dry_run = false;
    let mut interactive = false;
    for flag in &parsed.flags {
        match flag.name {
            "-f" | "--force" => force = true,
            "--no-force" => force = false,
            "-n" | "--dry-run" => dry_run = true,
            "--no-dry-run" => dry_run = false,
            "-i" | "--interactive" => interactive = true,
            "--no-interactive" => interactive = false,
            _ => {}
        }
    }
    if interactive && !dry_run {
        git_argument_boundary(
            builder,
            s,
            "interactive git clean selection depends on user input",
        );
        return;
    }
    if dry_run {
        s.repo_effect(builder, "git.read", Attrs::new());
        return;
    }
    // git-clean(1) refuses without -f unless clean.requireForce is false.
    // A setting the model cannot read may be false, so the clean is planned
    // as the forced one it may be.
    if !force {
        let configured = config_values(s.globals, "clean.requireForce");
        if configured
            .values
            .iter()
            .all(|value| value.and_then(git_bool) == Some(true))
        {
            s.repo_effect(builder, "git.read", Attrs::new());
            return;
        }
        if configured.certain().map(|value| value.and_then(git_bool)) != Some(Some(false)) {
            git_argument_boundary(
                builder,
                s,
                "git clean requireForce configuration is not statically resolvable",
            );
        }
        force = true;
    }
    let mut attributes: Attrs = [
        ("force", force),
        ("dry_run", dry_run),
        (
            "root_uses_invocation_cwd",
            root_uses_invocation_cwd(s.globals, s.ctx),
        ),
        (
            "discovers_from_worktree",
            discovers_from_worktree(s.globals, s.ctx),
        ),
        ("untracked", true),
        ("directories", parsed.has(&["-d"])),
        ("ignored", parsed.has(&["-x", "-X"])),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), AttrValue::Bool(value)))
    .collect();
    attributes.insert("discard_mode".into(), AttrValue::String("clean".into()));
    // Cleaning without operands selects cwd, which need not be the repository root.
    let default_path = Word::literal(".");
    let paths = if parsed.operands.is_empty() {
        vec![(s.sub_index, &default_path)]
    } else {
        parsed
            .operands
            .iter()
            .map(|(index, word)| (s.rest_offset - 1 + index, *word))
            .collect()
    };
    // `-e <pattern>` removes files from the set inside the pathspec; it never
    // selects a path the pathspec does not already cover, so it is an
    // attribute of the discard, not an unknown selection.
    let excluded = parsed.has(&["-e", "--exclude"]);
    attributes.insert("excluded".into(), AttrValue::Bool(excluded));
    let controls_known = parsed.flags.iter().all(|flag| {
        flag.value
            .as_ref()
            .is_none_or(|value| value.as_literal().is_some())
    });
    let top_discovered = top_discovered(s);
    let mut selects_top = false;
    // With the whole tree selected, a positive top-relative pathspec
    // (`:/src`) only repeats part of it. Exclude magic still narrows it.
    let top_selected = paths
        .iter()
        .any(|(_, path)| is_worktree_root_pathspec(s, path));
    let whole_tree = foreach_whole_tree(builder, s, &paths);
    let mut selection_paths = Vec::new();
    let mut selection_complete = true;
    for (index, path) in paths {
        let mut attributes = attributes.clone();
        if top_discovered && is_worktree_root_pathspec(s, path) {
            attributes.insert("selects_top".into(), AttrValue::Bool(true));
            selects_top = true;
        }
        if let Some(path) = git_request_path(s, path) {
            attributes.insert("selection_path".into(), AttrValue::String(path.clone()));
            selection_paths.push(path);
        } else if !(whole_tree || top_selected && positive_top_relative_pathspec(path)) {
            selection_complete = false;
            git_argument_boundary(
                builder,
                s,
                "git clean pathspec selection is not a known plain path",
            );
        }
        s.git_path_effect(builder, index, path, "git.worktree_discard", attributes);
    }
    if controls_known && selection_complete {
        let mut request = request_attrs(&[
            ("force", true),
            ("dry_run", false),
            ("untracked", true),
            ("selection_complete", true),
            (
                "root_uses_invocation_cwd",
                root_uses_invocation_cwd(s.globals, s.ctx),
            ),
            (
                "discovers_from_worktree",
                discovers_from_worktree(s.globals, s.ctx),
            ),
        ]);
        request.insert("discard_mode".into(), AttrValue::String("clean".into()));
        request.insert("excluded".into(), AttrValue::Bool(excluded));
        insert_selection(&mut request, whole_tree, &selection_paths);
        if selects_top {
            request.insert("selects_top".into(), AttrValue::Bool(true));
        }
        s.request_effect(builder, "git.clean_request", request);
    }
}

/// git-stash(1) keeps the newest stash in `refs/stash` and the older ones
/// in that ref's reflog.
const STASH_REF: &str = "refs/stash";

/// Deleting `refs/stash` deletes its reflog with it, which is every stash:
/// `git stash clear` is implemented as exactly that deletion.
fn stash_destroyed(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.recovery_destroy", attrs(&[("stash", true)]));
    let mut request = request_attrs(&[("stash", true), ("target_complete", true)]);
    request.insert("scope".into(), AttrValue::String("whole".into()));
    request.insert("broad".into(), AttrValue::Bool(true));
    s.request_effect(builder, "git.recovery_destroy_request", request);
}

/// Record the setting a `git config` write leaves for later invocations in
/// the subject to read. The legacy grammar sets with `<name> <value>
/// [<value-pattern>]` (also under `--add` and `--replace-all`) and removes
/// with `--unset` or `--unset-all`; git 2.46 adds the `set` and `unset`
/// actions. A single name alone reads. A form the model does not read here
/// (a dynamic key or action, an unrecognized option, a section rename or
/// removal, an editor) is recorded under an unknown key: it may set
/// anything. A literal key keeps its name when only its value, or the file
/// `--file` names, is not known.
fn record_config_write(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--type", "--comment", "--value", "-f", "--file"],
            known_flags: &[
                "--local",
                "--global",
                "--system",
                "--worktree",
                "--add",
                "--replace-all",
                "--unset",
                "--unset-all",
                "--all",
                "--fixed-value",
                "--bool",
                "--int",
                "--bool-or-int",
                "--path",
                "--expiry-date",
                "--no-type",
            ],
            allow_abbreviation: true,
        },
    );
    use crate::builder::GitConfigScope;

    // git refuses more than one of these; the last spelled is the file
    // the model takes.
    let location = parsed.flags.iter().rev().find_map(|flag| match flag.name {
        "--system" => Some(GitConfigScope::System),
        "--global" => Some(GitConfigScope::Global),
        "--local" => Some(GitConfigScope::Local),
        "--worktree" => Some(GitConfigScope::Worktree),
        _ => None,
    });
    let scope = location.unwrap_or(GitConfigScope::Local);
    // The write is tied to the repository its cwd discovers only when no
    // selector redirects it (see `selects_by_discovery`) and no option the
    // model does not know, which may be `--file`, names another file. A
    // redirected write may land in any file some reader selects or includes,
    // such as the common dir GIT_COMMON_DIR names or the file GIT_CONFIG
    // names, so it is not tied to one repository.
    let redirected = !selects_by_discovery(builder, s.ctx, s.globals)
        || !parsed.unknown_flags.is_empty()
        || parsed.has(&["-f", "--file"]);
    let repository = (matches!(scope, GitConfigScope::Local | GitConfigScope::Worktree)
        && !redirected)
        .then(|| s.repo.clone());
    let operands: Vec<Option<&str>> = parsed
        .operands
        .iter()
        .map(|(_, word)| word.as_literal())
        .collect();
    let (unset, operands) = match operands.split_first() {
        Some((Some("set"), rest)) => (false, rest),
        Some((Some("unset"), rest)) => (true, rest),
        _ => (parsed.has(&["--unset", "--unset-all"]), operands.as_slice()),
    };
    let (key, value) = if !git_options_known(&parsed) {
        (None, None)
    } else {
        match operands {
            [key, ..] if unset => (key.map(str::to_string), None),
            [key, value, ..] => (key.map(str::to_string), value.map(str::to_string)),
            // `<name>` alone reads its value.
            [Some(_)] => return,
            [None] | [] => (None, None),
        }
    };
    builder.record_git_config_write(scope, repository, key, value);
}

fn remote(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.config_write", Attrs::new());
    record_remote_settings(builder, s);
    let operands = s.operands(false);
    let [(_, action), (_, name)] = operands.as_slice() else {
        return;
    };
    if !matches!(action.as_literal(), Some("remove" | "rm")) {
        return;
    }
    let Some(name) = name
        .as_literal()
        .filter(|name| !name.is_empty() && !name.starts_with('-'))
    else {
        return;
    };
    s.repo_effect(
        builder,
        "git.ref_update",
        Attrs::from([
            ("delete".into(), AttrValue::Bool(true)),
            ("remote".into(), AttrValue::String(name.into())),
        ]),
    );
    let mut request = request_attrs(&[("delete", true), ("selection_complete", false)]);
    request.insert("remote".into(), AttrValue::String(name.into()));
    request.insert("scope".into(), AttrValue::String("selected".into()));
    request.insert("broad".into(), AttrValue::Bool(false));
    s.request_effect(builder, "git.ref_delete_request", request);
}

/// Record the `remote.<name>.mirror=true` that `git remote add` writes for
/// `--mirror=push`, or for `--mirror` alone, which mirrors both ways. A
/// mirror mode the model cannot read may be push; a name it cannot read is
/// recorded under an unknown key. `git remote rename` moves the remote's
/// section, so a literal rename adds each earlier recorded setting of the
/// old remote under the new name.
fn record_remote_settings(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-t", "--track", "-m", "--master"],
            known_flags: &[
                "-f",
                "--fetch",
                "--no-fetch",
                "--tags",
                "--no-tags",
                "--mirror",
                "--no-mirror",
                "-v",
                "--verbose",
                "--progress",
                "--no-progress",
            ],
            allow_abbreviation: true,
        },
    );
    let [(_, action), (_, name), ..] = parsed.operands.as_slice() else {
        return;
    };
    if action.as_literal() == Some("rename")
        && git_options_known(&parsed)
        && let [_, _, (_, new_name)] = parsed.operands.as_slice()
        && let (Some(old), Some(new)) = (name.as_literal(), new_name.as_literal())
    {
        let renamed: Vec<_> = builder
            .git_config_writes()
            .filter_map(|write| {
                let (section, rest) = write.key.as_deref()?.split_once('.')?;
                let (subsection, variable) = rest.rsplit_once('.')?;
                (section.eq_ignore_ascii_case("remote") && subsection == old).then(|| {
                    (
                        write.scope,
                        write.repository.clone(),
                        format!("remote.{new}.{variable}"),
                        write.value.clone(),
                    )
                })
            })
            .collect();
        for (scope, repository, key, value) in renamed {
            builder.record_git_config_write(scope, repository, Some(key), value);
        }
        return;
    }
    if action.as_literal() != Some("add") {
        return;
    }
    let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
    let mode = parsed.flags.iter().rev().find_map(|flag| match flag.name {
        "--no-mirror" => Some(Some("none")),
        "--mirror" => Some(
            argv[flag.index as usize]
                .as_literal()
                .map(|text| text.split_once('=').map_or("push", |(_, mode)| mode)),
        ),
        _ => None,
    });
    // A word whose literal start spells `--mirror` may carry any mode.
    let dynamic_mirror = |index: u32| {
        let word = &argv[index as usize];
        let prefix = word.literal_prefix();
        word.as_literal().is_none()
            && prefix.len() >= 4
            && ("--mirror".starts_with(prefix) || prefix.starts_with("--mirror"))
    };
    if !parsed
        .unknown_flags
        .iter()
        .any(|(index, _)| dynamic_mirror(*index))
        && !matches!(mode, Some(None | Some("push")))
    {
        return;
    }
    let repository = selects_by_discovery(builder, s.ctx, s.globals).then(|| s.repo.clone());
    // A dynamic word may be an option that shifts which operand is the name.
    let operands_known = git_operands_known(&parsed)
        && parsed.unknown_flags.iter().all(|(index, _)| {
            dynamic_mirror(*index)
                || parsed
                    .flags
                    .iter()
                    .any(|flag| flag.index == *index && flag.name == "--mirror")
        });
    let key = name
        .as_literal()
        .filter(|_| operands_known)
        .map(|name| format!("remote.{name}.mirror"));
    builder.record_git_config_write(
        crate::builder::GitConfigScope::Local,
        repository,
        key,
        Some("true".into()),
    );
}

/// The options that create a branch and take its name as their value:
/// `-b`/`-B` for checkout, `-c`/`-C` for switch, `--orphan` for both.
fn branch_creation_flags(sub: &str) -> &'static [&'static str] {
    if sub == "switch" {
        &["-c", "-C", "--create", "--force-create", "--orphan"]
    } else {
        &["-b", "-B", "--orphan"]
    }
}

/// The refs a checkout or switch lands on.
struct CheckoutTargets {
    /// The ref the command ends on: the created branch, or the operand.
    target: Option<String>,
    /// The revision a branch creation branches from.
    start_point: Option<String>,
    /// A branch creation, whose operands are refs: without an explicit `--`
    /// no operand of such a form is a pathspec.
    creates_branch: bool,
    /// git reads no further operand; more is a form it rejects.
    bounded: bool,
}

/// Read the operands of a checkout or switch under git's grammar. A branch
/// creation takes the new name as its flag value, inline or as the next
/// word; git then reads at most one more operand, the start point the branch
/// is created from — a revision, never a pathspec. Without a branch creation
/// that single operand is the ref itself.
fn checkout_targets(s: &SubCtx<'_>, sub: &str, operands: &[(u32, &Word)]) -> CheckoutTargets {
    let created = s
        .rest
        .iter()
        .enumerate()
        .take_while(|(_, word)| word.as_literal() != Some("--"))
        .find_map(|(offset, word)| {
            let text = word.as_literal()?;
            let name = branch_creation_flags(sub).iter().find_map(|flag| {
                if text == *flag {
                    // The flag stands alone: the name is the next word.
                    return Some(None);
                }
                // `--orphan=<name>`, and a short flag also takes `-b<name>`.
                let value = text.strip_prefix(flag)?;
                value
                    .strip_prefix('=')
                    .or_else(|| (!flag.starts_with("--")).then_some(value))
                    .filter(|value| !value.is_empty())
                    .map(|value| Some(value.to_string()))
            })?;
            Some((s.rest_offset + offset as u32, name))
        });
    let Some((flag_index, inline_name)) = created else {
        return CheckoutTargets {
            target: operands
                .first()
                .and_then(|(_, word)| word.as_literal().map(str::to_string)),
            start_point: None,
            creates_branch: false,
            bounded: operands.len() <= 1,
        };
    };
    let name_index = inline_name.is_none().then_some(flag_index + 1);
    let named = |wanted: Option<u32>| {
        operands
            .iter()
            .find(|(index, _)| Some(*index) == wanted)
            .and_then(|(_, word)| word.as_literal().map(str::to_string))
    };
    let start_points: Vec<&(u32, &Word)> = operands
        .iter()
        .filter(|(index, _)| Some(*index) != name_index)
        .collect();
    CheckoutTargets {
        target: inline_name.or_else(|| named(name_index)),
        start_point: start_points
            .first()
            .and_then(|(_, word)| word.as_literal().map(str::to_string)),
        creates_branch: true,
        bounded: start_points.len() <= 1,
    }
}

/// A discard request's selection: the whole tree, or the selected paths.
fn insert_selection(request: &mut Attrs, whole_tree: bool, selection_paths: &[String]) {
    request.insert(
        "scope".into(),
        AttrValue::String(if whole_tree { "whole" } else { "selected" }.into()),
    );
    request.insert("broad".into(), AttrValue::Bool(whole_tree));
    if !whole_tree {
        request.insert("selections".into(), string_list(selection_paths));
    }
}

/// checkout/restore/switch: pathspec forms discard local changes; branch
/// switches write the worktree. `git checkout -f` with no target discards
/// the whole tree.
/// A forced checkout or switch replaces the whole worktree; the operands are
/// the refs it lands on, not a selection, so the request carries them as the
/// target and, for a branch creation, its start point.
fn whole_worktree_discard_request(
    builder: &mut PlanBuilder,
    sub: &str,
    s: &SubCtx,
    operands: &[(u32, &Word)],
    targets: &CheckoutTargets,
) {
    // A `--` introduces pathspecs, which scope the discard to those paths.
    // Only the pathspec branch above can certify that shape.
    if s.rest.iter().any(|word| word.as_literal() == Some("--"))
        || !targets.bounded
        || !operands.iter().all(|(_, w)| w.as_literal().is_some())
        || !git_operands_are_not_options(s, operands)
        || !git_checkout_options_known(s, sub)
    {
        return;
    }
    let mut request = request_attrs(&[
        ("force", true),
        ("selection_complete", true),
        (
            "root_uses_invocation_cwd",
            root_uses_invocation_cwd(s.globals, s.ctx),
        ),
        (
            "discovers_from_worktree",
            discovers_from_worktree(s.globals, s.ctx),
        ),
    ]);
    request.insert("discard_mode".into(), AttrValue::String(sub.into()));
    request.insert("scope".into(), AttrValue::String("whole".into()));
    request.insert("broad".into(), AttrValue::Bool(true));
    request.insert("target_complete".into(), AttrValue::Bool(true));
    if let Some(start_point) = targets.start_point.clone() {
        request.insert("start_point".into(), AttrValue::String(start_point));
    }
    if let Some(target) = targets.target.clone() {
        request.insert("target".into(), AttrValue::String(target));
    }
    s.request_effect(builder, "git.worktree_discard_request", request);
}

/// Every long option of `git checkout` and `git switch`, for resolving an
/// abbreviation the way git's parse-options does: against all of them.
const CHECKOUT_LONG_OPTIONS: &[&str] = &[
    "guess",
    "overlay",
    "quiet",
    "recurse-submodules",
    "progress",
    "merge",
    "conflict",
    "detach",
    "track",
    "force",
    "orphan",
    "overwrite-ignore",
    "ignore-other-worktrees",
    "ours",
    "theirs",
    "patch",
    "ignore-skip-worktree-bits",
    "pathspec-from-file",
    "pathspec-file-nul",
];
const SWITCH_LONG_OPTIONS: &[&str] = &[
    "create",
    "force-create",
    "guess",
    "discard-changes",
    "quiet",
    "recurse-submodules",
    "progress",
    "merge",
    "conflict",
    "detach",
    "track",
    "force",
    "orphan",
    "overwrite-ignore",
    "ignore-other-worktrees",
];

/// git's parse-options takes short options bundled into one word (`-qf`,
/// `-fb <branch>`) and a unique prefix of a long option (`--di`). The
/// checkout model reads options one exact word at a time, so this spells
/// them out: one word per short option and per attached branch name, and
/// each abbreviation its full name. Each
/// spelled word carries the index of the word it came from. A word that
/// cannot be spelled out exactly stays as written, and None means nothing
/// changed.
fn spelled_checkout_options(sub: &str, rest: &[Word]) -> Option<Vec<(usize, Word)>> {
    let (flags, creation, long_options, long_values): (&str, &str, _, &[&str]) = if sub == "switch"
    {
        (
            "qfdm",
            "cC",
            SWITCH_LONG_OPTIONS,
            &["create", "force-create", "orphan", "conflict"],
        )
    } else {
        (
            "qfldmp23",
            "bB",
            CHECKOUT_LONG_OPTIONS,
            &["orphan", "conflict", "pathspec-from-file"],
        )
    };
    let mut spelled = Vec::new();
    let mut changed = false;
    let mut takes_value = false;
    let mut options_end = false;
    for (index, word) in rest.iter().enumerate() {
        let text = word.as_literal();
        if options_end || std::mem::take(&mut takes_value) || text.is_none() {
            spelled.push((index, word.clone()));
            continue;
        }
        let text = text.unwrap();
        if text == "--" {
            options_end = true;
            spelled.push((index, word.clone()));
        } else if let Some(option) = text.strip_prefix("--") {
            let (name, value) = option
                .split_once('=')
                .map_or((option, None), |(name, value)| (name, Some(value)));
            let mut matches = long_options
                .iter()
                .flat_map(|long| [long.to_string(), format!("no-{long}")])
                .filter(|long| long.starts_with(name));
            let full = match (matches.next(), matches.next()) {
                (Some(full), None) if !name.is_empty() && full != name => {
                    changed = true;
                    full
                }
                _ => name.to_string(),
            };
            takes_value = value.is_none() && long_values.contains(&full.as_str());
            spelled.push((
                index,
                Word::literal(match value {
                    Some(value) => format!("--{full}={value}"),
                    None => format!("--{full}"),
                }),
            ));
        } else if let Some(cluster) = text.strip_prefix('-').filter(|cluster| cluster.len() > 1) {
            let mut words = Vec::new();
            for (offset, short) in cluster.char_indices() {
                if flags.contains(short) {
                    words.push(format!("-{short}"));
                } else if creation.contains(short) {
                    // The rest of the word is the new branch's name; without
                    // one, the next word is.
                    words.push(format!("-{short}"));
                    let name = &cluster[offset + 1..];
                    if name.is_empty() {
                        takes_value = true;
                    } else {
                        words.push(name.to_string());
                    }
                    break;
                } else {
                    words.clear();
                    break;
                }
            }
            if words.len() > 1 {
                changed = true;
                spelled.extend(words.into_iter().map(|word| (index, Word::literal(word))));
            } else {
                takes_value = false;
                spelled.push((index, word.clone()));
            }
        } else {
            takes_value = text.len() == 2 && creation.contains(&text[1..]);
            spelled.push((index, word.clone()));
        }
    }
    changed.then_some(spelled)
}

enum PathspecFile {
    Absent,
    Read(Vec<(usize, Word)>),
    Unknown,
}

/// `--pathspec-from-file=<file>` hands checkout and restore their pathspecs
/// one per line, or NUL-separated with `--pathspec-file-nul`. From a literal
/// stdin (`-`), this spells them as operands after `--`, each carrying the
/// option word's index; any other file, or a line git would unquote, is
/// Unknown.
fn pathspec_file_operands(s: &SubCtx<'_>) -> PathspecFile {
    let mut kept = Vec::new();
    let mut file = None;
    let mut nul = false;
    let mut words = s.rest.iter().enumerate();
    while let Some((index, word)) = words.next() {
        let text = word.as_literal().unwrap_or_default();
        if text == "--" {
            kept.push((index, word.clone()));
            kept.extend(words.by_ref().map(|(index, word)| (index, word.clone())));
            break;
        }
        let (name, value) = text.split_once('=').unwrap_or((text, ""));
        if name.len() >= "--pathspec-fr".len() && "--pathspec-from-file".starts_with(name) {
            let value = if text.contains('=') {
                Some(Word::literal(value))
            } else {
                words.next().map(|(_, value)| value.clone())
            };
            file = Some((index, value));
        } else if matches!(text, "--pathspec-file-nul" | "--no-pathspec-file-nul") {
            nul = text == "--pathspec-file-nul";
        } else {
            kept.push((index, word.clone()));
        }
    }
    let Some((index, value)) = file else {
        return PathspecFile::Absent;
    };
    let Some(input) = value
        .filter(|value| value.as_literal() == Some("-"))
        .and_then(|_| s.ctx.stdin_literal())
    else {
        return PathspecFile::Unknown;
    };
    let separator = if nul { '\0' } else { '\n' };
    let input = input.strip_suffix(separator).unwrap_or(input);
    let pathspecs = input
        .split(separator)
        .map(|line| {
            if nul {
                line
            } else {
                line.strip_suffix('\r').unwrap_or(line)
            }
        })
        .collect::<Vec<_>>();
    if pathspecs
        .iter()
        .any(|line| line.is_empty() || !nul && line.starts_with('"'))
    {
        return PathspecFile::Unknown;
    }
    if !kept.iter().any(|(_, word)| word.as_literal() == Some("--")) {
        kept.push((index, Word::literal("--")));
    }
    kept.extend(
        pathspecs
            .into_iter()
            .map(|line| (index, Word::literal(line))),
    );
    PathspecFile::Read(kept)
}

/// git-restore(1) documents `-W` for `--worktree`, `-S` for `--staged` and
/// `-s <tree>` for `--source=<tree>`; parse-options also takes `-SW`, an
/// attached `-s<tree>` and a separate `--source <tree>`. This spells each as
/// the long form the restore model reads, so the source tree is never read as
/// a pathspec. None means nothing changed; Err means the source option has
/// no value, which parse-options rejects before restoring anything.
fn spelled_restore_options(rest: &[Word]) -> Result<Option<Vec<(usize, Word)>>, ()> {
    let mut spelled = Vec::new();
    let mut words = rest.iter().enumerate();
    while let Some((index, word)) = words.next() {
        let Some(text) = word.as_literal() else {
            spelled.push((index, word.clone()));
            continue;
        };
        if text == "--" {
            spelled.extend(
                std::iter::once((index, word.clone()))
                    .chain(words.by_ref().map(|(index, word)| (index, word.clone()))),
            );
            break;
        }
        let source_value =
            |attached: &str, words: &mut std::iter::Enumerate<std::slice::Iter<'_, Word>>| {
                let value = if attached.is_empty() {
                    let (_, value) = words.next()?;
                    value.parts.clone()
                } else {
                    vec![WordPart::Literal(attached.to_string())]
                };
                let mut parts = vec![WordPart::Literal("--source=".into())];
                parts.extend(value);
                Some(Word::new(parts))
            };
        if text == "--source" {
            spelled.push((index, source_value("", &mut words).ok_or(())?));
        } else if let Some(cluster) = text
            .strip_prefix('-')
            .filter(|cluster| !cluster.is_empty() && !cluster.starts_with('-'))
            .filter(|cluster| {
                cluster
                    .split_once('s')
                    .map_or(*cluster, |(flags, _)| flags)
                    .chars()
                    .all(|short| matches!(short, 'W' | 'S'))
            })
        {
            for (offset, short) in cluster.char_indices() {
                match short {
                    'W' => spelled.push((index, Word::literal("--worktree"))),
                    'S' => spelled.push((index, Word::literal("--staged"))),
                    _ => {
                        let value = source_value(&cluster[offset + 1..], &mut words).ok_or(())?;
                        spelled.push((index, value));
                        break;
                    }
                }
            }
        } else {
            spelled.push((index, word.clone()));
        }
    }
    let unchanged = spelled.len() == rest.len()
        && spelled
            .iter()
            .zip(rest)
            .all(|((_, spelled), word)| spelled == word);
    Ok((!unchanged).then_some(spelled))
}

fn checkout(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    let spelled = if sub == "restore" {
        let Ok(spelled) = spelled_restore_options(s.rest) else {
            return;
        };
        spelled
    } else {
        spelled_checkout_options(sub, s.rest)
    };
    let spelled = match spelled {
        Some(spelled) => Some(spelled),
        None if sub == "switch" => None,
        None => match pathspec_file_operands(s) {
            PathspecFile::Absent => None,
            PathspecFile::Read(spelled) => Some(spelled),
            // The file names what is discarded; without its contents the
            // selection may be the whole tree.
            PathspecFile::Unknown => {
                let staged_only = sub == "restore"
                    && s.scanned(&["--staged"]).has(&["--staged"])
                    && !s.scanned(&["--worktree"]).has(&["--worktree"]);
                if !staged_only {
                    let mut discard = Attrs::new();
                    discard.insert("discard_mode".into(), AttrValue::String(sub.into()));
                    s.repo_effect(builder, "git.worktree_discard", discard);
                }
                git_argument_boundary(
                    builder,
                    s,
                    "git pathspec file contents are not statically known",
                );
                return;
            }
        },
    };
    if let Some(spelled) = spelled {
        let offset = s.rest_offset as usize;
        let mut argv = s.ctx.argv[..offset].to_vec();
        let mut provenance = (0..offset)
            .map(|index| vec![arg_node(builder, s.ctx, index as u32)])
            .collect::<Vec<_>>();
        for (index, word) in spelled {
            argv.push(word);
            provenance.push(vec![arg_node(builder, s.ctx, (offset + index) as u32)]);
        }
        let ctx = InvocationCtx {
            argv: &argv,
            stdin: s.ctx.stdin,
            argv_provenance: Some(&provenance),
            cwd: s.ctx.cwd,
            cwd_resource: s.ctx.cwd_resource.clone(),
            runtime_cwd: s.ctx.runtime_cwd,
            scope: s.ctx.scope,
            cwd_node: s.ctx.cwd_node,
            nest: s.ctx.nest,
            depth: s.ctx.depth,
            model_stack: s.ctx.model_stack.clone(),
        };
        let spelled = SubCtx {
            globals: s.globals,
            ctx: &ctx,
            model_node: s.model_node,
            repo: s.repo.clone(),
            cwd: s.cwd.clone(),
            rest: &argv[offset..],
            rest_offset: s.rest_offset,
            sub_index: s.sub_index,
        };
        checkout(builder, sub, &spelled);
        return;
    }
    let force = git_effective_flag(s, &["-f", "--force", "--discard-changes"], &["--no-force"]);
    let dd_paths = s.operands(true);
    let all_operands = s.operands(false);
    let mut discard = attrs(&[("force", force)]);
    discard.insert("discard_mode".into(), AttrValue::String(sub.into()));

    if sub == "restore" {
        let staged_selected = s.scanned(&["--staged"]).has(&["--staged"]);
        let worktree_selected = !staged_selected || s.scanned(&["--worktree"]).has(&["--worktree"]);
        if staged_selected && !all_operands.is_empty() {
            s.repo_effect(builder, "git.index_write", Attrs::new());
        }
        if worktree_selected {
            for (index, path) in &all_operands {
                s.git_path_effect(
                    builder,
                    *index,
                    path,
                    "git.worktree_discard",
                    discard.clone(),
                );
                // Restoring the working tree overwrites the entry the
                // pathspec names, the way `git rm` deletes and `git mv`
                // writes the entries their operands name.
                s.filesystem_path_effect(builder, *index, path, "filesystem.write", Attrs::new());
            }
        }
        let whole_tree = foreach_whole_tree(builder, s, &all_operands);
        let selection_paths = if whole_tree {
            Some(Vec::new())
        } else {
            all_operands
                .iter()
                .map(|(_, path)| git_discard_selection_path(builder, s, path))
                .collect::<Option<Vec<_>>>()
        };
        // The pathspec selects what the worktree restore overwrites. With
        // only the index selected there is no worktree path to widen.
        if worktree_selected && !all_operands.is_empty() && selection_paths.is_none() {
            git_argument_boundary(
                builder,
                s,
                "git restore pathspec selection is not a known plain path",
            );
        }
        if worktree_selected
            && !all_operands.is_empty()
            && let Some(selection_paths) = selection_paths
            && git_operands_are_not_options(s, &all_operands)
            && git_checkout_options_known(s, sub)
        {
            let mut request = request_attrs(&[
                ("force", false),
                ("selection_complete", true),
                (
                    "root_uses_invocation_cwd",
                    root_uses_invocation_cwd(s.globals, s.ctx),
                ),
                (
                    "discovers_from_worktree",
                    discovers_from_worktree(s.globals, s.ctx),
                ),
            ]);
            request.insert("discard_mode".into(), AttrValue::String("restore".into()));
            insert_selection(&mut request, whole_tree, &selection_paths);
            insert_selects_top(&mut request, s, &all_operands);
            s.request_effect(builder, "git.worktree_discard_request", request);
        }
        return;
    }
    // Git rejects force with effective merge before changing the worktree,
    // for a branch switch and a pathspec checkout alike.
    if force && git_effective_flag(s, &["--merge", "-m"], &["--no-merge"]) {
        return;
    }
    let targets = checkout_targets(s, sub, &all_operands);
    if sub == "switch" {
        if !targets.bounded && git_checkout_options_known(s, sub) {
            return;
        }
        if force {
            s.repo_effect(builder, "git.worktree_discard", discard.clone());
            whole_worktree_discard_request(builder, sub, s, &all_operands, &targets);
        }
        s.repo_effect(builder, "git.worktree_write", Attrs::new());
        if targets.creates_branch && targets.bounded && git_checkout_options_known(s, sub) {
            let force_create = s.rest.iter().any(|word| {
                matches!(word.as_literal(), Some("-C" | "--force-create"))
                    || word
                        .as_literal()
                        .is_some_and(|value| value.starts_with("-C") && value.len() > 2)
            });
            s.repo_effect(builder, "git.ref_update", attrs(&[("force", force_create)]));
        }
        return;
    }

    if !dd_paths.is_empty()
        && git_checkout_options_known(s, sub)
        && all_operands.len() > dd_paths.len() + 1
    {
        return;
    }

    // checkout: pathspecs after `--`, or path-looking operands without it.
    let paths: Vec<(u32, &Word)> = if !dd_paths.is_empty() {
        dd_paths
    } else if targets.creates_branch {
        // The operands of a branch creation are the new name and the start
        // point it branches from; a pathspec needs an explicit `--`.
        Vec::new()
    } else if all_operands
        .first()
        .is_some_and(|(_, word)| word.as_literal() == Some("HEAD"))
        && all_operands.len() > 1
    {
        all_operands.iter().skip(1).copied().collect()
    } else {
        // git-check-ref-format(1) forbids `*`, `?` and `[` in a ref, so an
        // operand spelling one is a pathspec.
        all_operands
            .iter()
            .filter(|(_, w)| {
                w.as_literal().is_none_or(|t| {
                    t == "."
                        || t.starts_with("./")
                        || t.contains('/')
                        || t.contains(['*', '?', '['])
                })
            })
            .map(|(i, w)| (*i, *w))
            .collect()
    };
    if !paths.is_empty() {
        for (index, path) in &paths {
            s.git_path_effect(
                builder,
                *index,
                path,
                "git.worktree_discard",
                discard.clone(),
            );
            // A pathspec checkout overwrites the working-tree entries it
            // names, exactly as `git restore` does.
            s.filesystem_path_effect(builder, *index, path, "filesystem.write", Attrs::new());
        }
        let whole_tree = foreach_whole_tree(builder, s, &paths);
        let selection_paths = if whole_tree {
            Some(Vec::new())
        } else {
            paths
                .iter()
                .map(|(_, path)| git_discard_selection_path(builder, s, path))
                .collect::<Option<Vec<_>>>()
        };
        if selection_paths.is_none() {
            git_argument_boundary(
                builder,
                s,
                "git checkout pathspec selection is not a known plain path",
            );
        }
        if let Some(selection_paths) = selection_paths
            && git_operands_are_not_options(s, &paths)
            && git_checkout_options_known(s, sub)
        {
            let mut request = request_attrs(&[
                ("force", force),
                ("selection_complete", true),
                (
                    "root_uses_invocation_cwd",
                    root_uses_invocation_cwd(s.globals, s.ctx),
                ),
                (
                    "discovers_from_worktree",
                    discovers_from_worktree(s.globals, s.ctx),
                ),
            ]);
            request.insert("discard_mode".into(), AttrValue::String("checkout".into()));
            insert_selection(&mut request, whole_tree, &selection_paths);
            insert_selects_top(&mut request, s, &paths);
            s.request_effect(builder, "git.worktree_discard_request", request);
        }
        return;
    }
    let branchish = all_operands
        .iter()
        .any(|(_, w)| w.as_literal().is_some_and(|t| t != "HEAD"));
    if force && (!branchish || s.scanned(&["-B"]).has(&["-B"])) {
        s.repo_effect(builder, "git.worktree_discard", discard.clone());
        whole_worktree_discard_request(builder, sub, s, &all_operands, &targets);
    } else if branchish || s.scanned(&["-b", "-B"]).has(&["-b", "-B"]) {
        // `checkout -f <branch>` force-switches, discarding uncommitted local
        // changes — a destructive worktree_discard on top of the switch.
        if force {
            s.repo_effect(builder, "git.worktree_discard", discard.clone());
            whole_worktree_discard_request(builder, sub, s, &all_operands, &targets);
        }
        s.repo_effect(builder, "git.worktree_write", Attrs::new());
        if s.scanned(&["-b", "-B"]).has(&["-b", "-B"]) {
            s.repo_effect(builder, "git.ref_update", Attrs::new());
        }
    } else {
        s.repo_effect(builder, "git.read", Attrs::new());
    }
}

/// Push options and operands share one scan so option values cannot become remotes or refspecs.
struct PushArgs<'a> {
    flags: Vec<(&'a str, Option<String>)>,
    remote: Option<(u32, &'a Word)>,
    /// The last `--repo` value, `Some(None)` when it is not literal.
    repo: Option<Option<String>>,
    refs: Vec<(u32, &'a Word)>,
    complete: bool,
    control_known: bool,
    option_values_known: bool,
}
impl<'a> PushArgs<'a> {
    fn scan(s: &'a SubCtx) -> Self {
        let scanned = git_options(
            s,
            &FlagSpec {
                value_flags: &[
                    "-o",
                    "--push-option",
                    "--repo",
                    "--receive-pack",
                    "--exec",
                    "--recurse-submodules",
                ],
                known_flags: &[
                    "-f",
                    "--force",
                    "--no-force",
                    "--force-with-lease",
                    "--no-force-with-lease",
                    "--force-if-includes",
                    "--no-force-if-includes",
                    "-d",
                    "--delete",
                    "--no-delete",
                    "--mirror",
                    "--no-mirror",
                    "-n",
                    "--dry-run",
                    "--no-dry-run",
                    "--all",
                    "--no-all",
                    "--branches",
                    "--no-branches",
                    "--tags",
                    "--no-tags",
                    "--prune",
                    "--no-prune",
                    "--verify",
                    "--no-verify",
                    "--follow-tags",
                    "--no-follow-tags",
                    "-v",
                    "--verbose",
                    "--no-verbose",
                    "-q",
                    "--quiet",
                    "--no-quiet",
                    "-u",
                    "--set-upstream",
                    "--no-set-upstream",
                    "--porcelain",
                    "--no-porcelain",
                    "--progress",
                    "--no-progress",
                    "--thin",
                    "--no-thin",
                    "--signed",
                    "--no-signed",
                    "--atomic",
                    "--no-atomic",
                    "-4",
                    "--ipv4",
                    "-6",
                    "--ipv6",
                    "-h",
                    "--help",
                    "--version",
                ],
                allow_abbreviation: true,
            },
        );
        let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
        let flags = scanned
            .flags
            .iter()
            .filter_map(|flag| {
                if scanned
                    .unknown_flags
                    .iter()
                    .any(|(index, _)| *index == flag.index)
                {
                    return None;
                }
                let text = argv[flag.index as usize].as_literal()?;
                Some((
                    flag.name,
                    text.split_once('=').map(|(_, value)| value.to_string()),
                ))
            })
            .collect();
        let value_flags = [
            "-o",
            "--push-option",
            "--repo",
            "--receive-pack",
            "--exec",
            "--recurse-submodules",
        ];
        let optional_value_flags = ["--force-with-lease"];
        let controls_valid = scanned.flags.iter().all(|flag| {
            let Some(text) = argv[flag.index as usize].as_literal() else {
                return false;
            };
            if value_flags.contains(&flag.name) && flag.value.is_none() {
                return false;
            }
            text.split_once('=').is_none_or(|_| {
                value_flags.contains(&flag.name) || optional_value_flags.contains(&flag.name)
            })
        });
        let unknown_control = scanned.unknown_flags.iter().any(|(index, _)| {
            !scanned
                .operands
                .iter()
                .any(|(operand_index, _)| operand_index == index)
        });
        let control_known = !unknown_control && controls_valid;
        let complete = scanned.unknown_flags.is_empty() && controls_valid;
        let option_values_known = scanned
            .flags
            .iter()
            .all(|flag| argv[flag.index as usize].as_literal().is_some())
            && scanned.unknown_flags.iter().all(|(index, _)| {
                scanned
                    .operands
                    .iter()
                    .any(|(operand_index, _)| operand_index == index)
                    || argv[*index as usize].as_literal().is_some()
            });
        let repo = scanned
            .value_of(&["--repo"])
            .map(|value| value.as_literal().map(str::to_string));
        let mut operands = scanned
            .operands
            .into_iter()
            .map(|(index, word)| (s.rest_offset - 1 + index, word))
            .collect::<Vec<_>>();
        let remote = if operands.first().is_some_and(|(_, w)| {
            w.as_literal().is_none_or(|t| {
                !t.starts_with('+') && (!t.contains(':') || parse_endpoint(t).is_some())
            })
        }) {
            Some(operands.remove(0))
        } else {
            None
        };
        Self {
            flags,
            remote,
            repo,
            refs: operands,
            complete,
            control_known,
            option_values_known,
        }
    }

    fn has(&self, name: &str, short: Option<char>) -> bool {
        let negative = if name.starts_with("--no-") {
            name.replacen("--no-", "--", 1)
        } else {
            name.replacen("--", "--no-", 1)
        };
        let short = short.map(|c| format!("-{c}"));
        self.flags
            .iter()
            .rev()
            .find_map(|(flag, _)| {
                if *flag == name || short.as_deref() == Some(*flag) {
                    Some(true)
                } else if *flag == negative {
                    Some(false)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
}

fn valid_git_ref_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.starts_with('-')
        && !name.contains("..")
        && !name.contains("@{")
        && !name
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
        && !name.contains(['~', '^', ':', '?', '*', '[', '\\'])
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
        })
}

fn valid_git_refspec(text: &str) -> bool {
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() || text.contains(['*', '?', '[']) {
        return false;
    }
    match text.split_once(':') {
        Some((source, destination)) => {
            (source.is_empty() || valid_git_ref_name(source)) && valid_git_ref_name(destination)
        }
        None => valid_git_ref_name(text),
    }
}

fn push(builder: &mut PlanBuilder, s: &SubCtx) {
    if empty_repository_global(s) {
        return;
    }
    let args = PushArgs::scan(s);
    if args.has("--help", Some('h')) || args.has("--version", None) {
        return;
    }
    let explicit_force = args.has("--force", Some('f'));
    let all_branches = args
        .flags
        .iter()
        .rev()
        .find_map(|(flag, _)| match *flag {
            "--all" | "--branches" => Some(true),
            "--no-all" | "--no-branches" => Some(false),
            _ => None,
        })
        .unwrap_or(false);
    let mut all_refs_lease = false;
    let mut lease_targets = Vec::new();
    for (flag, value) in &args.flags {
        match *flag {
            "--no-force-with-lease" => {
                all_refs_lease = false;
                lease_targets.clear();
            }
            "--force-with-lease" => match value {
                None => all_refs_lease = true,
                Some(value) => {
                    let target = value
                        .split_once(':')
                        .map_or(value.as_str(), |(target, _)| target);
                    if !lease_targets.contains(&target) {
                        lease_targets.push(target);
                    }
                }
            },
            _ => {}
        }
    }
    let normalize = normalize_push_ref;
    let mut complete = args.complete && args.remote.is_some() && !args.refs.is_empty();
    let mut refspecs_valid = true;
    let mut request_destinations = Vec::new();
    let mut request_sources = Vec::new();
    let mut request_forced = Vec::new();
    let mut request_deleted = Vec::new();
    let mut refspec_deletes = Vec::new();
    let delete = args.has("--delete", Some('d'));
    let mirror = args.has("--mirror", None);
    // remote.<name>.mirror and remote.<name>.push configure the remote the
    // push selects (git-push(1)): the repository operand, else `--repo`.
    // Without either, git takes it from branch.<name>.pushRemote,
    // remote.pushDefault or the branch's upstream, which unobserved files
    // may set, so any configured remote may be it.
    let selected_remote = match (args.remote, &args.repo) {
        (Some((_, word)), _) => word.as_literal(),
        (None, Some(repo)) => repo.as_deref(),
        (None, None) => None,
    };
    // remote.<name>.mirror holds one value, the last that reaches git, for
    // each remote that may be selected. git reads it as a boolean; a value
    // the model does not classify may be true. An include the model could
    // not read leaves the setting unknown rather than possibly true.
    let mut mirror_values = Vec::new();
    let mirror_unknown;
    match selected_remote {
        Some(name) => {
            let found = config_values(s.globals, &format!("remote.{name}.mirror"));
            mirror_unknown = found.unknown;
            mirror_values.extend(found.values);
        }
        None => {
            let mut names = Vec::new();
            for entry in &s.globals.configs {
                let Some((section, rest)) = entry.key.split_once('.') else {
                    continue;
                };
                if let Some((name, variable)) = rest.rsplit_once('.')
                    && section.eq_ignore_ascii_case("remote")
                    && variable.eq_ignore_ascii_case("mirror")
                    && !names.contains(&name)
                {
                    names.push(name);
                }
            }
            for name in names {
                mirror_values
                    .extend(config_values(s.globals, &format!("remote.{name}.mirror")).values);
            }
            if s.globals.configs.iter().any(|entry| entry.key.is_empty()) {
                mirror_values.push(None);
            }
            // The unread include may name any remote.
            mirror_unknown = s.globals.configs.iter().any(|entry| entry.unobserved);
        }
    }
    let mirror_possible = mirror_values
        .iter()
        .any(|value| value.is_none_or(|value| git_bool(value) != Some(false)));
    let config_mirror_certain = !mirror_unknown
        && selected_remote.is_some_and(|name| {
            matches!(
                config_value(s.globals, &format!("remote.{name}.mirror")),
                Some(Some(value)) if git_bool(value) == Some(true)
            )
        });
    // git sets the mirror flags from the remote before it refuses refspecs
    // or `--all` beside them (push.c `cmd_push`), so a mirror remote pushes
    // only without either, as `git push --mirror` does.
    let mirror_refused = !args.refs.is_empty() || all_branches;
    let config_mirror = mirror_possible && !mirror_refused;
    let config_mirror_unknown = mirror_unknown && !mirror_possible && !mirror_refused;
    // remote.<name>.push keeps every value. Without a refspec, `--all` or
    // `--tags`, git pushes these refspecs; a leading `+` forces the update,
    // and a value the model cannot read may.
    let configured_refspecs = remote_settings(s.globals, selected_remote, "push");
    let configured_forced = |value: Option<&str>| value.is_none_or(|text| text.starts_with('+'));
    // Each configured destination: source, destination, forced (`None` when
    // an unread include may set it), deleted, and whether it certainly
    // applies.
    let mut configured = Vec::new();
    if args.refs.is_empty() && !all_branches && !args.has("--tags", None) {
        for setting in &configured_refspecs {
            let RemoteSetting::Value(value, certain) = *setting else {
                configured.push((None, None, None, false, false));
                continue;
            };
            let unforced = value.map(|text| text.strip_prefix('+').unwrap_or(text));
            // `:` alone pushes the matching branches; it deletes nothing.
            let matching = unforced == Some(":");
            let deleted = !matching && unforced.is_some_and(|text| text.starts_with(':'));
            configured.push((
                unforced.filter(|_| !matching).map(|text| {
                    text.split_once(':')
                        .map_or(text, |(source, _)| source)
                        .to_string()
                }),
                unforced
                    .filter(|_| !matching)
                    .map(|text| normalize(text.split_once(':').map_or(text, |(_, dst)| dst))),
                Some(configured_forced(value) || deleted),
                deleted,
                certain,
            ));
        }
    }
    // Colonless branch operands, which may take a configured mapping.
    let mut mappable = Vec::new();
    let mut refs = Vec::new();
    let mut operands = args.refs.iter();
    while let Some((_, word)) = operands.next() {
        if word.as_literal() == Some("tag") {
            let tag = operands.next().and_then(|(_, word)| word.as_literal());
            refs.push(tag.map(|tag| format!("refs/tags/{tag}")));
            let valid =
                tag.is_some_and(|tag| !tag.is_empty() && !tag.contains([':', '*', '?', '[']));
            complete &= valid;
            refspecs_valid &= tag.is_some_and(valid_git_ref_name);
            request_destinations.push(tag.map(|tag| format!("refs/tags/{tag}")));
            request_sources.push(tag.map(|tag| format!("refs/tags/{tag}")));
            request_forced.push(Some(false));
            request_deleted.push(false);
            refspec_deletes.push(false);
        } else {
            let refspec = word.as_literal();
            // `:` alone pushes the matching branches, forced with `+:`; it
            // names no branch and deletes nothing.
            let matching =
                refspec.is_some_and(|text| text.strip_prefix('+').unwrap_or(text) == ":");
            let symbolic_delete = !matching && word.literal_prefix().starts_with(':');
            let valid = refspec.is_some_and(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                !text.is_empty()
                    && text != ":"
                    && !text.contains(['*', '?', '['])
                    && !text
                        .split_once(':')
                        .is_some_and(|(_, dst)| dst.is_empty() || dst.contains(':'))
            });
            complete &= valid;
            refspecs_valid &= matching || refspec.is_some_and(valid_git_refspec);
            let deletes = symbolic_delete
                || !matching
                    && refspec.is_some_and(|text| {
                        text.strip_prefix('+').unwrap_or(text).starts_with(':')
                    });
            request_destinations.push(refspec.filter(|_| !matching).map(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                normalize(text.split_once(':').map_or(text, |(_, dst)| dst))
            }));
            request_sources.push(refspec.filter(|_| !matching).map(|text| {
                let text = text.strip_prefix('+').unwrap_or(text);
                text.split_once(':')
                    .map_or(text, |(source, _)| source)
                    .to_string()
            }));
            request_forced.push(Some(
                refspec_word_forced(word) || deletes || explicit_force || mirror || delete,
            ));
            request_deleted.push(deletes || delete);
            refspec_deletes.push(deletes);
            // git maps a colonless operand that names one local ref through
            // the remote's push refspecs; a deletion or `tag <name>` is not
            // mapped (push.c `set_refspecs`).
            if !delete
                && let Some(operand) =
                    refspec.filter(|text| !text.contains(':') && !text.starts_with('+'))
            {
                mappable.push(operand);
            }
            refs.push(refspec.map(str::to_owned));
        }
    }
    // For each full name git's ref matching may resolve an operand to, the
    // first push refspec whose source is that name maps it, with that
    // refspec's force (refspec.c `refspec_find_match`). A later refspec
    // applies only while every earlier match may not.
    for operand in mappable {
        for name in [
            operand.to_string(),
            format!("refs/{operand}"),
            format!("refs/tags/{operand}"),
            format!("refs/heads/{operand}"),
            format!("refs/remotes/{operand}"),
            format!("refs/remotes/{operand}/HEAD"),
        ] {
            for setting in &configured_refspecs {
                let (value, certain) = match *setting {
                    RemoteSetting::Unobserved => {
                        configured.push((None, None, None, false, false));
                        continue;
                    }
                    RemoteSetting::Value(None, _) => {
                        configured.push((None, None, Some(true), false, false));
                        continue;
                    }
                    RemoteSetting::Value(Some(value), certain) => (value, certain),
                };
                let unforced = value.strip_prefix('+').unwrap_or(value);
                let Some((source, destination)) = unforced.split_once(':') else {
                    continue;
                };
                let mapped = match (source.split_once('*'), destination.split_once('*')) {
                    (Some((prefix, suffix)), Some((before, after))) => name
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.strip_suffix(suffix))
                        .map(|middle| format!("{before}{middle}{after}")),
                    (None, None) => (source == name).then(|| destination.to_string()),
                    _ => None,
                };
                if let Some(mapped) = mapped {
                    configured.push((
                        Some(name.clone()),
                        Some(normalize(&mapped)),
                        Some(configured_forced(Some(value))),
                        false,
                        false,
                    ));
                    if certain {
                        break;
                    }
                }
            }
        }
    }
    let configured_force = configured
        .iter()
        .any(|(_, _, forced, _, _)| *forced == Some(true));
    let configured_unknown = configured
        .iter()
        .any(|(_, _, forced, _, _)| forced.is_none());
    // Unknown force (`None`) is never certain, so it is unestablished too.
    let config_unestablished = config_mirror && !config_mirror_certain
        || config_mirror_unknown
        || configured
            .iter()
            .any(|(_, _, forced, _, certain)| *forced != Some(false) && !certain);
    if config_unestablished {
        git_argument_boundary(
            builder,
            s,
            "git push remote configuration is not statically established",
        );
    }
    // Refspec operands are certain; a configured mapping is certain when its
    // setting is and no possible mirror remote may force it.
    let mut request_certain = vec![true; request_destinations.len()];
    for (source, destination, forced, deleted, certain) in configured {
        request_certain.push(certain && (!config_mirror || config_mirror_certain));
        request_sources.push(source);
        request_destinations.push(destination);
        request_forced.push(if explicit_force || mirror || config_mirror {
            Some(true)
        } else {
            forced
        });
        request_deleted.push(deleted);
    }
    complete &= !args.has("--tags", None)
        && !args.has("--follow-tags", None)
        && !all_branches
        && !args.has("--mirror", None)
        && !args.has("--prune", None);
    if refs.is_empty() {
        refs.push(None);
    }
    let lease_targets_known = lease_targets
        .iter()
        .all(|target| !target.is_empty() && !target.contains(['*', '?', '[', ' ', '\n']));
    let request_controls_valid = !(delete && (all_branches || mirror))
        && (!mirror || args.refs.is_empty())
        && (!all_branches || args.refs.is_empty())
        && !(config_mirror_certain && mirror_refused);
    if !args.complete
        || !lease_targets_known
        || !request_controls_valid
        || !complete && !args.refs.is_empty()
    {
        git_argument_boundary(
            builder,
            s,
            "git push options or refspec destinations are not fully known",
        );
    }
    let remote = args.remote.and_then(|(_, remote)| remote.as_literal());
    let remote_known = args.remote.is_none() || remote.is_some();
    let controls_for_attributes = args.option_values_known
        && (args.remote.is_none()
            || args
                .remote
                .is_some_and(|(_, word)| word.as_literal().is_some()));
    // Each sync describes one destination; every effect retains the full lease scope set.
    let mut source = None;
    for (ref_index, refspec) in refs.into_iter().enumerate() {
        let refspec = refspec.as_deref();
        let unforced = refspec.map(|r| r.strip_prefix('+').unwrap_or(r));
        // A matching `:` names no source or destination.
        let named = unforced.filter(|r| *r != ":");
        let dst = named.map(|r| normalize(r.split_once(':').map_or(r, |(_, d)| d)));
        let refspec_forced = refspec.is_some_and(|r| r.starts_with('+'));
        let force = explicit_force
            || mirror
            || config_mirror
            || configured_force
            || delete
            || refspec_forced
            || refspec_deletes.get(ref_index).copied().unwrap_or(false);
        let lease = !explicit_force
            && (all_refs_lease
                || dst.as_ref().is_some_and(|dst| {
                    lease_targets.iter().any(|target| *dst == normalize(target))
                }));
        let mut a: Attrs = [
            ("push", true),
            ("remote_complete", remote.is_some()),
            ("explicit_force", explicit_force),
            (
                "lease_requested",
                all_refs_lease || !lease_targets.is_empty(),
            ),
            ("all_refs_lease", all_refs_lease),
            (
                "lease_targets_complete",
                lease_targets_known && controls_for_attributes,
            ),
            ("refspecs_complete", complete),
            (
                "refspec_forced",
                refspec_forced
                    || configured_force
                    || explicit_force
                    || mirror
                    || config_mirror
                    || delete,
            ),
            ("branches", all_branches),
            ("force", force),
            ("lease", lease),
            ("delete", delete),
            ("mirror", mirror || config_mirror),
            ("no_verify", args.has("--no-verify", None)),
            ("prune", args.has("--prune", None)),
            ("dry_run", args.has("--dry-run", Some('n'))),
            ("all", all_branches),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), AttrValue::Bool(value)))
        .collect();
        if let Some(remote) = remote {
            a.insert("remote".into(), AttrValue::String(remote.into()));
        }
        if !lease_targets_known {
            a.remove("lease");
        }
        if controls_for_attributes {
            a.insert("lease_targets".into(), string_list(&lease_targets));
        } else {
            // A symbolic option may enable or cancel a control; absence means unknown.
            for key in [
                "explicit_force",
                "lease_requested",
                "all_refs_lease",
                "branches",
                "force",
                "lease",
                "delete",
                "mirror",
                "no_verify",
                "prune",
                "dry_run",
                "all",
            ] {
                a.remove(key);
            }
        }
        for (key, value) in [
            ("refspec", refspec),
            (
                "source_ref",
                named.map(|r| r.split_once(':').map_or(r, |(source, _)| source)),
            ),
            ("dst_ref", dst.as_deref()),
        ] {
            if let Some(value) = value {
                a.insert(key.into(), AttrValue::String(value.into()));
            }
        }
        // An unread include may make the remote a mirror or force a
        // configured refspec; absence means unknown.
        if config_mirror_unknown && !mirror {
            a.remove("mirror");
        }
        if (config_mirror_unknown || configured_unknown) && !force {
            a.remove("force");
            a.remove("refspec_forced");
        }
        source = s.repo_effect_slot(builder, "git.remote_sync", a);
    }
    let destination = s.remote_network(builder, "network.upload");
    if let (Some(source), Some(destination)) = (source, destination) {
        builder.transfer_binding(TransferBinding::new(source, destination));
    }
    if !args.has("--dry-run", Some('n')) {
        let request_exact = args.control_known
            && lease_targets_known
            && refspecs_valid
            && request_controls_valid
            && !config_unestablished;
        let mut request = Attrs::new();
        request.insert("push".into(), AttrValue::Bool(true));
        request.insert("active".into(), AttrValue::Bool(true));
        request.insert("abort".into(), AttrValue::Bool(false));
        request.insert(
            "destination_complete".into(),
            AttrValue::Bool(complete && remote_known),
        );
        request.insert("remote_complete".into(), AttrValue::Bool(remote.is_some()));
        request.insert(
            "controls_complete".into(),
            AttrValue::Bool(args.control_known),
        );
        if let Some(remote) = remote {
            request.insert("remote".into(), AttrValue::String(remote.to_string()));
        }
        let destinations = (0..request_destinations.len())
            .map(|index| PushedRef {
                destination: request_destinations[index].clone(),
                source: request_sources[index].as_deref(),
                forced: request_forced[index],
                deleted: Some(request_deleted[index]),
                certain: request_certain[index],
            })
            .collect::<Vec<_>>();
        // Only a complete destination set, from literal refspecs to a literal
        // remote, is enumerated.
        push_destination_lists(
            &mut request,
            &destinations,
            // A symbolic option may request a lease, as it may for the
            // `all_refs_lease` attribute.
            controls_for_attributes.then_some((all_refs_lease, lease_targets.as_slice())),
            lease_targets_known,
            complete && remote_known,
        );
        for (key, value) in [
            ("explicit_force", explicit_force),
            (
                "lease_requested",
                all_refs_lease || !lease_targets.is_empty(),
            ),
            ("all_refs_lease", all_refs_lease),
            (
                "force",
                explicit_force
                    || args.has("--mirror", None)
                    || config_mirror
                    || configured_force
                    || args.has("--delete", Some('d'))
                    || args.refs.iter().any(|(_, word)| {
                        refspec_word_forced(word)
                            || word
                                .as_literal()
                                .is_some_and(|value| value.starts_with(':') && value != ":")
                    }),
            ),
            ("delete", args.has("--delete", Some('d'))),
            ("mirror", args.has("--mirror", None) || config_mirror),
            ("no_verify", args.has("--no-verify", None)),
            ("prune", args.has("--prune", None)),
            ("all", all_branches),
            ("dry_run", false),
        ] {
            request.insert(key.into(), AttrValue::Bool(value));
        }
        if config_mirror_unknown && !mirror {
            request.remove("mirror");
        }
        if (config_mirror_unknown || configured_unknown)
            && request.get("force") == Some(&AttrValue::Bool(false))
        {
            request.remove("force");
        }
        if controls_for_attributes {
            request.insert("lease_targets".into(), string_list(&lease_targets));
        }
        let mut antecedents = s.ctx.arg_antecedents(s.sub_index);
        if repo_uses_cwd(s.globals) {
            antecedents.extend(s.ctx.cwd_node);
        }
        let arg = builder.node(
            ProvenanceKind::Argument { index: s.sub_index },
            &antecedents,
        );
        let mut provenance = vec![arg];
        provenance.extend(s.repo_global_nodes(builder));
        provenance.push(s.model_node);
        builder.effect(Effect {
            request_assurance: if request_exact {
                effinterp_proto::RequestAssurance::Exact
            } else {
                effinterp_proto::RequestAssurance::Conservative
            },
            id: Default::default(),
            operation: Operation::new("git.push_request"),
            resource: s.repo.clone(),
            attributes: request,
            modality: if request_exact {
                Modality::MustOnSuccess
            } else {
                Modality::May
            },
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        // A mirror push prunes: git-push(1) removes every remote ref the
        // local repository lacks, whichever remote it pushes to.
        if request_exact
            && (args.has("--prune", None) && remote.is_some() || mirror || config_mirror)
        {
            let mut deletion = request_attrs(&[
                ("delete", true),
                ("prune", true),
                ("selection_complete", false),
            ]);
            if let Some(remote) = remote {
                deletion.insert("remote".into(), AttrValue::String(remote.into()));
            }
            deletion.insert("scope".into(), AttrValue::String("selected".into()));
            deletion.insert("broad".into(), AttrValue::Bool(false));
            s.request_effect(builder, "git.ref_delete_request", deletion);
        }
    }
    s.hooks_boundary(builder);
}
