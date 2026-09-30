//! File-transfer commands that cross the host boundary: `rsync` and `scp`.
//! A `[user@]host:path` or `rsync://host/path` operand is a remote endpoint
//! (network), a plain path is local (filesystem), and an operand that could be
//! either carries an unresolved transfer boundary. Sources are read and the
//! destination is written; a remote side is never a local filesystem effect.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionEdgeKind, ExecutionRealm, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, arg_node, code_execution, fs_arg_effect, has_unknown,
    leading_symbolic_without, nest_remote_shell, opaque_source_with_provenance, operand_effect,
    program_input_attrs, program_output_attrs, remote_endpoint, symbolic_expr,
    unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{Transition, word_resource};
use crate::paths::resolve_fs_word_with_cwd;
use crate::word::{Word, WordPart};

pub(super) fn transfer_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(Rsync), Box::new(Scp)]
}

/// A transfer operand: a local path, remote endpoint, or ambiguous target.
#[derive(Clone)]
enum Target {
    Local(ResourceExpr),
    Remote(ResourceExpr),
    /// `host:path` whose host a command substitution spells: its output may
    /// hold a slash, which makes the whole word a local path. An environment
    /// variable could hold one too, but `$HOST:path` deliberately stays
    /// `Remote`, as a host name is what such a variable conventionally holds.
    MaybeRemote(ResourceExpr),
    Unknown(ResourceExpr),
}

/// Classify an operand by transfer syntax before resolving local paths.
fn classify(word: &Word, cwd: Option<ResourceExpr>) -> Target {
    if let Some(text) = word.as_literal() {
        if let Some(rest) = text.strip_prefix("rsync://") {
            let host = rest.split('/').next().unwrap_or(rest);
            return Target::Remote(endpoint(host, "rsync"));
        }
        // `[user@]host:path` — a colon before any slash marks a remote host.
        if let Some((hostpart, _path)) = text.split_once(':')
            && !hostpart.contains('/')
            && !hostpart.is_empty()
        {
            return Target::Remote(endpoint(hostpart, "ssh"));
        }
        return Target::Local(resolve_fs_word_with_cwd(word, cwd));
    }
    if word.parts.first().is_some_and(
        |part| matches!(part, WordPart::Literal(value) if value.starts_with("rsync://")),
    ) {
        let host = parts_before_separator(word, "rsync://", '/');
        if !host.is_empty() {
            return Target::Remote(remote_endpoint(host, "rsync"));
        }
    }
    if let Some(mut host) = parts_before_colon(word) {
        let substituted = host
            .iter()
            .any(|part| matches!(part, WordPart::Unknown | WordPart::Value(_)));
        strip_user_prefix(&mut host);
        if !host.is_empty() {
            let endpoint = remote_endpoint(host, "ssh");
            return if substituted {
                Target::MaybeRemote(endpoint)
            } else {
                Target::Remote(endpoint)
            };
        }
    }
    // A glob's own text settles the ambiguity the way literal text does: a
    // slash before any colon cannot begin a `host:path` operand.
    let local_glob = word.parts.iter().any(|part| {
        matches!(part, WordPart::Glob(text)
            if text.find('/').is_some_and(|slash| !text[..slash].contains(':')))
    });
    if !local_glob && leading_symbolic_without(word, &[':', '/']) {
        return Target::Unknown(symbolic_expr(word, "network"));
    }
    Target::Local(resolve_fs_word_with_cwd(word, cwd))
}

fn endpoint(hostpart: &str, scheme: &str) -> ResourceExpr {
    let host = hostpart.rsplit('@').next().unwrap_or(hostpart);
    ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host: host.to_string(),
            scheme: Some(scheme.to_string()),
            port: None,
            path: None,
        },
    }
}

fn parts_before_separator(word: &Word, prefix: &str, separator: char) -> Vec<WordPart> {
    let mut parts = Vec::new();
    for (index, part) in word.parts.iter().enumerate() {
        match part {
            WordPart::Literal(value) => {
                let value = if index == 0 {
                    value.strip_prefix(prefix).unwrap()
                } else {
                    value
                };
                if let Some((before, _)) = value.split_once(separator) {
                    if !before.is_empty() {
                        parts.push(WordPart::Literal(before.to_string()));
                    }
                    break;
                }
                if !value.is_empty() {
                    parts.push(WordPart::Literal(value.to_string()));
                }
            }
            part => parts.push(part.clone()),
        }
    }
    Word::new(parts).parts
}

fn parts_before_colon(word: &Word) -> Option<Vec<WordPart>> {
    let mut parts = Vec::new();
    for part in &word.parts {
        match part {
            WordPart::Literal(value) => {
                let colon = value.find(':');
                let slash = value.find('/');
                if slash.is_some_and(|slash| colon.is_none_or(|colon| slash < colon)) {
                    return None;
                }
                if let Some(colon) = colon {
                    if colon > 0 {
                        parts.push(WordPart::Literal(value[..colon].to_string()));
                    }
                    return Some(Word::new(parts).parts);
                }
                if !value.is_empty() {
                    parts.push(part.clone());
                }
            }
            part => parts.push(part.clone()),
        }
    }
    None
}

fn strip_user_prefix(parts: &mut Vec<WordPart>) {
    let Some((index, at)) = parts.iter().enumerate().rev().find_map(|(index, part)| {
        let WordPart::Literal(value) = part else {
            return None;
        };
        value.rfind('@').map(|at| (index, at))
    }) else {
        return;
    };
    let WordPart::Literal(value) = &parts[index] else {
        unreachable!();
    };
    let suffix = value[at + 1..].to_string();
    parts.drain(..=index);
    if !suffix.is_empty() {
        parts.insert(0, WordPart::Literal(suffix));
    }
}

fn remote_host(word: &Word) -> Option<Word> {
    if let Some(text) = word.as_literal() {
        if let Some(rest) = text.strip_prefix("rsync://") {
            let host = rest.split('/').next().unwrap_or(rest);
            return (!host.is_empty()).then(|| Word::literal(host));
        }
        if let Some((host, _)) = text.split_once(':')
            && !host.contains('/')
            && !host.is_empty()
        {
            return Some(Word::literal(host.rsplit('@').next().unwrap_or(host)));
        }
        return None;
    }
    if word.parts.first().is_some_and(
        |part| matches!(part, WordPart::Literal(value) if value.starts_with("rsync://")),
    ) {
        let mut host = parts_before_separator(word, "rsync://", '/');
        strip_user_prefix(&mut host);
        return (!host.is_empty()).then(|| Word::new(host));
    }
    let mut host = parts_before_colon(word)?;
    strip_user_prefix(&mut host);
    (!host.is_empty()).then(|| Word::new(host))
}

fn split_rsync_shell(command: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
                continue;
            }
            if quote.is_none() {
                quote = Some(character);
                continue;
            }
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                words.push(Word::literal(std::mem::take(&mut current)));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        words.push(Word::literal(current));
    }
    Some(words)
}

fn unrecoverable_rsync_shell(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    argument: ProvenanceRef,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: crate::builder::KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![model_node, argument],
        limit: None,
        detail: Some("rsync remote shell is not statically recoverable".to_string()),
    });
}

/// One transfer endpoint: whether the operand stayed unresolved, and the slot
/// its read-side or write-side effect landed in so the pairing can be
/// recorded.
struct Endpoint {
    unknown: bool,
    slot: Option<u32>,
    /// An ambiguous source may instead be a local file this copy reads.
    local_read: Option<u32>,
}

#[derive(Clone, Copy)]
struct EmitOptions<'a> {
    source: bool,
    delete: bool,
    recursive: bool,
    /// The copy reads what a local source's links lead to, below it as well
    /// as at it.
    follow_links: bool,
    /// The names a recursive local source skips below it.
    excluded_names: Option<&'a Attrs>,
}

fn emit(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    target: Target,
    options: EmitOptions<'_>,
) -> Endpoint {
    // A destination whose host a substitution spells stays the remote
    // endpoint it names; a source that may be local also sends a local file.
    let unknown = matches!(target, Target::Unknown(_))
        || options.source && matches!(target, Target::MaybeRemote(_));
    let (operation, resource, local) = match (target, options.source) {
        (Target::Local(resource), true) => ("filesystem.read", resource, true),
        (Target::Local(resource), false) => ("filesystem.write", resource, true),
        (
            Target::Remote(resource) | Target::MaybeRemote(resource) | Target::Unknown(resource),
            true,
        ) => ("network.download", resource, false),
        (
            Target::Remote(resource) | Target::MaybeRemote(resource) | Target::Unknown(resource),
            false,
        ) => ("network.upload", resource, false),
    };
    // A destination-pruning transfer is a synchronization: the write and the
    // removal it drives carry the same marker whether the destination is a
    // local tree or a remote endpoint.
    let mut attributes = std::collections::BTreeMap::new();
    if options.delete && !options.source {
        attributes.insert("delete".to_string(), AttrValue::Bool(true));
    }
    if options.source && local {
        attributes.extend(program_input_attrs());
        if options.recursive {
            attributes.insert("recursive".to_string(), AttrValue::Bool(true));
            if let Some(excluded) = options.excluded_names {
                attributes.extend(excluded.clone());
            }
        }
        // A copy that does not follow links sends or skips the link itself.
        attributes.insert(
            "follow_links".to_string(),
            AttrValue::Bool(options.follow_links),
        );
    } else if !options.source && local {
        attributes.extend(program_output_attrs());
    }
    let slot = if local {
        fs_arg_effect(
            builder,
            ctx,
            model_node,
            index,
            &ctx.argv[index as usize],
            operation,
            resource.clone(),
            attributes,
        )
    } else {
        arg_effect(
            builder,
            ctx,
            model_node,
            index,
            operation,
            resource.clone(),
            attributes,
        )
    };
    if options.delete && !options.source && local {
        fs_arg_effect(
            builder,
            ctx,
            model_node,
            index,
            &ctx.argv[index as usize],
            "filesystem.delete",
            resource,
            std::collections::BTreeMap::from([
                ("active".into(), AttrValue::Bool(true)),
                ("delete".into(), AttrValue::Bool(true)),
                ("dry_run".into(), AttrValue::Bool(false)),
                ("recursive".into(), AttrValue::Bool(true)),
                ("contents_only".into(), AttrValue::Bool(true)),
            ]),
        );
    } else if options.delete && !options.source && !unknown {
        remote_delete(builder, ctx, model_node, index);
    }
    // An ambiguous source that is not `host:path` names a local file, whose
    // bytes the copy sends; which file is not known.
    let local_read = (unknown && options.source)
        .then(|| {
            fs_arg_effect(
                builder,
                ctx,
                model_node,
                index,
                &ctx.argv[index as usize],
                "filesystem.read",
                ResourceExpr::Unresolved {
                    family: effinterp_proto::ResourceFamily::new("filesystem"),
                },
                program_input_attrs(),
            )
        })
        .flatten();
    if unknown {
        let arg = arg_node(builder, ctx, index);
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_TRANSFER_TARGET,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem"), Domain::new("network")],
            provenance: vec![arg, model_node],
            limit: None,
            detail: Some(format!(
                "transfer operand {} (arg {index}) may be a local path or a remote endpoint",
                ctx.argv[index as usize].render_raw()
            )),
        });
    }
    Endpoint {
        unknown,
        slot,
        local_read,
    }
}

fn remote_delete(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
) {
    let argument = arg_node(builder, ctx, index);
    let destination = ctx.argv[index as usize].as_literal().and_then(|text| {
        let (host, path) = text.split_once(':')?;
        (!host.is_empty()
            && !host.contains(['/', '[', ']'])
            && !path.is_empty()
            && !path.starts_with(':')
            && !path.contains(['~', '$', '`', '*', '?', '[', ']', '\\', '\'', '"']))
        .then_some((host, path))
    });
    let Some((host, path)) = destination else {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_TRANSFER_TARGET,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![model_node, argument],
            limit: None,
            detail: Some(
                "rsync deletion destination requires a resolved remote host and filesystem path"
                    .into(),
            ),
        });
        return;
    };
    // Project the invocation's receiver-side behavior into its remote realm.
    // This model scope adds no fabricated server argv or process launch effect.
    let transition = Transition::exec(
        ctx.argv.iter().map(word_resource).collect(),
        ctx.argv.to_vec(),
    )
    .kind(ExecutionEdgeKind::ToolModel)
    .realm(ExecutionRealm::Remote {
        endpoint: host.into(),
    })
    .cwd(Some(ResourceExpr::Parameter { name: "cwd".into() }), None)
    .source_cwd(None)
    .runtime_cwd(None);
    let Some(frame) = ctx
        .nest
        .begin(builder, transition, &[model_node, argument], ctx.depth)
    else {
        return;
    };
    let resource = resolve_fs_word_with_cwd(
        &Word::literal(path),
        Some(ResourceExpr::Parameter { name: "cwd".into() }),
    );
    arg_effect(
        builder,
        ctx,
        frame.scope,
        index,
        "filesystem.delete",
        resource,
        std::collections::BTreeMap::from([
            ("active".into(), AttrValue::Bool(true)),
            ("delete".into(), AttrValue::Bool(true)),
            ("dry_run".into(), AttrValue::Bool(false)),
            ("recursive".into(), AttrValue::Bool(true)),
            ("contents_only".into(), AttrValue::Bool(true)),
        ]),
    );
    frame.end(builder);
}

/// What rsync selects below its source operands.
struct SourceSelection<'a> {
    recursive: bool,
    file_lists: &'a [(u32, &'a Word)],
    /// Filter rules in command-line order; the first rule a name matches
    /// decides it.
    filters: &'a [FilterRule<'a>],
    /// Whether every argv word is literal, so no symbolic word can be a filter
    /// option.
    literal_argv: bool,
}

/// One rsync filter rule as far as an empty selection can be proved from it.
enum FilterRule<'a> {
    /// A literal `--exclude PAT`, `--include '- PAT'`, `-f '- PAT'` or
    /// `-f 'exclude PAT'`.
    Exclude(&'a str),
    /// A literal `--include PAT`, `--exclude '+ PAT'`, `-f '+ PAT'` or
    /// `-f 'include PAT'`, which adds a rule without touching earlier ones.
    Include,
    /// A rule that may rebuild the list: a clear (`!`), a merge or dir-merge,
    /// a modified rule, a rule file, or a symbolic value.
    Unread,
}

fn filter_rules<'a>(flags: &'a [crate::models::args::Flag<'a>]) -> Vec<FilterRule<'a>> {
    flags
        .iter()
        .filter_map(|flag| {
            let value = flag.value.as_ref().and_then(Word::as_literal);
            Some(match (flag.name, value) {
                // Either option takes a `+ ` or `- ` prefix as the rule's
                // type and `!` as a clear; only an unprefixed pattern gets
                // the option's own type.
                ("--exclude" | "--include", Some("!")) => FilterRule::Unread,
                ("--exclude" | "--include", Some(pattern)) => {
                    if let Some(pattern) = pattern.strip_prefix("- ") {
                        FilterRule::Exclude(pattern)
                    } else if pattern.starts_with("+ ") || flag.name == "--include" {
                        FilterRule::Include
                    } else {
                        FilterRule::Exclude(pattern)
                    }
                }
                ("--filter" | "-f", Some(rule)) => {
                    if let Some(pattern) = rule
                        .strip_prefix("- ")
                        .or_else(|| rule.strip_prefix("exclude "))
                    {
                        FilterRule::Exclude(pattern)
                    } else if rule.starts_with("+ ") || rule.starts_with("include ") {
                        FilterRule::Include
                    } else {
                        FilterRule::Unread
                    }
                }
                (
                    "--exclude" | "--include" | "--filter" | "-f" | "--include-from"
                    | "--exclude-from",
                    _,
                ) => FilterRule::Unread,
                _ => return None,
            })
        })
        .collect()
}

/// `--remove-source-files` makes the sender delete every non-directory it
/// transferred; the source directories stay. A recursive transfer so empties a
/// source tree, a flat one deletes the named files. A `--files-from` list
/// selects unread names, so the deletion is unresolved rather than the source
/// base. Nothing is transferred, so nothing deleted, only when an exclude of
/// every name (`*`, `/*`, `**`) comes before any include, over a literal
/// command line with no rule that could rebuild the list; any other filter
/// keeps the deletion and says it may be narrower.
fn remove_source_files(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    operands: &[(u32, &Word)],
    selection: SourceSelection<'_>,
) {
    let SourceSelection {
        recursive,
        file_lists,
        filters,
        literal_argv,
    } = selection;
    let Some((_, sources)) = operands.split_last() else {
        return;
    };
    if !file_lists.is_empty() {
        // The list's own boundary states the unread selection.
        for (index, _) in file_lists {
            arg_effect(
                builder,
                ctx,
                model_node,
                *index,
                "filesystem.delete",
                ResourceExpr::Unresolved {
                    family: effinterp_proto::ResourceFamily::new("filesystem"),
                },
                std::collections::BTreeMap::from([(
                    "recursive".into(),
                    AttrValue::Bool(recursive),
                )]),
            );
        }
        return;
    }
    // Earlier excludes only remove names, so the first exclude of every name
    // decides every name no include came before. Only a literal command line
    // whose every rule is a plain include or exclude is read: a clear, merge
    // or rule file could rebuild the list.
    let excludes_everything = literal_argv
        && filters
            .iter()
            .all(|rule| !matches!(rule, FilterRule::Unread))
        && filters
            .iter()
            .take_while(|rule| matches!(rule, FilterRule::Exclude(_)))
            .any(|rule| {
                matches!(rule, FilterRule::Exclude(pattern) if {
                    let pattern = pattern.trim_start_matches('/');
                    !pattern.is_empty() && pattern.chars().all(|character| character == '*')
                })
            });
    if excludes_everything {
        return;
    }
    if !filters.is_empty() {
        builder.boundary(Boundary {
            reason: BoundaryReason::MODEL_COVERAGE,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "rsync filter rules may narrow the files --remove-source-files deletes".into(),
            ),
        });
    }
    for (index, source) in sources {
        match classify(source, ctx.cwd_resource()) {
            Target::Local(resource) => {
                let mut attributes = std::collections::BTreeMap::from([(
                    "recursive".into(),
                    AttrValue::Bool(recursive),
                )]);
                if recursive {
                    attributes.insert("contents_only".into(), AttrValue::Bool(true));
                }
                fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    source,
                    "filesystem.delete",
                    resource,
                    attributes,
                );
            }
            _ => {
                let argument = arg_node(builder, ctx, *index);
                builder.boundary(Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node, argument],
                    limit: None,
                    detail: Some(
                        "rsync --remove-source-files deletion on a remote or unresolved sender is unmodeled"
                            .into(),
                    ),
                });
            }
        }
    }
}

/// `--chmod` sets the permissions of the entries rsync transfers into a local
/// destination, so it is a permission change there. Each comma-separated item
/// is a chmod mode, octal or symbolic, applied to directories with a `D`
/// prefix, to files with `F`, and to both without one; repeated `--chmod`
/// values apply in order. The change states each grant an item provably
/// makes, and a boundary when a value is not a literal mode or leaves a grant
/// to the umask.
fn destination_chmod(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    resource: ResourceExpr,
    modes: &[(u32, &Word)],
) {
    use crate::permission_mode::{Dialect, Grants, Mode, apply_symbolic, established, granted};
    let mut directories = Mode::unchanged();
    let mut files = Mode::unchanged();
    let mut literal = true;
    for item in modes.iter().flat_map(|(_, mode)| match mode.as_literal() {
        Some(mode) => mode.split(',').map(Some).collect(),
        None => vec![None],
    }) {
        let Some(item) = item else {
            literal = false;
            continue;
        };
        let (applies_to_directories, applies_to_files, mode) = match item.split_at_checked(1) {
            Some(("D", mode)) => (true, false, mode),
            Some(("F", mode)) => (false, true, mode),
            _ => (true, true, item),
        };
        for (applies, state) in [
            (applies_to_directories, &mut directories),
            (applies_to_files, &mut files),
        ] {
            if !applies {
                continue;
            }
            if !mode.is_empty() && mode.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
                match u32::from_str_radix(mode, 8) {
                    Ok(mode) => *state = Mode::numeric(mode),
                    Err(_) => literal = false,
                }
            } else if !apply_symbolic(state, mode, Dialect::Chmod) {
                literal = false;
            }
        }
    }
    let (directories, files) = (directories.grants(), files.grants());
    let combined: Grants = std::array::from_fn(|grant| match (directories[grant], files[grant]) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    });
    let mut attributes =
        std::collections::BTreeMap::from([("action".into(), AttrValue::String("chmod".into()))]);
    attributes.extend(granted(combined).map(|grant| (grant.into(), AttrValue::Bool(true))));
    fs_arg_effect(
        builder,
        ctx,
        model_node,
        index,
        &ctx.argv[index as usize],
        "filesystem.metadata",
        resource,
        attributes,
    );
    if !literal || !established(combined) {
        builder.boundary(Boundary {
            reason: BoundaryReason::MODEL_COVERAGE,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "rsync --chmod is not a literal mode, or leaves a permission to the umask or the prior mode, so what it grants is unknown"
                    .into(),
            ),
        });
    }
}

struct Rsync;

impl CommandModel for Rsync {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "rsync/rsync@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["rsync"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let value_flags = [
            "-e",
            "--rsh",
            "--rsync-path",
            "-T",
            "--temp-dir",
            "--exclude-from",
            "--files-from",
            "--exclude",
            "--include",
            "--filter",
            "-f",
            "--include-from",
            "--chmod",
            "--chown",
            "--usermap",
            "--groupmap",
            "--log-file",
            "--log-file-format",
            "--partial-dir",
            "--backup-dir",
            "--suffix",
            "--compare-dest",
            "--copy-dest",
            "--link-dest",
            "--bwlimit",
            "--timeout",
            "--contimeout",
            "--port",
            "--address",
            "--sockopts",
            "--max-size",
            "--min-size",
            "--max-delete",
            "--block-size",
            "-B",
            "--modify-window",
            "--checksum-choice",
            "--iconv",
            "--out-format",
            "--password-file",
            "--remote-option",
            "-M",
            "--outbuf",
            "--skip-compress",
            "--compress-level",
            "--info",
            "--debug",
            "--protocol",
            "--write-batch",
            "--only-write-batch",
            "--read-batch",
        ];
        let scanned = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                value_flags: &value_flags,
                known_flags: &[
                    "-a",
                    "--archive",
                    "-r",
                    "--recursive",
                    "--no-recursive",
                    "--no-r",
                    "-d",
                    "--dirs",
                    "--no-dirs",
                    "--no-d",
                    "-v",
                    "--verbose",
                    "-h",
                    "--human-readable",
                    "-z",
                    "--compress",
                    "-q",
                    "--quiet",
                    "-P",
                    "--partial",
                    "--progress",
                    "-l",
                    "--links",
                    "-L",
                    "--copy-links",
                    "-p",
                    "--perms",
                    "-t",
                    "--times",
                    "-g",
                    "--group",
                    "-o",
                    "--owner",
                    "-D",
                    "--devices",
                    "--specials",
                    "-H",
                    "--hard-links",
                    "-A",
                    "--acls",
                    "-X",
                    "--xattrs",
                    "-c",
                    "--checksum",
                    "-u",
                    "--update",
                    // Skips existing destination files but still creates missing ones.
                    "--ignore-existing",
                    "-b",
                    "--backup",
                    "--numeric-ids",
                    "--delete",
                    "--delete-before",
                    "--delete-during",
                    "--del",
                    "--delete-delay",
                    "--delete-after",
                    "--delete-excluded",
                    "--ignore-errors",
                    "--force",
                    "--remove-source-files",
                    "-n",
                    "--dry-run",
                    "--list-only",
                    "--help",
                    "--version",
                ],
                allow_abbreviation: false,
            },
            true,
        );
        let mut invalid = scanned.unknown_flags.clone();
        for flag in &scanned.flags {
            if value_flags.contains(&flag.name) && flag.value.is_none()
                || !value_flags.contains(&flag.name)
                    && ctx.argv[flag.index as usize].literal_prefix().contains('=')
            {
                invalid.push((flag.index, ctx.argv[flag.index as usize].render_raw()));
            }
        }
        if !invalid.is_empty() {
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem", "network", "process"],
                &invalid,
            );
            return;
        }
        if scanned.has(&["--help", "--version"]) {
            return;
        }
        let operands = &scanned.operands;
        let remote_to_remote = operands.split_last().is_some_and(|((_, dest), sources)| {
            matches!(
                classify(dest, None),
                Target::Remote(_) | Target::MaybeRemote(_)
            ) && sources
                .iter()
                .any(|(_, source)| matches!(classify(source, None), Target::Remote(_)))
        });
        if remote_to_remote || scanned.has(&["--only-write-batch", "--read-batch"]) {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("network")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "rsync batch mode or remote-to-remote operands are unsupported".into(),
                ),
            });
            return;
        }
        let mut directories = false;
        let mut recursive = false;
        for flag in &scanned.flags {
            match flag.name {
                "-a" | "--archive" if !scanned.has(&["--files-from"]) => recursive = true,
                "-r" | "--recursive" => recursive = true,
                "--no-recursive" | "--no-r" => recursive = false,
                "-d" | "--dirs" => directories = true,
                "--no-dirs" | "--no-d" => directories = false,
                _ => {}
            }
        }
        let delete = (directories || recursive)
            && scanned.has(&[
                "--delete",
                "--delete-before",
                "--delete-during",
                "--del",
                "--delete-delay",
                "--delete-after",
                "--delete-excluded",
            ])
            && !scanned.has(&["--max-delete", "--backup-dir", "-b", "--backup"]);
        let no_op = scanned.has(&["-n", "--dry-run", "--list-only"]);
        let local_no_op = no_op
            && operands.len() >= 2
            && operands.iter().all(|(_, operand)| {
                matches!(classify(operand, ctx.cwd_resource()), Target::Local(_))
            });
        if local_no_op {
            let (_, sources) = operands.split_last().unwrap();
            for (index, source) in sources {
                emit(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    classify(source, ctx.cwd_resource()),
                    EmitOptions {
                        source: true,
                        delete: false,
                        recursive: false,
                        follow_links: false,
                        excluded_names: None,
                    },
                );
            }
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        } else if no_op || operands.len() < 2 {
            builder.boundary(Boundary {
                reason: BoundaryReason::MODEL_COVERAGE,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("network")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("rsync listing or dry-run metadata exchange is unmodeled".into()),
            });
        } else {
            let file_lists = scanned.values_of(&["--files-from"]);
            let mut unresolved_sources = Vec::new();
            for (index, list) in &file_lists {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    list,
                    "filesystem.read",
                    program_input_attrs(),
                );
                if let Some(source) = arg_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    "filesystem.read",
                    ResourceExpr::Unresolved {
                        family: effinterp_proto::ResourceFamily::new("filesystem"),
                    },
                    std::collections::BTreeMap::from([
                        (
                            "access_purpose".into(),
                            AttrValue::String("program_input".into()),
                        ),
                        ("recursive".into(), AttrValue::Bool(true)),
                    ]),
                ) {
                    unresolved_sources.push(source);
                }
            }
            // rsync matches a pattern without `/` against each name's final
            // component and the first matching rule decides, so literal
            // excludes skip their names only when no include may come first
            // and no unread rule (a clear, merge or rule file) may rebuild
            // the list, over a command line with no symbolic word.
            let filters = filter_rules(&scanned.flags);
            let literal_argv = ctx.argv.iter().all(|word| word.as_literal().is_some());
            let excluded_names = if file_lists.is_empty()
                && literal_argv
                && filters
                    .iter()
                    .all(|rule| matches!(rule, FilterRule::Exclude(_)))
            {
                super::archive::excluded_names(filters.iter().filter_map(|rule| match rule {
                    FilterRule::Exclude(pattern) => Some(*pattern),
                    _ => None,
                }))
            } else {
                None
            };
            let certified = scanned.flags.iter().all(|flag| {
                matches!(
                    flag.name,
                    "-a" | "--archive"
                        | "-r"
                        | "--recursive"
                        | "--no-recursive"
                        | "--no-r"
                        | "-d"
                        | "--dirs"
                        | "--no-dirs"
                        | "--no-d"
                        | "-v"
                        | "--verbose"
                        | "-q"
                        | "--quiet"
                        | "-z"
                        | "--compress"
                        | "-p"
                        | "--perms"
                        | "-t"
                        | "--times"
                        | "-g"
                        | "--group"
                        | "-o"
                        | "--owner"
                        | "-l"
                        | "--links"
                        | "-L"
                        | "--copy-links"
                        | "-h"
                        | "--human-readable"
                )
            });
            transfer(
                builder,
                ctx,
                model_node,
                operands,
                TransferOptions {
                    delete,
                    certified,
                    certified_download: certified && !recursive && !directories,
                    recursive_source: recursive || !file_lists.is_empty(),
                    // `-L` sends what links lead to; otherwise rsync copies a
                    // link as a link (`-l`) or skips it.
                    follow_links: scanned.has(&["-L", "--copy-links"]),
                    additional_sources: &unresolved_sources,
                    excluded_names,
                },
            );
            let modes = scanned.values_of(&["--chmod"]);
            if !modes.is_empty()
                && let Some((index, destination)) = operands.last()
                && let Target::Local(resource) = classify(destination, ctx.cwd_resource())
            {
                destination_chmod(builder, ctx, model_node, *index, resource, &modes);
            }
            if scanned.has(&["--remove-source-files"]) {
                remove_source_files(
                    builder,
                    ctx,
                    model_node,
                    operands,
                    SourceSelection {
                        recursive,
                        file_lists: &file_lists,
                        filters: &filters,
                        literal_argv,
                    },
                );
            }
            if !file_lists.is_empty() {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        affected_resource: Some(ResourceExpr::Unresolved {
                            family: effinterp_proto::ResourceFamily::new("filesystem"),
                        }),
                        callee: None,
                        domains: vec![Domain::new("filesystem")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some(
                            "rsync source paths are selected by an unobserved file list".into(),
                        ),
                    },
                    CoverageLevel::Partial,
                );
            }
        }
        if scanned.has(&["--max-delete", "--backup-dir", "-b", "--backup"]) {
            builder.boundary(Boundary {
                reason: BoundaryReason::MODEL_COVERAGE,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("rsync backup or bounded deletion selection is unmodeled".into()),
            });
        }

        let Some(remote_host) = operands.iter().find_map(|(_, operand)| {
            remote_host(operand).or_else(|| {
                matches!(classify(operand, None), Target::Unknown(_))
                    .then(|| Word::new(vec![WordPart::Unknown]))
            })
        }) else {
            return;
        };
        if let Some((index, command)) = scanned.values_of(&["--rsync-path"]).into_iter().next() {
            let argument = arg_node(builder, ctx, index);
            if has_unknown(command) {
                unrecoverable_rsync_shell(builder, model_node, argument);
            } else {
                nest_remote_shell(
                    builder,
                    ctx,
                    &[model_node, argument],
                    command.render_raw(),
                    remote_host.render_raw(),
                );
            }
        }
        if let Some((index, command)) = scanned.values_of(&["-e", "--rsh"]).into_iter().next() {
            let argument = arg_node(builder, ctx, index);
            let Some(mut words) = command.as_literal().and_then(split_rsync_shell) else {
                unrecoverable_rsync_shell(builder, model_node, argument);
                return;
            };
            words.push(remote_host);
            ctx.nest_exec(builder, &words, ctx.cwd, None, &[model_node, argument]);
        }
    }
}

struct Scp;

impl CommandModel for Scp {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "openssh/scp@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["scp"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                value_flags: &["-i", "-o", "-l", "-P", "-c", "-F", "-J", "-S", "-D", "-X"],
                known_flags: &[
                    "-2", "-3", "-4", "-6", "-A", "-B", "-C", "-O", "-p", "-q", "-R", "-r", "-s",
                    "-T", "-v",
                ],
                allow_abbreviation: false,
            },
            true,
        );
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "network", "process"],
            &scanned.unknown_flags,
        );
        if !scanned.unknown_flags.is_empty() {
            // An unresolved option can change whether SCP reaches the operands.
            return;
        }
        let operands = &scanned.operands;
        let certified = scanned.flags.iter().all(|flag| {
            matches!(
                flag.name,
                "-r" | "-p" | "-q" | "-v" | "-C" | "-4" | "-6" | "-B"
            )
        });
        transfer(
            builder,
            ctx,
            model_node,
            operands,
            TransferOptions {
                delete: false,
                certified,
                certified_download: false,
                recursive_source: scanned.has(&["-r"]),
                // scp copies what a link leads to, including the links a
                // recursive copy meets below its sources.
                follow_links: true,
                additional_sources: &[],
                excluded_names: None,
            },
        );
        if operands.len() < 2
            || operands
                .iter()
                .all(|(_, word)| matches!(classify(word, ctx.cwd_resource()), Target::Local(_)))
        {
            return;
        }
        if let Some((index, program)) = scanned
            .values_of(&["-D"])
            .into_iter()
            .last()
            .or_else(|| scanned.values_of(&["-S"]).into_iter().last())
        {
            let argument = arg_node(builder, ctx, index);
            // These switches name one executable, never a shell command line.
            // Its SSH/SFTP protocol arguments are not a recoverable script.
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "process.exec",
                program.as_literal().map_or_else(
                    || ResourceExpr::Unresolved {
                        family: effinterp_proto::ResourceFamily::new("process"),
                    },
                    |program| ResourceExpr::Concrete {
                        identity: crate::paths::executable_identity(program, ctx.cwd),
                    },
                ),
                std::collections::BTreeMap::from([
                    ("source".into(), AttrValue::String("file".into())),
                    ("program".into(), AttrValue::String(program.render_raw())),
                ]),
            );
            opaque_source_with_provenance(
                builder,
                &[model_node, argument],
                &["environment", "filesystem", "network", "process"],
                "scp custom transport executable is not available as source",
            );
            return;
        }
        let mut configured = std::collections::BTreeSet::new();
        for (index, option) in scanned.values_of(&["-o"]) {
            let prefix = option.literal_prefix();
            let Some(separator) = prefix.find(|c: char| c == '=' || c.is_ascii_whitespace()) else {
                if option.as_literal().is_none() {
                    let argument = arg_node(builder, ctx, index);
                    opaque_source_with_provenance(
                        builder,
                        &[model_node, argument],
                        &["environment", "filesystem", "network", "process"],
                        "scp SSH configuration option is not recoverable",
                    );
                }
                continue;
            };
            let key = prefix[..separator].to_ascii_lowercase();
            if !configured.insert(key.clone())
                || !matches!(key.as_str(), "proxycommand" | "knownhostscommand")
            {
                // scp prepends PermitLocalCommand=no before the user's options.
                continue;
            }
            let value = prefix[separator..].trim_start_matches([' ', '\t']);
            let value = value
                .strip_prefix('=')
                .unwrap_or(value)
                .trim_start_matches([' ', '\t']);
            let offset = prefix.len() - value.len();
            let command = super::args::strip_literal_prefix(option, offset);
            if command
                .as_literal()
                .is_some_and(|value| value.eq_ignore_ascii_case("none"))
            {
                continue;
            }
            let argument = arg_node(builder, ctx, index);
            code_execution(
                effinterp_proto::RequestAssurance::Conservative,
                builder,
                ctx,
                model_node,
                Some(index),
                "argument",
                Default::default(),
            );
            let Some(source) = command
                .as_literal()
                .filter(|source| !source.contains('%') && !source.contains("${"))
            else {
                opaque_source_with_provenance(
                    builder,
                    &[model_node, argument],
                    &["environment", "filesystem", "network", "process"],
                    "scp SSH command contains unrecoverable source or connection tokens",
                );
                continue;
            };
            if key == "knownhostscommand" {
                if let Some(words) = ssh_command_argv(source) {
                    ctx.nest_exec(builder, &words, ctx.cwd, None, &[model_node, argument]);
                } else {
                    opaque_source_with_provenance(
                        builder,
                        &[model_node, argument],
                        &["environment", "filesystem", "network", "process"],
                        "KnownHostsCommand has invalid quoting",
                    );
                }
            } else {
                // Reuse the SSH model's shell handoff, retaining this option's span.
                let words = [ctx.argv[0].clone(), Word::literal("-o"), option.clone()];
                let provenance = [vec![], vec![argument], vec![argument]];
                let mut option_ctx = ctx.without_stdin();
                option_ctx.argv = &words;
                option_ctx.argv_provenance = Some(&provenance);
                crate::models::subprocess::ssh_option_commands(builder, &option_ctx, model_node);
            }
        }
    }
}

/// OpenSSH's argv_split grammar for KnownHostsCommand: quotes group words,
/// only quotes, backslashes and unquoted spaces can be backslash-escaped.
/// Shell operators and expansions remain literal arguments.
fn ssh_command_argv(source: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\'
            && chars.peek().is_some_and(|next| {
                matches!(next, '\'' | '"' | '\\') || quote.is_none() && *next == ' '
            })
        {
            word.push(chars.next().unwrap());
            started = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
            started = true;
        } else if quote.is_none() && matches!(ch, ' ' | '\t') {
            if started {
                words.push(Word::literal(std::mem::take(&mut word)));
                started = false;
            }
        } else {
            word.push(ch);
            started = true;
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(Word::literal(word));
    }
    Some(words)
}

/// The last operand is the destination (write/upload); the rest are sources
/// (read/download).
struct TransferOptions<'a> {
    delete: bool,
    certified: bool,
    certified_download: bool,
    recursive_source: bool,
    follow_links: bool,
    additional_sources: &'a [u32],
    /// The names every recursive local source skips below it.
    excluded_names: Option<Attrs>,
}

fn transfer(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    operands: &[(u32, &Word)],
    options: TransferOptions<'_>,
) {
    let TransferOptions {
        delete,
        certified,
        certified_download,
        recursive_source,
        follow_links,
        additional_sources,
        excluded_names,
    } = options;
    // Endpoint identity may stay patterned, but an unresolved control word
    // could change the source/destination grammar and cannot certify bytes.
    let certified = certified
        && builder.execution_is_exact(builder.current_execution())
        && operands
            .last()
            .is_some_and(|(_, destination)| destination.as_literal().is_some())
        && operands.iter().all(|(_, word)| {
            word.as_literal().is_some()
                || matches!(word.parts.as_slice(), [WordPart::Glob(pattern)]
                    if pattern.split(['*', '?', '[', '{', '@', '!', '+']).next()
                        .is_some_and(|prefix| !prefix.starts_with('-') && prefix.contains('/')))
        });
    let mut unknown = false;
    if let Some(((dest_index, dest), sources)) = operands.split_last() {
        let destination = classify(dest, ctx.cwd_resource());
        let sources_classified = sources
            .iter()
            .map(|(_, source)| classify(source, ctx.cwd_resource()))
            .collect::<Vec<_>>();
        let certified = certified
            && (matches!(destination, Target::Remote(_))
                && sources_classified
                    .iter()
                    .all(|source| matches!(source, Target::Local(_)))
                || certified_download
                    && sources_classified.len() == 1
                    && matches!(sources_classified[0], Target::Remote(_))
                    && matches!(destination, Target::Local(_)));
        // Each source keeps its own pairing to the single destination; a
        // symbolic operand still publishes the other side's known effect.
        let mut source_slots = additional_sources
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<_>>();
        source_slots.extend(sources.iter().zip(&sources_classified).flat_map(
            |((index, _), source)| {
                let endpoint = emit(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    source.clone(),
                    EmitOptions {
                        source: true,
                        delete: false,
                        recursive: recursive_source,
                        follow_links,
                        excluded_names: excluded_names.as_ref(),
                    },
                );
                unknown |= endpoint.unknown;
                [endpoint.slot, endpoint.local_read]
            },
        ));
        let destination = emit(
            builder,
            ctx,
            model_node,
            *dest_index,
            destination,
            EmitOptions {
                source: false,
                delete,
                recursive: false,
                follow_links: false,
                excluded_names: None,
            },
        );
        unknown |= destination.unknown;
        if let Some(destination) = destination.slot {
            for source in source_slots.into_iter().flatten() {
                builder.transfer_binding(if certified && !unknown {
                    crate::resource_transfer::TransferBinding::exact(source, destination)
                } else {
                    crate::resource_transfer::TransferBinding::new(source, destination)
                });
            }
        }
    }
    let coverage = if unknown {
        CoverageLevel::Partial
    } else {
        CoverageLevel::Full
    };
    builder.declare_coverage(Domain::new("filesystem"), coverage);
    builder.declare_coverage(Domain::new("network"), coverage);
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
}
