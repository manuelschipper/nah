//! `git checkout`, `git switch` and `git restore`: which options and pathspecs
//! were spelled, and the worktree paths they discard.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, arg_node, attrs};
use crate::word::{Word, WordPart};

use super::git_options::{
    git_controls_known, git_effective_flag, git_help_requested, git_operands_are_not_options,
    git_options,
};
use super::git_pathspec::{
    foreach_whole_tree, git_request_path, insert_selection, is_worktree_root_pathspec,
    matches_everything,
};
use super::git_repository::{
    discovers_from_worktree, empty_repository_global, root_uses_invocation_cwd, top_discovered,
};
use super::{SubCtx, git_argument_boundary, request_attrs};

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

pub(super) fn checkout(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
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

/// git-checkout-index(1) writes index entries over the working tree: `-a`
/// every entry below the cwd (checkout-index.c `checkout_all` skips entries
/// outside the prefix), as `checkout -- .` selects, or the named files. It
/// replaces an existing file only with `-f`. `--temp`, `--prefix` and
/// `--stdin` write elsewhere or read their paths elsewhere and are not
/// modeled. Returns false for a form the model does not read.
pub(super) fn checkout_index(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
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
