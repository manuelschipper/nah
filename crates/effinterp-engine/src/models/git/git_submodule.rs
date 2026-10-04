//! `git submodule add`, `deinit` and `foreach`: the clone a new submodule
//! downloads, the submodule working trees a deinit discards, and the
//! command foreach runs in each submodule.

use effinterp_proto::{AttrValue, ProvenanceRef, ResourceExpr};

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, arg_node, attrs};
use crate::word::Word;

use super::git_fetch::clone_destination;
use super::git_options::{
    git_controls_known, git_operands_are_not_options, git_operands_known, git_options,
    parsed_effective_flag,
};
use super::git_pathspec::git_request_path;
use super::git_repository::{discovers_from_worktree, root_uses_invocation_cwd};
use super::{SubCtx, git_argument_boundary, request_attrs, string_list};

/// `git submodule add <repository> [<path>]` clones the repository
/// into the path and stages it with `.gitmodules`.
pub(super) fn submodule_add(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[
                "-b",
                "--branch",
                "--name",
                "--reference",
                "--ref-format",
                "--depth",
            ],
            known_flags: &["-f", "--force", "-q", "--quiet", "--progress"],
            allow_abbreviation: true,
        },
    );
    if !git_controls_known(&parsed) || !git_operands_known(&parsed) {
        git_argument_boundary(builder, s, "git submodule add options are not fully known");
    }
    s.repo_effect(builder, "git.remote_sync", attrs(&[("clone", true)]));
    s.repo_effect(builder, "git.index_write", Attrs::new());
    let source = s.remote_network(builder, "network.download");
    let operands = parsed
        .operands
        .iter()
        .skip(1)
        .map(|(index, word)| (s.rest_offset - 1 + index, *word))
        .collect::<Vec<_>>();
    clone_destination(builder, s, &operands, source);
}

/// `git submodule deinit` discards the working tree of each submodule
/// it names, or of every submodule with `--all`.
pub(super) fn submodule_deinit(builder: &mut PlanBuilder, s: &SubCtx) {
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
            let known = git_controls_known(&parsed) && git_operands_are_not_options(s, &operands);
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

/// git-submodule(1) `foreach [--recursive] <command>` runs the command in
/// each checked-out submodule, as git runs a shell alias: through the shell
/// when it has shell syntax, directly otherwise. A lone command word also
/// sees `$name`, `$sm_path`, `$displaypath`, `$sha1` and `$toplevel`. Which
/// submodules exist and where is not observed. Returns false when the words
/// before the command cannot be read.
pub(super) fn submodule_foreach(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
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
