//! git history rewrites: `git rebase`, `git filter-branch` and
//! `git filter-repo`, with the commands and filter code they run.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
    ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned};
use crate::models::common::{Attrs, arg_node, attrs, opaque_source};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

use super::git_options::{
    git_effective_flag, git_help_requested, git_operands_known, git_option_values_known,
    git_options, git_options_known,
};
use super::git_repository::{effective_cwd, empty_repository_global, repo_expr};
use super::{ALL_DOMAINS, Git, Globals, SubCtx, dispatch, request_attrs};

/// The one external `git-<name>` program this model dispatches.
pub(super) const GIT_FILTER_REPO: &str = "filter-repo";

/// `git filter-repo` execs the `git-filter-repo` program found on PATH, so
/// running that program directly is the same rewrite of the repository at the
/// working directory.
pub(super) struct GitFilterRepo;

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

/// `git rebase`, `git filter-branch` and `git filter-repo` rewrite the
/// history of the current branch. The history rewrite request is stated
/// only where the options are known and git does not refuse the call
/// before it rewrites anything.
pub(super) fn history_rewrite(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
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
                        && flag
                            .value
                            .as_ref()
                            .and_then(Word::as_literal)
                            .is_some_and(|value| {
                                let negative_number = value.strip_prefix('-').is_some_and(|n| {
                                    let digits =
                                        |text: &str| text.bytes().all(|b| b.is_ascii_digit());
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
                            }))
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
                    && flag
                        .value
                        .as_ref()
                        .and_then(Word::as_literal)
                        .is_some_and(|command| {
                            command.contains('\n')
                                || command
                                    .trim_matches([' ', '\t', '\r', '\x0c', '\x0b'])
                                    .is_empty()
                        })
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
            AttrValue::Bool(git_operands_known(&parsed) && git_option_values_known(&parsed)),
        );
        s.request_effect(builder, "git.history_rewrite_request", request);
        if sub == "rebase" {
            rebase_exec_commands(builder, s, &parsed);
        }
    }
    s.hooks_boundary(builder);
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
