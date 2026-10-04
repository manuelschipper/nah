//! git: subcommand dispatch with a small effect taxonomy mapped from nah's
//! guard families. Operations (domain "git"): read, index_write,
//! worktree_write, worktree_discard, ref_update, history_rewrite,
//! recovery_destroy, config_write, remote_sync.
//!
//! This file owns the invocation: the global options, alias expansion, the
//! `SubCtx` effect emitters and the `dispatch` table. Each subcommand's
//! effects live in the `git/git_*.rs` module `dispatch` calls, named for
//! the question it answers (`git_recovery`, `git_history_rewrite`,
//! `git_read`); the helpers they share are `git_repository` (which
//! repository is selected), `git_options` (option scanning), `git_pathspec`
//! (what a pathspec selects) and `git_config` (the configuration read).

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionInputRole, ExecutionPhase, ExecutionSelector, Modality, Operation,
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, matches_long_option, scan_literal};
use crate::models::common::{
    Attrs, RuntimeSourceLanguage, arg_node, attrs, fs_arg_effect, fs_arg_node,
    program_output_attrs, runtime_searched_source,
};
use crate::models::net::parse_endpoint;
use crate::models::{CommandModel, InvocationCtx};
use crate::paths::{fs_word_uses_cwd, resolve_fs_word};
use crate::value::unresolved_resource;
use crate::word::Word;

mod git_checkout;
mod git_clean;
mod git_config;
mod git_config_command;
mod git_fetch;
mod git_history_rewrite;
mod git_index;
mod git_object_read;
mod git_options;
mod git_pathspec;
pub(super) mod git_push;
mod git_read;
mod git_recovery;
mod git_ref_update;
mod git_remote;
mod git_repository;
mod git_reset;
mod git_submodule;
mod git_worktree;

use git_checkout::{checkout, checkout_index};
use git_clean::clean;
use git_config::{
    Alias, ConfigEntry, GIT_ALIAS_DEPTH, command_parameters, config_env_setting,
    config_option_setting, config_value, config_values, expand_includes, inherited_configs,
    repository_aliases, split_alias,
};
use git_config_command::{printed_configuration, record_config_write};
use git_fetch::{clone_destination, fetch_or_pull};
use git_history_rewrite::{GIT_FILTER_REPO, GitFilterRepo, history_rewrite};
use git_index::{git_add, git_mv, git_rm};
use git_object_read::{
    archive, cat_file, record_shown_object_reads, shown_objects, tree_or_ref_query,
};
use git_options::{git_controls_known, git_options};
use git_pathspec::is_worktree_root_pathspec;
use git_push::{PushArgs, push, send_pack};
use git_read::{
    PrintedFileContent, diff_no_index, diff_no_index_files, grep_arguments, implicit_no_index,
    is_read_form, printed_file_content, read_form,
};
use git_recovery::{gc, maintenance, prune, reflog, repack, stash};
use git_ref_update::{branch_or_tag, update_ref, update_ref_stdin};
use git_remote::remote;
use git_repository::{
    effective_cwd, repo_expr, repo_uses_cwd, selects_by_discovery, worktree_resource,
};
use git_reset::{read_tree, reset};
use git_submodule::{submodule_add, submodule_deinit, submodule_foreach};
use git_worktree::worktree;

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
        // A patch and an annotated file print the lines of each working
        // file the command reads; a diff or blame that reads only recorded
        // history has no filesystem read for the binding to carry.
        if let Some((index, word)) = sub
            && let Some(sub @ ("diff" | "blame" | "grep")) = word.as_literal()
        {
            let rest = &argv[*index as usize + 1..];
            if printed_file_content(sub, rest) != PrintedFileContent::Lines
                || sub == "grep" && grep_arguments(rest).summary
            {
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
        // `git config` and `git remote` print values of the configuration
        // file they read.
        if sub
            .and_then(|(_, word)| word.as_literal())
            .is_some_and(|sub| matches!(sub, "config" | "remote"))
        {
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
        self.operands_past_values(&[], after_double_dash)
    }

    /// [`Self::operands`] for a subcommand whose `value_flags` each take the
    /// next word as their value, which is then not an operand.
    fn operands_past_values(
        &self,
        value_flags: &'static [&'static str],
        after_double_dash: bool,
    ) -> Vec<(u32, &Word)> {
        let scanned = scan_literal(
            &self.ctx.argv[self.rest_offset as usize - 1..],
            &FlagSpec {
                value_flags,
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
            None => unresolved_resource("network"),
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
        // A remote named rather than spelled as a URL takes its endpoint from
        // configuration. The files are not read, so the unresolved endpoint
        // above stands for them; a URL this call's own configuration or an
        // earlier `git remote add` in the subject may have set is one more
        // endpoint the transfer may reach.
        if endpoint.is_none()
            && let Some(name) = operands.first().and_then(|(_, word)| word.as_literal())
        {
            let variables: &[&str] = if operation == "network.upload" {
                &["pushurl", "url"]
            } else {
                &["url"]
            };
            let mut configured = Vec::new();
            for variable in variables {
                for identity in config_values(self.globals, &format!("remote.{name}.{variable}"))
                    .values
                    .into_iter()
                    .flatten()
                    .filter_map(parse_endpoint)
                {
                    if !configured.contains(&identity) {
                        configured.push(identity);
                    }
                }
            }
            for identity in configured {
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new(operation),
                    resource: ResourceExpr::Concrete { identity },
                    attributes: Default::default(),
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: vec![arg, self.model_node],
                });
            }
        }
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        slot
    }
}

/// The git subcommand dispatch table: plans the effects of subcommand `sub`.
/// Arm order is the contract: a guarded arm (a read form, `submodule add`)
/// takes the subcommand before the plain arm of the same name below it.
fn dispatch(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    match sub {
        "merge-base" | "ls-tree" | "diff-tree" | "show-ref" => tree_or_ref_query(builder, sub, s),
        "archive" => archive(builder, s),
        "cat-file" => cat_file(builder, s),
        "show"
            if {
                let objects = shown_objects(s);
                !objects.is_empty() && objects.len() == s.operands(false).len()
            } =>
        {
            record_shown_object_reads(builder, s);
        }
        "diff" if diff_no_index(s.rest) || implicit_no_index(s) => {
            diff_no_index_files(builder, sub, s)
        }
        "status" | "log" | "diff" | "show" | "blame" | "rev-parse" | "describe" | "shortlog"
        | "ls-files" | "grep" | "rev-list" | "name-rev" | "whatchanged" | "branch" | "tag"
        | "remote" | "stash" | "reflog" | "config" | "worktree"
            if is_read_form(sub, s) =>
        {
            read_form(builder, sub, s)
        }
        "add" => git_add(builder, s),
        "rm" => git_rm(builder, s),
        "mv" => git_mv(builder, s),
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
        "branch" | "tag" => branch_or_tag(builder, sub, s),
        "push" => push(builder, s),
        "fetch" | "pull" => fetch_or_pull(builder, sub, s),
        // Cloning downloads the remote into a new local directory.
        "clone" => {
            s.repo_effect(builder, "git.remote_sync", attrs(&[("clone", true)]));
            let source = s.remote_network(builder, "network.download");
            clone_destination(builder, s, &s.operands(false), source);
        }
        "submodule"
            if s.operands(false).first().and_then(|(_, w)| w.as_literal()) == Some("add") =>
        {
            submodule_add(builder, s)
        }
        "gc" => gc(builder, s),
        "reflog" => reflog(builder, s),
        "rebase" | "filter-branch" | "filter-repo" => history_rewrite(builder, sub, s),
        "stash" => stash(builder, s),
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
            // A single name, `get` and `list` print values all the same.
            printed_configuration(builder, sub, s);
        }
        "remote" => remote(builder, s),
        "worktree" => worktree(builder, s),
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
            update_ref(builder, s)
        }
        "submodule"
            if s.operands(false).first().and_then(|(_, w)| w.as_literal()) == Some("deinit")
                && (s.scanned(&["--all"]).has(&["--all"]) || s.operands(false).len() > 1) =>
        {
            submodule_deinit(builder, s)
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
        "prune" => prune(builder, s),
        _ => unmodeled_subcommand_boundary(
            builder,
            s,
            &format!("git subcommand {sub:?} (possibly an alias)"),
        ),
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
