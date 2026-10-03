//! git: subcommand dispatch with a small effect taxonomy mapped from nah's
//! guard families. Operations (domain "git"): read, index_write,
//! worktree_write, worktree_discard, ref_update, history_rewrite,
//! recovery_destroy, config_write, remote_sync.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionInputRole, ExecutionPhase, ExecutionSelector, Modality, Operation,
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::models::args::{FlagSpec, Scanned, matches_long_option, scan, scan_literal};
use crate::value::unresolved_resource;

use crate::builder::PlanBuilder;
use crate::models::common::{
    Attrs, RuntimeSourceLanguage, arg_node, attrs, fs_arg_effect, fs_arg_node, opaque_source,
    program_output_attrs, runtime_searched_source,
};
use crate::models::net::parse_endpoint;
use crate::models::{CommandModel, InvocationCtx};
use crate::paths::{fs_word_uses_cwd, resolve_fs_word, resolve_fs_word_with_cwd};
use crate::resource_transfer::TransferBinding;
use crate::word::Word;

mod git_checkout;
mod git_config;
pub(super) mod git_push;

use git_checkout::checkout;
use git_config::{
    Alias, ConfigEntry, GIT_ALIAS_DEPTH, command_parameters, config_env_setting,
    config_option_setting, config_parameters, config_value, config_values, expand_includes,
    git_bool, inherited_configs, repository_aliases, split_alias,
};
use git_push::{PushArgs, push, send_pack};

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

fn git_environment_path(
    ctx: &InvocationCtx<'_>,
    name: &str,
    base: Option<ResourceExpr>,
) -> Option<ResourceExpr> {
    match ctx.environment_value(name) {
        Some(ResourceExpr::Literal { value }) => Some(resolve_fs_word_with_cwd(
            &Word::literal(value),
            base.or_else(|| ctx.cwd_resource()),
        )),
        Some(_) => Some(unresolved_resource("filesystem")),
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
        .or_else(|| git_environment_path(ctx, "GIT_WORK_TREE", Some(base.clone())))
        .unwrap_or(base.clone());
    let git_dir = globals
        .git_dir
        .as_ref()
        .map(|git_dir| resolve_fs_word_with_cwd(&git_dir.word, Some(base.clone())));
    let git_dir = git_dir.or_else(|| git_environment_path(ctx, "GIT_DIR", Some(base.clone())));
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
            match git_environment_path(ctx, "GIT_WORK_TREE", Some(worktree_base(globals, ctx))) {
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
            match git_environment_path(ctx, "GIT_WORK_TREE", Some(worktree_base(globals, ctx))) {
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
    enum UpdateRefTransactionState {
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
    let mut state = UpdateRefTransactionState::Open;
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
                && matches!(
                    state,
                    UpdateRefTransactionState::Open | UpdateRefTransactionState::Started
                ))
            .then_some(state),
            "start" | "prepare" | "commit" | "abort" if !arguments.is_empty() => None,
            "start" => matches!(
                state,
                UpdateRefTransactionState::Open | UpdateRefTransactionState::Closed
            )
            .then_some(UpdateRefTransactionState::Started),
            "prepare" => matches!(
                state,
                UpdateRefTransactionState::Open | UpdateRefTransactionState::Started
            )
            .then_some(UpdateRefTransactionState::Prepared),
            "commit" | "abort" if state == UpdateRefTransactionState::Closed => None,
            "commit" => {
                commit(builder, &mut queued);
                Some(UpdateRefTransactionState::Closed)
            }
            "abort" => {
                queued.clear();
                Some(UpdateRefTransactionState::Closed)
            }
            "update" | "create" | "delete" | "verify"
                if matches!(
                    state,
                    UpdateRefTransactionState::Open | UpdateRefTransactionState::Started
                ) =>
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
    } else if !died && state == UpdateRefTransactionState::Open {
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

/// `:/` selects the top of the working tree. Unless the work tree is named,
/// git discovers that top upward from the start directory, which the plan
/// cannot see: a selection keeps the start directory and states the
/// discovered top as `selects_top` for the host to resolve.
fn top_discovered(s: &SubCtx<'_>) -> bool {
    s.globals.work_tree.is_none() && s.ctx.environment_value("GIT_WORK_TREE").is_none()
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
