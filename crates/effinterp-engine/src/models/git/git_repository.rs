//! Which repository a git invocation selects: the work tree and git dir its
//! global options and environment name, discovery from the cwd, and the
//! submodule a `submodule foreach` command runs in.

use effinterp_proto::{ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::paths::{fs_word_uses_cwd, resolve_fs_word, resolve_fs_word_with_cwd};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::git_config::config_parameters;
use super::{Globals, SubCtx};

/// A repository expression and the foreach call that binds the
/// `<git_submodule>` it names; each call binds its own submodules.
#[derive(Clone, Copy)]
pub(super) struct ScopedRepo<'a> {
    expr: &'a ResourceExpr,
    binding: Option<usize>,
}

impl<'a> ScopedRepo<'a> {
    pub(super) fn new(expr: &'a ResourceExpr, binding: Option<usize>) -> Self {
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
pub(super) fn selects_by_discovery(
    builder: &PlanBuilder,
    ctx: &InvocationCtx<'_>,
    globals: &Globals,
) -> bool {
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
pub(super) fn superproject_and_submodule(
    builder: &PlanBuilder,
    a: ScopedRepo<'_>,
    b: ScopedRepo<'_>,
) -> bool {
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
pub(super) fn foreach_submodule() -> ResourceExpr {
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

pub(super) fn git_dir_resource(repo: &ResourceExpr) -> Option<&ResourceExpr> {
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

pub(super) fn worktree_resource(repo: &ResourceExpr) -> Option<&ResourceExpr> {
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

pub(super) fn git_environment_path(
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
pub(super) fn discovers_from_worktree(globals: &Globals, ctx: &InvocationCtx<'_>) -> bool {
    globals.work_tree.is_none()
        && globals.git_dir.is_none()
        && ctx.environment_value("GIT_WORK_TREE").is_none()
        && ctx.environment_value("GIT_DIR").is_none()
}

/// Git discovers the repository from the invocation's own directory: it
/// discovers from the worktree, and any `-C` spells that same directory.
pub(super) fn root_uses_invocation_cwd(globals: &Globals, ctx: &InvocationCtx<'_>) -> bool {
    discovers_from_worktree(globals, ctx)
        && globals
            .repo_dir
            .as_ref()
            .is_none_or(|dir| ctx.resolve_fs_word(&dir.word) == invocation_directory(ctx))
}

pub(super) fn worktree_base(globals: &Globals, ctx: &InvocationCtx) -> ResourceExpr {
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

pub(super) fn repo_expr(globals: &Globals, ctx: &InvocationCtx) -> ResourceExpr {
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

pub(super) fn repo_uses_cwd(globals: &Globals) -> bool {
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
pub(super) fn effective_cwd<'a>(globals: &'a Globals, ctx: &'a InvocationCtx) -> Option<String> {
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

/// Git stops before running the subcommand on an empty `--git-dir` ("not a
/// git repository") or `--work-tree` ("the empty string is not a valid
/// path"), in either spelling; `-C ''` stays in the cwd.
pub(super) fn empty_repository_global(s: &SubCtx<'_>) -> bool {
    [&s.globals.git_dir, &s.globals.work_tree]
        .into_iter()
        .flatten()
        .any(|global| global.word.as_literal() == Some(""))
}

/// `:/` selects the top of the working tree. Unless the work tree is named,
/// git discovers that top upward from the start directory, which the plan
/// cannot see: a selection keeps the start directory and states the
/// discovered top as `selects_top` for the host to resolve.
pub(super) fn top_discovered(s: &SubCtx<'_>) -> bool {
    s.globals.work_tree.is_none() && s.ctx.environment_value("GIT_WORK_TREE").is_none()
}
