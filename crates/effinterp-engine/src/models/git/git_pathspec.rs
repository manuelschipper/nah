//! What a git pathspec selects: the top of the working tree, everything
//! below the cwd, or one plain path a discard request can name.

use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::models::common::Attrs;
use crate::paths::resolve_fs_word;
use crate::word::Word;

use super::git_config::git_bool;
use super::git_repository::{foreach_submodule, worktree_resource};
use super::{SubCtx, string_list};

/// `:/` or its long-magic spelling `:(top)`: the whole working tree. So is
/// a top-anchored pattern that matches every path under the pathspec mode in
/// effect, such as `:/*` or `:(top,glob)**/*`; a mode the model cannot read
/// may leave it matching everything, so it counts too.
pub(super) fn is_worktree_root_pathspec(s: &SubCtx<'_>, path: &Word) -> bool {
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
pub(super) fn positive_top_relative_pathspec(path: &Word) -> bool {
    path.as_literal()
        .and_then(|text| text.strip_prefix(":/").or(text.strip_prefix(":(top)")))
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with(['!', '^', ':']))
}

/// A `submodule foreach` command starts in its submodule's top with
/// `GIT_DIR=.git` and no work tree named, so git takes that start directory
/// as the top of the working tree (git(1) `GIT_DIR`). Pathspecs selecting
/// everything below it select that whole submodule tree, though the plan
/// cannot name its path.
pub(super) fn foreach_whole_tree(
    builder: &PlanBuilder,
    s: &SubCtx<'_>,
    paths: &[(u32, &Word)],
) -> bool {
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

pub(super) fn git_request_path(s: &SubCtx<'_>, path: &Word) -> Option<String> {
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
pub(super) fn matches_everything(s: &SubCtx<'_>, path: &Word) -> Option<bool> {
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

/// A discard request's selection: the whole tree, or the selected paths.
pub(super) fn insert_selection(request: &mut Attrs, whole_tree: bool, selection_paths: &[String]) {
    request.insert(
        "scope".into(),
        AttrValue::String(if whole_tree { "whole" } else { "selected" }.into()),
    );
    request.insert("broad".into(), AttrValue::Bool(whole_tree));
    if !whole_tree {
        request.insert("selections".into(), string_list(selection_paths));
    }
}
