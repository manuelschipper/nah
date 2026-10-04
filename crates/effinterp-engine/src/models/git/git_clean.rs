//! `git clean`: the untracked files a clean request discards, and the
//! pathspecs that select them.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::Attrs;
use crate::word::Word;

use super::git_config::{config_values, git_bool};
use super::git_options::git_options;
use super::git_pathspec::{
    foreach_whole_tree, git_request_path, insert_selection, is_worktree_root_pathspec,
    positive_top_relative_pathspec,
};
use super::git_repository::{
    discovers_from_worktree, empty_repository_global, root_uses_invocation_cwd, top_discovered,
};
use super::{SubCtx, git_argument_boundary, request_attrs};

pub(super) fn clean(builder: &mut PlanBuilder, s: &SubCtx) {
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
