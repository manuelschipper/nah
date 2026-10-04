//! `git reset` and `git read-tree`: the reset request, and the working
//! tree a hard reset discards.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::Attrs;

use super::git_options::{
    git_controls_known, git_help_requested, git_operands_known, git_options, parsed_effective_flag,
};
use super::git_repository::empty_repository_global;
use super::{SubCtx, git_argument_boundary, request_attrs};

pub(super) fn reset(builder: &mut PlanBuilder, s: &SubCtx) {
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

/// git-read-tree(1) reads trees into the index, and with `-u` checks the
/// result out. `--reset -u` does so even when that loses working tree
/// changes or untracked files in the way, which is `git reset --hard` to the
/// tree without moving HEAD; `-m -u` refuses to lose them. Returns false for
/// the forms left to the unmodeled-subcommand boundary.
pub(super) fn read_tree(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
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
