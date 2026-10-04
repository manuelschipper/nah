//! `git worktree`: the linked worktrees `remove` and `prune` discard.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, attrs};
use crate::word::Word;

use super::git_options::{
    git_controls_known, git_operands_are_not_options, git_options, parsed_effective_flag,
};
use super::git_pathspec::git_request_path;
use super::git_repository::{discovers_from_worktree, root_uses_invocation_cwd};
use super::{SubCtx, git_argument_boundary, request_attrs, string_list};

/// `git worktree remove <worktree>` discards one linked worktree and
/// `git worktree prune` every stale one; the other actions write.
pub(super) fn worktree(builder: &mut PlanBuilder, s: &SubCtx) {
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
