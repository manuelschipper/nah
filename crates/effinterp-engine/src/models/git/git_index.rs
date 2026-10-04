//! git commands that stage working files into the index: `git add`,
//! `git rm` and `git mv`.

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, attrs};

use super::git_options::{git_controls_known, git_options, parsed_effective_flag};
use super::{SubCtx, git_argument_boundary};

/// `git add` writes the index and reads each file it stages.
pub(super) fn git_add(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.index_write", Attrs::new());
    // Staging hashes each file's contents into the object store; a
    // dry run only lists what it would add.
    let staged = if s.scanned(&["-n", "--dry-run"]).has(&["-n", "--dry-run"]) {
        Attrs::new()
    } else {
        crate::models::common::program_input_attrs()
    };
    for (index, path) in s.operands(false) {
        s.filesystem_path_effect(builder, index, path, "filesystem.read", staged.clone());
    }
}

/// `git rm` removes each path from the index and, without `--cached`,
/// deletes the working file; `-r` makes that deletion recursive.
pub(super) fn git_rm(builder: &mut PlanBuilder, s: &SubCtx) {
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
            !flag.starts_with("--") && !parsed.operands.iter().any(|(operand, _)| operand == index)
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

/// `git mv` moves each source entry to the destination: the source
/// entry is deleted and the destination entry written, with no source
/// content read to invent. `filesystem.move` is the semantic layer.
pub(super) fn git_mv(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.index_write", Attrs::new());
    let operands = s.operands(false);
    if let Some(((dest_index, dest), sources)) = operands.split_last() {
        let mut source_slots = Vec::with_capacity(sources.len());
        for (index, source) in sources {
            s.filesystem_path_effect(builder, *index, source, "filesystem.move", Attrs::new());
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
