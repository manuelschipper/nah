//! The files Git reads a message from. The bytes become part of an object
//! in the repository, as a file `git add` stages does, so each file is read
//! as program input. The commands differ in which of their options they
//! read, what `-` names and where a relative path starts:
//!
//! - `commit` reads the last `-F`/`--file` (`--no-file` drops it), or else,
//!   with no other message, the last `-t`/`--template`; a dry run, which
//!   `--short`, `--long` and `--porcelain` imply, reads neither. `tag`
//!   reads its last `-F`/`--file`. Both take `-` as standard input and a
//!   relative path from the directory Git was started in.
//! - `merge` reads every `-F`/`--file`, and opens `-` as a file there too.
//! - `notes add`, `append` and `edit` read every `-F`/`--file`, and
//!   `commit-tree` every `-F`, taking `-` as standard input. They open a
//!   relative path from the work tree's top level, where Git's setup has
//!   moved before the command reads its options. `commit-tree` also reads
//!   standard input when the message it gathered is empty, which only a
//!   nonempty literal `-m` rules out here.
//!
//! A path that opens descriptor 0 (`/dev/stdin`) is standard input for all.

use crate::builder::PlanBuilder;
use crate::models::args::{Flag, FlagSpec, Scanned};
use crate::models::common::{Attrs, fs_arg_effect, program_input_attrs};
use crate::paths::resolve_fs_word;

use super::git_options::git_options;
use super::{SubCtx, unmodeled_subcommand_boundary};

/// Where a relative message file starts.
enum Base {
    /// The directory Git was started in, which `-C` changes.
    Start,
    /// The work tree's top level.
    Top,
}

/// Read the message file `flag` names, or note standard input as consumed.
/// Call it after the subcommand's first effect: a model notes standard input
/// as consumed by the effects its stage has emitted so far.
fn read_message_file(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    flag: &Flag,
    dash_is_stdin: bool,
    base: &Base,
) {
    let Some(value) = &flag.value else {
        return;
    };
    if value.as_literal().is_some_and(|path| {
        path == "-" && dash_is_stdin || crate::models::subprocess::names_stdin(path)
    }) {
        builder.note_stdin_consumed();
        return;
    }
    let index = s.rest_offset - 1 + flag.value_index.unwrap_or(flag.index);
    let relative = value
        .as_literal()
        .is_some_and(|path| !crate::paths::is_absolute(path));
    match base {
        Base::Top if relative => {
            for top in top_candidates(builder, s) {
                fs_arg_effect(
                    builder,
                    s.ctx,
                    s.model_node,
                    index,
                    value,
                    "filesystem.read",
                    resolve_fs_word(value, Some(&top)),
                    program_input_attrs(),
                );
            }
        }
        _ => {
            s.filesystem_path_effect(
                builder,
                index,
                value,
                "filesystem.read",
                program_input_attrs(),
            );
        }
    }
}

/// The directories that may be the work tree's top level. When Git finds
/// the repository by discovery and the configuration does not establish
/// its top level, Git may be started anywhere below it, so the start
/// directory and each directory above it is a candidate. A named work tree
/// or git dir starts the work tree where `SubCtx::cwd` already stands.
fn top_candidates(builder: &mut PlanBuilder, s: &SubCtx) -> Vec<String> {
    let Some(cwd) = s.cwd.clone() else {
        return Vec::new();
    };
    if !super::git_repository::discovers_from_worktree(s.globals, s.ctx) {
        return vec![cwd];
    }
    let established =
        super::git_config::file_configs(builder, s.ctx, s.globals, s.model_node, s.sub_index)
            .ok()
            .flatten()
            .and_then(|(config, entries)| s.hook_top(&config, &entries));
    if let Some(top) = established {
        return vec![top];
    }
    let mut candidates = vec![cwd];
    loop {
        let parent = crate::paths::parent_dir(candidates.last().unwrap());
        if parent.is_empty() || candidates.contains(&parent) {
            return candidates;
        }
        candidates.push(parent);
    }
}

/// The last of the file options `names`, unless `negation` comes after it.
fn last_file<'a>(parsed: &'a Scanned, names: &[&str], negation: &str) -> Option<&'a Flag<'a>> {
    parsed
        .flags
        .iter()
        .rev()
        .find(|flag| names.contains(&flag.name) || flag.name == negation)
        .filter(|flag| flag.name != negation)
}

/// The message file of `git commit`, from the options its dispatch arm
/// scanned.
pub(super) fn commit_message(builder: &mut PlanBuilder, s: &SubCtx, parsed: &Scanned) {
    if parsed.has(&["--dry-run", "--short", "--long", "--porcelain"]) {
        return;
    }
    if let Some(file) = last_file(parsed, &["-F", "--file"], "--no-file") {
        read_message_file(builder, s, file, true, &Base::Start);
    } else if !parsed.has(&[
        "-m",
        "--message",
        "-C",
        "--reuse-message",
        "-c",
        "--reedit-message",
    ]) && let Some(template) = last_file(parsed, &["-t", "--template"], "--no-template")
    {
        read_message_file(builder, s, template, true, &Base::Start);
    }
}

/// The message file of `git tag`, whose other effects its dispatch arm
/// plans.
pub(super) fn tag_message(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[
                "-m",
                "--message",
                "-F",
                "--file",
                "-u",
                "--local-user",
                "--cleanup",
                "--trailer",
            ],
            known_flags: &[
                "-a",
                "--annotate",
                "-s",
                "--sign",
                "--no-sign",
                "-f",
                "--force",
                "-e",
                "--edit",
                "--no-edit",
                "--create-reflog",
            ],
            allow_abbreviation: true,
        },
    );
    if let Some(file) = last_file(&parsed, &["-F", "--file"], "--no-file") {
        read_message_file(builder, s, file, true, &Base::Start);
    }
}

/// The message files of `git merge`, whose other effects its dispatch arm
/// plans.
pub(super) fn merge_message(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[
                "-m",
                "--message",
                "-F",
                "--file",
                "-s",
                "--strategy",
                "-X",
                "--strategy-option",
                "--cleanup",
                "--into-name",
            ],
            known_flags: &[
                "--commit",
                "--no-commit",
                "-e",
                "--edit",
                "--no-edit",
                "--ff",
                "--no-ff",
                "--ff-only",
                "--squash",
                "--no-squash",
                "-n",
                "--stat",
                "--no-stat",
                "--no-log",
                "--signoff",
                "--no-signoff",
                "-q",
                "--quiet",
                "-v",
                "--verbose",
                "--autostash",
                "--no-autostash",
                "--allow-unrelated-histories",
                "--no-verify",
            ],
            allow_abbreviation: true,
        },
    );
    for flag in &parsed.flags {
        if matches!(flag.name, "-F" | "--file") {
            read_message_file(builder, s, flag, false, &Base::Start);
        }
    }
}

/// `git notes add`, `append` and `edit` write the notes ref from a message;
/// the other notes forms stay unmodeled.
pub(super) fn notes(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[
                "--ref",
                "-m",
                "--message",
                "-F",
                "--file",
                "-c",
                "--reedit-message",
                "-C",
                "--reuse-message",
            ],
            known_flags: &[
                "-f",
                "--force",
                "--allow-empty",
                "-e",
                "--edit",
                "--no-edit",
                "--no-separator",
                "--stripspace",
                "--no-stripspace",
            ],
            allow_abbreviation: true,
        },
    );
    if matches!(
        parsed
            .operands
            .first()
            .and_then(|(_, word)| word.as_literal()),
        Some("add" | "append" | "edit")
    ) {
        s.repo_effect(builder, "git.ref_update", Attrs::new());
        for flag in &parsed.flags {
            if matches!(flag.name, "-F" | "--file") {
                read_message_file(builder, s, flag, true, &Base::Top);
            }
        }
    }
    unmodeled_subcommand_boundary(builder, s, "git subcommand \"notes\" (possibly an alias)");
}

/// `git commit-tree` reads the tree it is given and writes a commit object
/// from the message; the object is otherwise left unmodeled.
pub(super) fn commit_tree(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-p", "-m", "-F"],
            known_flags: &["--no-gpg-sign"],
            allow_abbreviation: true,
        },
    );
    s.repo_effect(builder, "git.read", Attrs::new());
    for flag in &parsed.flags {
        if flag.name == "-F" {
            read_message_file(builder, s, flag, true, &Base::Top);
        }
    }
    let message_given = parsed.flags.iter().any(|flag| {
        flag.name == "-m"
            && flag
                .value
                .as_ref()
                .and_then(|value| value.as_literal())
                .is_some_and(|message| !message.is_empty())
    });
    if !message_given {
        builder.note_stdin_consumed();
    }
    unmodeled_subcommand_boundary(
        builder,
        s,
        "git subcommand \"commit-tree\" (possibly an alias)",
    );
}
