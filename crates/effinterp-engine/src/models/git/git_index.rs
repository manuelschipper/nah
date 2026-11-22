//! git commands that change the index from the work tree: `git add`
//! stages files, `git rm` removes them and `git mv` moves them.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, attrs};
use crate::word::{Word, WordPart};

use super::git_options::{git_controls_known, git_options, parsed_effective_flag};
use super::git_pathspec::git_request_path;
use super::{SubCtx, git_argument_boundary};

/// The attributes of an index write that touches only the entries at or
/// below the literal pathspecs `operands`: `index_paths`, each joined to the
/// cwd. A pattern, pathspec magic, a dynamic operand, no operand or an
/// unknown cwd states nothing.
pub(super) fn limited_index_write<'w>(
    s: &SubCtx,
    operands: impl IntoIterator<Item = Option<&'w str>>,
) -> Attrs {
    let Some(cwd) = s.cwd.as_deref() else {
        return Attrs::new();
    };
    let mut paths = Vec::new();
    for operand in operands {
        match operand {
            Some(path)
                if !path.is_empty()
                    && !path.starts_with(':')
                    && !path.contains(['*', '?', '[', '\\']) =>
            {
                paths.push(crate::paths::join_cwd(cwd, path));
            }
            _ => return Attrs::new(),
        }
    }
    if paths.is_empty() {
        return Attrs::new();
    }
    Attrs::from([("index_paths".into(), super::string_list(&paths))])
}

/// `git add` writes the index and reads each file it stages.
pub(super) fn git_add(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.index_write", Attrs::new());
    // Staging hashes each file's contents into the object store; a dry run,
    // a refresh or an intent to add records none.
    let parsed = super::git_content_selection::add_options(s);
    let staged = if super::git_content_selection::add_stages_contents(&parsed) {
        crate::models::common::program_input_attrs()
    } else {
        Attrs::new()
    };
    // `--chmod +x` gives its option a value, not a pathspec.
    for (index, path) in &parsed.operands {
        s.filesystem_path_effect(
            builder,
            s.rest_offset - 1 + index,
            path,
            "filesystem.read",
            staged.clone(),
        );
    }
    // A directory or pattern operand, or -A or -u, names no file itself:
    // what the pathspecs stage is the repository selection the host observes.
    if let Some(mut selection) = super::git_content_selection::content_selection(builder, "add", s)
    {
        selection.extend(staged);
        s.repo_effect(builder, "git.read", selection);
    }
}

/// `git rm` removes each path from the index and, without `--cached`,
/// deletes the working file; `-r` makes that deletion recursive. It
/// deletes only tracked files (`tracked_only`), and without `-f` refuses
/// one that differs from HEAD or the index, so only `force` may lose an
/// edit. Nah reads those attributes of the delete in the bridge
/// (`unforced_git_rm`, `deleted_state` in `bridge/guard_host_facts.rs`) and
/// in save-then-run (`discards` in `nah-cli/src/save_then_run.rs`), and the
/// `git.worktree_discard` of mode `rm` that `forced_removal_selection`
/// states in both (`pathspec_discards` there).
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
    let limited = if git_controls_known(&parsed)
        && parsed.unknown_flags.is_empty()
        && !parsed.has(&["--pathspec-from-file"])
    {
        limited_index_write(s, parsed.operands.iter().map(|(_, word)| word.as_literal()))
    } else {
        Attrs::new()
    };
    s.repo_effect(builder, "git.index_write", limited);
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
        let force = !git_controls_known(&parsed)
            || parsed_effective_flag(&parsed, &["-f", "--force"], &["--no-force"]);
        // A pathspec Git reads as a pattern or with magic may match files
        // anywhere below where it starts, so its removal is recursive.
        let pattern = |path: &Word| git_pattern(s, path);
        for (index, path) in s.operands(false) {
            s.filesystem_path_effect(
                builder,
                index,
                path,
                "filesystem.delete",
                attrs(&[
                    ("recursive", recursive || pattern(path)),
                    ("tracked_only", true),
                    ("force", force),
                ]),
            );
        }
        if force {
            forced_removal_selection(builder, s, &parsed, &pattern);
        }
    }
}

/// Whether Git may read `path` as other than one plain path: a literal it
/// reads as a pattern or with magic, or a word holding a value Nah did not
/// recover, which may spell either. Shell glob text is not: the shell hands
/// Git the plain names it expands to.
fn git_pattern(s: &SubCtx, path: &Word) -> bool {
    fn unrecovered(part: &WordPart) -> bool {
        match part {
            WordPart::Env(_) | WordPart::Value(_) | WordPart::Unknown => true,
            WordPart::Union(words) => words.iter().any(|word| word.parts.iter().any(unrecovered)),
            WordPart::Literal(_) | WordPart::Glob(_) => false,
        }
    }
    match path.as_literal() {
        Some(_) => git_request_path(s, path).is_none(),
        None => path.parts.iter().any(unrecovered),
    }
}

/// What a forced `git rm` selects where its deletes cannot say. It takes
/// the tracked changes of every file its pathspecs match. Where Git reads
/// any of them as a pattern or with magic, or one may be either, every
/// pathspec, plain ones too, is stated as a `git.worktree_discard` of mode
/// `rm`, for Git to list before the removal runs, beside the boundary that
/// names them unknown (as a `git checkout` of such pathspecs is); one Nah
/// cannot spell leaves that selection unknown. A pathspec file, which Nah
/// does not read, or an option the model does not know may select anything
/// in the work tree, so the selection then also holds all of it (`:/`).
fn forced_removal_selection(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    parsed: &crate::models::args::Scanned<'_>,
    pattern: &dyn Fn(&Word) -> bool,
) {
    let operands = s.operands(false);
    // A dynamic operand is still an operand; an unknown option is not.
    let whole = parsed.has(&["--pathspec-from-file"]) || !git_controls_known(parsed);
    if !whole && !operands.iter().any(|(_, path)| pattern(path)) {
        return;
    }
    git_argument_boundary(
        builder,
        s,
        "git rm pathspec selection is not a known plain path",
    );
    let mut discard = attrs(&[("force", true)]);
    discard.insert("discard_mode".into(), AttrValue::String("rm".into()));
    let top = Word::literal(":/");
    for (index, path) in operands
        .into_iter()
        .chain(whole.then_some((s.sub_index, &top)))
    {
        s.git_path_effect(
            builder,
            index,
            path,
            "git.worktree_discard",
            discard.clone(),
        );
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
