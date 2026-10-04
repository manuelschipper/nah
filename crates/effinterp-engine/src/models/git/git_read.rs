//! git read forms: which subcommand spellings only read, what file content
//! `git diff`, `git log`, `git blame` and `git grep` print, and the paths
//! whose contents that discloses.

use effinterp_proto::{ObservationOutcome, PathKind, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::models::common::Attrs;
use crate::paths::resolve_fs_word;
use crate::word::Word;

use super::git_config_command::printed_configuration;
use super::git_object_read::record_shown_object_reads;
use super::git_repository::worktree_resource;
use super::{SubCtx, git_argument_boundary};

/// Subcommands that are only sometimes reads: bare/list forms.
pub(super) fn is_read_form(sub: &str, s: &SubCtx) -> bool {
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

/// What a read form writes to stdout about the files it names.
#[derive(PartialEq)]
pub(super) enum PrintedFileContent {
    /// The files' lines: a patch, or an annotated file.
    Lines,
    /// Names, counts or nothing: the command compares without disclosing.
    Summary,
    /// An option this model does not know, which git may reject before it
    /// reads anything, so neither reading is established.
    Unknown,
}

/// git-diff(1) long options that leave what is printed as it was: they
/// select what is compared or how a patch is drawn.
const DIFF_NEUTRAL_OPTIONS: &[&str] = &[
    "--no-index",
    "--cached",
    "--staged",
    "--merge-base",
    "--base",
    "--ours",
    "--theirs",
    "--cc",
    "--combined-all-paths",
    "--exit-code",
    "--indent-heuristic",
    "--no-indent-heuristic",
    "--minimal",
    "--patience",
    "--histogram",
    "--anchored",
    "--diff-algorithm",
    "--submodule",
    "--color",
    "--no-color",
    "--color-moved",
    "--no-color-moved",
    "--color-moved-ws",
    "--no-color-moved-ws",
    "--word-diff",
    "--word-diff-regex",
    "--color-words",
    "--no-renames",
    "--rename-empty",
    "--no-rename-empty",
    "--ws-error-highlight",
    "--full-index",
    "--abbrev",
    "--break-rewrites",
    "--find-renames",
    "--find-copies",
    "--find-copies-harder",
    "--irreversible-delete",
    "--diff-filter",
    "--pickaxe-all",
    "--pickaxe-regex",
    "--find-object",
    "--skip-to",
    "--rotate-to",
    "--relative",
    "--no-relative",
    "--text",
    "--ignore-cr-at-eol",
    "--ignore-space-at-eol",
    "--ignore-space-change",
    "--ignore-all-space",
    "--ignore-blank-lines",
    "--ignore-matching-lines",
    "--inter-hunk-context",
    "--function-context",
    "--ext-diff",
    "--no-ext-diff",
    "--textconv",
    "--no-textconv",
    "--ignore-submodules",
    "--src-prefix",
    "--dst-prefix",
    "--no-prefix",
    "--default-prefix",
    "--line-prefix",
    "--output-indicator-new",
    "--output-indicator-old",
    "--output-indicator-context",
    "--ita-invisible-in-index",
    "--ita-visible-in-index",
];

/// What `git diff` prints, from its options before `--`, read in order as
/// git reads them (diff.c `diff_opt_parse`).
///
/// A patch option (`-p`, `-u`, `-U<n>`, `--binary`, `--patch`, ...) prints
/// the patch beside `--stat`, `--raw` and the other summaries; `-s` and
/// `--no-patch` clear every format given before them, so only a patch option
/// after the last one prints lines. `--name-only` and `--name-status` keep
/// the patch off whatever the order, and `--quiet` prints nothing. Short
/// options without a value combine (`-pu`). `--output=<file>` sends the
/// patch to that file instead. An option outside these, or one git rejects,
/// is unknown.
fn diff_printed_file_content(rest: &[Word]) -> PrintedFileContent {
    let (mut patch, mut summary, mut suppressed) = (false, false, false);
    let (mut names, mut quiet) = (false, false);
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        let Some(text) = word.as_literal() else {
            if word.literal_prefix().starts_with('-') {
                return PrintedFileContent::Unknown;
            }
            continue;
        };
        if text == "--" {
            break;
        }
        let Some(short) = text.strip_prefix('-').filter(|short| !short.is_empty()) else {
            continue;
        };
        if short.starts_with('-') {
            match text.split('=').next().unwrap_or(text) {
                "--patch" | "--binary" | "--patch-with-stat" | "--patch-with-raw" | "--unified" => {
                    patch = true
                }
                "--no-patch" => (patch, summary, suppressed) = (false, false, true),
                "--raw" | "--stat" | "--numstat" | "--shortstat" | "--dirstat" | "--summary"
                | "--compact-summary" | "--cumulative" | "--dirstat-by-file" | "--stat-width"
                | "--stat-name-width" | "--stat-count" | "--stat-graph-width" => summary = true,
                "--name-only" | "--name-status" => names = true,
                "--quiet" => quiet = true,
                // The patch goes to the named file, modeled as a write.
                "--output" if text.len() > "--output=".len() => quiet = true,
                option if DIFF_NEUTRAL_OPTIONS.contains(&option) => {}
                _ => return PrintedFileContent::Unknown,
            }
            continue;
        }
        match short.chars().next() {
            Some('U') => patch = true,
            // These take the rest of the word as their value, or none.
            Some('B' | 'M' | 'C' | 'X' | 'l') => {}
            // These take the rest of the word, or else the next word.
            Some('S' | 'G' | 'O' | 'I') => {
                if short.len() == 1 {
                    words.next();
                }
            }
            _ => {
                for letter in short.chars() {
                    match letter {
                        'p' | 'u' => patch = true,
                        's' => (patch, summary, suppressed) = (false, false, true),
                        'R' | 'a' | 'b' | 'w' | 'W' | 'z' | 'D' | '0' | '1' | '2' | '3' => {}
                        _ => return PrintedFileContent::Unknown,
                    }
                }
            }
        }
    }
    if !quiet && !names && (patch || !(summary || suppressed)) {
        PrintedFileContent::Lines
    } else {
        PrintedFileContent::Summary
    }
}

/// An option that makes `git log`, `git show` or `git diff` print a patch.
fn is_patch_option(option: &str) -> bool {
    matches!(
        option,
        "-p" | "-u" | "--patch" | "--patch-with-stat" | "--patch-with-raw"
    ) || option.starts_with("-U")
        || option.starts_with("--unified")
}

/// What a read form prints about the files it names.
///
/// `git blame` prints each line, with `-s` only dropping the author and time
/// beside it; `--incremental` alone prints the commits without the lines.
/// For `git log` a summary format replaces the patch unless a patch option
/// is also given, and `--name-only` and `--name-status` keep it off.
pub(super) fn printed_file_content(sub: &str, rest: &[Word]) -> PrintedFileContent {
    if sub == "diff" {
        return diff_printed_file_content(rest);
    }
    let options = rest
        .iter()
        .take_while(|word| word.as_literal() != Some("--"))
        .filter_map(Word::as_literal)
        .map(|text| text.split('=').next().unwrap_or(text))
        .collect::<Vec<_>>();
    let summarized = if sub == "blame" {
        options.contains(&"--incremental")
    } else {
        let patch = options.iter().any(|option| is_patch_option(option));
        let names = options
            .iter()
            .any(|option| matches!(*option, "--name-only" | "--name-status"));
        options
            .iter()
            .any(|option| SUMMARY_FORMATS.contains(option))
            && (!patch || names)
    };
    if summarized {
        PrintedFileContent::Summary
    } else {
        PrintedFileContent::Lines
    }
}

/// Git also compares two filesystem paths without `--no-index` when a diff
/// names exactly two paths and either lies outside the work tree
/// (builtin/diff.c `path_inside_repo`). Only a work tree and operands that
/// resolve to concrete paths settle which side they are on.
pub(super) fn implicit_no_index(s: &SubCtx) -> bool {
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

/// `--no-index` before `--`: diff compares two filesystem paths.
pub(super) fn diff_no_index(rest: &[Word]) -> bool {
    rest.iter()
        .take_while(|word| word.as_literal() != Some("--"))
        .any(|word| word.as_literal() == Some("--no-index"))
}

/// A path operand whose file content a read form prints.
struct DisclosedPath<'a> {
    index: u32,
    word: &'a Word,
    /// The printed content comes from recorded history.
    historical: bool,
    /// The command also reads the working file itself.
    working_file: bool,
}

/// git-blame(1) options that take the next word as their value.
const BLAME_VALUE_FLAGS: &[&str] = &[
    "-L",
    "-S",
    "--contents",
    "--ignore-rev",
    "--ignore-revs-file",
    "--date",
    "--since",
    "--encoding",
];

/// The host shows a regular file at a literal path operand.
fn host_shows_regular_file(builder: &mut PlanBuilder, s: &SubCtx, path: &Word) -> bool {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = resolve_fs_word(path, s.cwd.as_deref())
    else {
        return false;
    };
    path.starts_with('/')
        && builder.budget().observations.is_some()
        && builder.is_host_realm()
        && matches!(
            builder.budget().observe_path(&path),
            ObservationOutcome::Path(fact) if fact.kind == PathKind::File
        )
}

/// What a `git grep` names, as positions in the words after `grep`.
pub(super) struct GrepArguments {
    /// It prints file names, counts or nothing instead of matching lines.
    pub(super) summary: bool,
    /// The revisions and pathspecs before `--`, the pattern left out.
    operands: Vec<usize>,
    /// The pathspecs after `--`.
    pathspecs: Vec<usize>,
}

/// `git grep [<options>] [-e] <pattern> [<rev>...] [[--] <pathspec>...]`.
///
/// The first operand is the pattern unless `-e` or `-f` gives one. Short
/// options combine (`-hn`, `-he PATTERN`), and one that takes a value takes
/// the rest of its word or else the next word. `-l`, `-L`, `-c` and `-q`
/// replace the matching lines with names, counts or nothing.
pub(super) fn grep_arguments(rest: &[Word]) -> GrepArguments {
    let mut arguments = GrepArguments {
        summary: false,
        operands: Vec::new(),
        pathspecs: Vec::new(),
    };
    let mut pattern_given = false;
    let mut at = 0;
    while at < rest.len() {
        let text = rest[at].as_literal();
        if text == Some("--") {
            arguments.pathspecs = (at + 1..rest.len()).collect();
            break;
        }
        let Some(option) = text.filter(|text| text.starts_with('-') && text.len() > 1) else {
            // A word that is not literal may still spell an option.
            if text.is_some() || !rest[at].literal_prefix().starts_with('-') {
                arguments.operands.push(at);
            }
            at += 1;
            continue;
        };
        if let Some(long) = option.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            match name {
                "files-with-matches" | "name-only" | "files-without-match" | "count" | "quiet" => {
                    arguments.summary = true
                }
                "max-depth" | "threads" | "max-count" | "after-context" | "before-context"
                | "context"
                    if !value =>
                {
                    at += 1
                }
                _ => {}
            }
        } else {
            for (offset, letter) in option.char_indices().skip(1) {
                match letter {
                    'l' | 'L' | 'c' | 'q' => arguments.summary = true,
                    'e' | 'f' | 'A' | 'B' | 'C' | 'm' => {
                        pattern_given |= matches!(letter, 'e' | 'f');
                        if offset + 1 == option.len() {
                            at += 1;
                        }
                        break;
                    }
                    // The rest of the word is the pager it opens files in.
                    'O' => break,
                    _ => {}
                }
            }
        }
        at += 1;
    }
    if !pattern_given && !arguments.operands.is_empty() {
        arguments.operands.remove(0);
    }
    arguments
}

/// The path operands whose file content a read form prints.
///
/// `git grep` prints the matching lines of each pathspec, from the working
/// tree, or from the index with `--cached`, or from each revision named.
/// Without a pathspec it searches the whole tree and names no path.
///
/// `git diff [<commit>...] [--] [<path>...]` and `git log [<options>] [--]
/// [<path>...]` take pathspecs after the `--` separator git documents for
/// telling a path from a revision. Without the separator git reads an
/// operand as a path when a file is there (setup.c `verify_filename`), so a
/// diff operand the host shows as a regular file is one too: inside a work
/// tree it is a pathspec, and outside one the two files are compared as
/// `--no-index` does. A plain `git log` prints commit metadata and its
/// pathspec only selects commits; the patch modes print the file.
/// `git blame [<rev>] [--] <file>` requires one file operand, so a lone
/// operand is that file.
///
/// A diff reads the working file unless both sides are recorded (the index
/// with `--cached`, two commits, or a range), and a blame reads it when no
/// revision, `--reverse` walk or `--contents` replaces it. Only an operand the host shows as a
/// regular file is that read: a directory or pattern pathspec selects files
/// this model does not enumerate.
fn disclosed_paths<'a>(
    builder: &mut PlanBuilder,
    sub: &str,
    s: &'a SubCtx<'a>,
) -> Vec<DisclosedPath<'a>> {
    if printed_file_content(sub, s.rest) != PrintedFileContent::Lines {
        return Vec::new();
    }
    match sub {
        "diff" => {
            let operands = s.operands(false);
            let paths = if s.rest.iter().any(|word| word.as_literal() == Some("--")) {
                s.operands(true)
            } else {
                operands
                    .iter()
                    .filter(|(_, path)| host_shows_regular_file(builder, s, path))
                    .copied()
                    .collect()
            };
            let commits = operands
                .iter()
                .filter(|(index, _)| !paths.iter().any(|(path, _)| path == index))
                .collect::<Vec<_>>();
            let staged = s
                .scanned(&["--cached", "--staged"])
                .has(&["--cached", "--staged"]);
            // Named commits and the staged tree are compared as recorded;
            // comparing neither compares the working tree.
            let historical = !commits.is_empty() || staged;
            let recorded_only = staged
                || commits.len() > 1
                || commits
                    .iter()
                    .any(|(_, commit)| commit.as_literal().is_none_or(|text| text.contains("..")));
            paths
                .into_iter()
                .map(|(index, word)| DisclosedPath {
                    index,
                    word,
                    historical,
                    working_file: !recorded_only && host_shows_regular_file(builder, s, word),
                })
                .collect()
        }
        "log" | "whatchanged"
            if s.scanned(&["-p", "-u", "--patch"])
                .has(&["-p", "-u", "--patch"])
                || s.rest
                    .iter()
                    .take_while(|word| word.as_literal() != Some("--"))
                    .filter_map(Word::as_literal)
                    .any(|text| is_patch_option(text.split('=').next().unwrap_or(text))) =>
        {
            s.operands(true)
                .into_iter()
                .map(|(index, word)| DisclosedPath {
                    index,
                    word,
                    historical: true,
                    working_file: false,
                })
                .collect()
        }
        "grep" => {
            let grep = grep_arguments(s.rest);
            if grep.summary {
                return Vec::new();
            }
            let recorded = s.scanned(&["--cached"]).has(&["--cached"]);
            let offset = s.rest_offset;
            let operand = |at: &usize| (offset + *at as u32, &s.rest[*at]);
            let separated = s.rest.iter().any(|word| word.as_literal() == Some("--"));
            // Past `--` every operand is a pathspec. Without it git reads an
            // operand as a path when a file is there, as it does for a diff.
            let (paths, revisions): (Vec<_>, Vec<_>) = if separated {
                (
                    grep.pathspecs.iter().map(operand).collect(),
                    grep.operands.iter().map(operand).collect(),
                )
            } else {
                grep.operands
                    .iter()
                    .map(operand)
                    .partition(|(_, path)| host_shows_regular_file(builder, s, path))
            };
            let historical = recorded || !revisions.is_empty();
            // A pathspec the shell still has to expand names files this
            // model cannot spell, so their contents read is not stated.
            if paths.iter().any(|(_, path)| path.as_literal().is_none()) {
                git_argument_boundary(builder, s, "git grep pathspec is not statically known");
            }
            paths
                .into_iter()
                .map(|(index, word)| DisclosedPath {
                    index,
                    word,
                    historical,
                    working_file: !historical && host_shows_regular_file(builder, s, word),
                })
                .collect()
        }
        "blame" => {
            let separated = s.operands_past_values(BLAME_VALUE_FLAGS, true);
            let operands = s.operands_past_values(BLAME_VALUE_FLAGS, false);
            let working_file = operands.len() == 1
                && !s.rest.iter().any(|word| {
                    word.as_literal().is_some_and(|text| {
                        matches!(text.split('=').next(), Some("--contents" | "--reverse"))
                    })
                });
            let file = if !separated.is_empty() {
                separated
            } else if operands.len() == 1 {
                operands
            } else {
                Vec::new()
            };
            file.into_iter()
                .map(|(index, word)| DisclosedPath {
                    index,
                    word,
                    historical: true,
                    working_file,
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// `git diff --no-index <path> <path>` compares two host files, not
/// pathspecs, and its patch prints both files' lines.
pub(super) fn diff_no_index_files(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    let attributes = match printed_file_content(sub, s.rest) {
        PrintedFileContent::Lines => crate::models::common::program_input_attrs(),
        PrintedFileContent::Summary => Attrs::new(),
        PrintedFileContent::Unknown => {
            git_argument_boundary(builder, s, "git diff options are not fully known");
            Attrs::new()
        }
    };
    for (index, path) in s.operands(false) {
        s.filesystem_path_effect(builder, index, path, "filesystem.read", attributes.clone());
    }
}

/// A read form states the repository read, or the contents read of each
/// disclosed path, and for `git config` and `git remote` the printed
/// configuration.
pub(super) fn read_form(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    if sub == "diff" && printed_file_content(sub, s.rest) == PrintedFileContent::Unknown {
        git_argument_boundary(builder, s, "git diff options are not fully known");
    }
    let disclosed = disclosed_paths(builder, sub, s);
    if disclosed.is_empty() {
        s.repo_effect(builder, "git.read", Attrs::new());
    } else {
        for path in disclosed {
            s.path_read(builder, path.index, path.word, path.historical);
            if path.working_file {
                s.filesystem_path_effect(
                    builder,
                    path.index,
                    path.word,
                    "filesystem.read",
                    crate::models::common::program_input_attrs(),
                );
            }
        }
    }
    // `git show COMMIT REV:PATH` prints the file beside the commit.
    if sub == "show" {
        record_shown_object_reads(builder, s);
    }
    if matches!(sub, "config" | "remote") {
        printed_configuration(builder, sub, s);
    }
}
