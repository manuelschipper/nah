//! The repository selection of a Git read that prints or stages file
//! contents. The host can answer these filename questions without running
//! the requested search.

use super::git_options::{
    git_controls_known, git_help_requested, git_options, parsed_effective_flag,
};
use super::git_pathspec::pathspec_options;
use super::git_read::{PrintedFileContent, grep_arguments, printed_file_content};
use super::{SubCtx, string_list};
use crate::builder::PlanBuilder;
use crate::models::args::{Flag, FlagSpec, Scanned};
use crate::models::common::Attrs;
use crate::paths::resolve_fs_word;
use crate::word::Word;
use effinterp_proto::{AttrValue, ObservationOutcome, PathKind, ResourceExpr, ResourceIdentity};

/// Static selection attributes shared by the repository read and its named
/// file reads. Unknown selections retain the evidence already named by the
/// invocation, without claiming to enumerate its files.
pub(super) fn content_selection(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) -> Option<Attrs> {
    let directory = s
        .cwd
        .as_deref()
        .filter(|path| crate::paths::is_absolute(path))?;
    let separated = s.rest.iter().any(|word| word.as_literal() == Some("--"));
    let flags = s
        .rest
        .iter()
        .take_while(|word| word.as_literal() != Some("--"))
        .filter_map(Word::as_literal)
        .collect::<Vec<_>>();
    let mut revisions = Vec::new();
    let mut revision_options = Vec::new();
    // A selection of the whole repository, which `:/` names.
    let repository_root;
    let mut whole_repository = false;
    // Pathspecs read from a file widen the selection to the whole repository.
    let mut pathspecs_from_file = false;
    let (kind, paths) = match sub {
        "grep" => {
            let grep = grep_arguments(s.rest);
            if grep.summary {
                return None;
            }
            let Some(kind) = grep.selection else {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git grep selection options are not observed",
                );
                return None;
            };
            let operands = grep
                .operands
                .iter()
                .map(|at| &s.rest[*at])
                .collect::<Vec<_>>();
            let paths = if separated {
                revisions = operands
                    .into_iter()
                    .map(|word| word.as_literal().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()?;
                grep.pathspecs
                    .iter()
                    .map(|at| &s.rest[*at])
                    .collect::<Vec<_>>()
            } else {
                let first_path = operands
                    .iter()
                    .position(|word| pathspec_operand(builder, s, word));
                let (commits, paths) = operands.split_at(first_path.unwrap_or(operands.len()));
                revisions = commits
                    .iter()
                    .map(|word| word.as_literal().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()?;
                paths.to_vec()
            };
            if !revisions.is_empty() && kind != "tracked" {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git grep revision selection options are not observed",
                );
                return None;
            }
            (
                if revisions.is_empty() {
                    kind
                } else {
                    "revision-grep"
                },
                paths,
            )
        }
        "diff" => {
            if printed_file_content(sub, s.rest) != PrintedFileContent::Lines {
                return None;
            }
            if unobserved_diff_selection(&flags) || flags.contains(&"--cc") {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git diff selection options are not observed",
                );
                return None;
            }
            let operands = s.operands_past_values(
                &[
                    "-S",
                    "-G",
                    "-O",
                    "-I",
                    "--unified",
                    "--diff-filter",
                    "--relative",
                ],
                false,
            );
            let paths = if separated {
                s.operands(true).into_iter().map(|(_, path)| path).collect()
            } else {
                operands
                    .iter()
                    .filter(|(_, path)| pathspec_operand(builder, s, path))
                    .map(|(_, path)| *path)
                    .collect::<Vec<_>>()
            };
            let commits = operands
                .iter()
                .filter(|(_, word)| !paths.contains(word))
                .collect::<Vec<_>>();
            if commits.len() > 1
                || commits
                    .first()
                    .is_some_and(|(_, word)| word.as_literal() != Some("HEAD"))
            {
                if commits
                    .iter()
                    .any(|(_, word)| word.as_literal().is_some_and(|text| text.starts_with(':')))
                {
                    super::git_argument_boundary(
                        builder,
                        s,
                        "git diff revision selection is not observed",
                    );
                }
                return None;
            }
            let kind = if flags
                .iter()
                .any(|flag| matches!(*flag, "--cached" | "--staged"))
            {
                if !commits.is_empty() {
                    return None;
                }
                "staged-diff"
            } else if commits.is_empty() {
                "diff"
            } else {
                "head-diff"
            };
            (kind, paths)
        }
        "log" | "show" => {
            if printed_file_content(sub, s.rest) != PrintedFileContent::Lines
                || sub == "log"
                    && !flags.iter().any(|flag| {
                        matches!(
                            *flag,
                            "-p" | "-u" | "--patch" | "--patch-with-stat" | "--patch-with-raw"
                        ) || flag.starts_with("-U")
                            || flag.starts_with("--unified")
                    })
            {
                return None;
            }
            let diff_flags = flags
                .iter()
                .copied()
                .filter(|flag| {
                    !flag
                        .strip_prefix("-n")
                        .or_else(|| flag.strip_prefix('-'))
                        .is_some_and(|value| {
                            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                        })
                })
                .collect::<Vec<_>>();
            if unobserved_diff_selection(&diff_flags)
                || flags.iter().any(|flag| {
                    *flag == "--first-parent"
                        || *flag == "--no-diff-merges"
                        || flag.starts_with("--diff-merges")
                        || flag
                            .strip_prefix('-')
                            .is_some_and(|short| !short.starts_with('-') && short.contains('m'))
                })
            {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git history selection options are not observed",
                );
                return None;
            }
            let Some(history) = history_arguments(builder, s, sub == "log") else {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git history selection options are not observed",
                );
                return None;
            };
            revisions = history
                .revisions
                .into_iter()
                .map(|word| word.as_literal().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?;
            revision_options = history.options;
            (
                if sub == "log" { "history" } else { "commit" },
                history.paths,
            )
        }
        "stash" if flags.first() == Some(&"show") => {
            // In stash show, -u includes the third parent's untracked files;
            // it is not diff's -u patch option. Keep it out of the format scan.
            let (mut include_untracked, mut only_untracked) = (false, false);
            let mut selection_known = true;
            let mut format = Vec::new();
            for word in &s.rest[1..] {
                let text = word.as_literal()?;
                match text {
                    "-u" | "--include-untracked" => include_untracked = true,
                    "--only-untracked" => only_untracked = true,
                    "--no-include-untracked" | "--no-only-untracked" => selection_known = false,
                    _ => {
                        let text = if text.starts_with('-')
                            && !text.starts_with("--")
                            && text[1..]
                                .chars()
                                .all(|letter| matches!(letter, 'p' | 'u' | 's'))
                        {
                            let stripped = text[1..].replace('u', "");
                            include_untracked |= text.contains('u');
                            format!("-{stripped}")
                        } else {
                            text.to_owned()
                        };
                        format.push(Word::literal(text));
                    }
                }
            }
            let patch = format.iter().filter_map(Word::as_literal).any(|flag| {
                flag == "--patch"
                    || flag.starts_with("--patch-with-")
                    || flag.starts_with("--unified")
                    || flag.starts_with("-U")
                    || flag.strip_prefix('-').is_some_and(|short| {
                        !short.starts_with('-')
                            && short.chars().all(|letter| matches!(letter, 'p' | 's'))
                            && short.contains('p')
                    })
            });
            if !patch || printed_file_content("diff", &format) != PrintedFileContent::Lines {
                return None;
            }
            if !selection_known {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git stash selection options are not observed",
                );
                return None;
            }
            let operands = s.operands(false);
            if operands.len() > 2 {
                return None;
            }
            revisions.push(
                match operands.get(1) {
                    Some((_, word)) => word.as_literal()?,
                    None => "refs/stash",
                }
                .to_owned(),
            );
            let kind = if only_untracked {
                "stash-only-untracked"
            } else if include_untracked {
                "stash-untracked"
            } else {
                "stash"
            };
            (kind, Vec::new())
        }
        "commit" => {
            // What a commit takes from the work tree, as builtin/commit.c
            // `prepare_index` decides it: with -a every changed tracked file;
            // with `--include` and pathspecs the changed tracked files they
            // match, beside the index; with pathspecs alone (`--only`) the
            // tracked files they match whose work tree differs from `HEAD`,
            // since Git builds that commit from `HEAD` and the named files,
            // whatever the index holds. Otherwise only what the index
            // already holds, which nothing stages here. Git refuses -a beside
            // pathspecs, and a status format (`--short`, `--long`,
            // `--porcelain`, `-z`) makes the commit a dry run, which rolls
            // the prepared index back.
            let parsed = commit_options(s);
            if git_help_requested(&parsed)
                || !git_controls_known(&parsed)
                || parsed.has(&[
                    "--dry-run",
                    "--short",
                    "--long",
                    "--porcelain",
                    "-z",
                    "--null",
                ])
            {
                return None;
            }
            if parsed.has(&["-p", "--patch"]) {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git commit interactive selection is not observed",
                );
                return None;
            }
            let all = parsed.has(&["-a", "--all"]);
            let from_file = parsed.has(&["--pathspec-from-file"]);
            let paths = parsed
                .operands
                .iter()
                .map(|(_, path)| *path)
                .collect::<Vec<_>>();
            if all && (from_file || !paths.is_empty()) || !all && !from_file && paths.is_empty() {
                return None;
            }
            // The pathspecs a file lists are not read here, so the commit
            // states what every pathspec could take, the whole repository,
            // and stays partly known.
            let paths = if from_file {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git commit pathspecs from a file are not observed",
                );
                pathspecs_from_file = true;
                whole_repository = true;
                repository_root = Word::literal(":/");
                vec![&repository_root]
            } else {
                paths
            };
            let include = parsed.has(&["-i", "--include"]);
            (
                if all || include {
                    "addable-tracked"
                } else {
                    "addable-head"
                },
                paths,
            )
        }
        "add" => {
            // What `git add` stages, as builtin/add.c `cmd_add` decides it:
            // with -u, --renormalize or --resolved the changed tracked files,
            // otherwise untracked ones too, and with --force ignored ones.
            // The last of each option and its negation decides.
            // A form that stages no contents states none. One whose
            // selection is not read here, an option Nah does not know among
            // them, states none either and leaves the add partly known.
            let parsed = add_options(s);
            if git_help_requested(&parsed) {
                return None;
            }
            if !git_controls_known(&parsed) {
                super::git_argument_boundary(builder, s, "git add options are not fully known");
                return None;
            }
            let effective = |positive, negative| parsed_effective_flag(&parsed, positive, negative);
            if effective(&["-i", "--interactive"], &["--no-interactive"])
                || effective(&["-p", "--patch"], &["--no-patch"])
                || effective(&["-e", "--edit"], &["--no-edit"])
            {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git add interactive selection is not observed",
                );
                return None;
            }
            // The pathspecs a file lists are not read here, so the add
            // states what every pathspec could stage, the whole repository,
            // and stays partly known.
            let from_file = effective(&["--pathspec-from-file"], &["--no-pathspec-from-file"]);
            if from_file {
                super::git_argument_boundary(
                    builder,
                    s,
                    "git add pathspecs from a file are not observed",
                );
            }
            if !add_stages_contents(&parsed) {
                return None;
            }
            let all = effective(
                &["-A", "--all", "--no-ignore-removal"],
                &["--no-all", "--ignore-removal"],
            );
            let update = effective(&["-u", "--update"], &["--no-update"]);
            let resolved = effective(&["--resolved"], &["--no-resolved"]);
            let renormalize = effective(&["--renormalize"], &["--no-renormalize"]);
            let force = effective(&["-f", "--force"], &["--no-force"]);
            let paths = parsed
                .operands
                .iter()
                .map(|(_, path)| *path)
                .collect::<Vec<_>>();
            // Git refuses any two of -A, -u and --resolved, and adds nothing
            // without a pathspec unless one of them is given.
            if [all, update, resolved].iter().filter(|set| **set).count() > 1
                || paths.is_empty() && !all && !update && !resolved && !from_file
            {
                return None;
            }
            // --renormalize re-adds every tracked file its pathspecs match,
            // changed or not (builtin/add.c renormalize_tracked_files), which
            // the tracked selection names; without a pathspec, every tracked
            // file in the repository.
            pathspecs_from_file = from_file;
            let paths = if from_file || renormalize && !resolved && paths.is_empty() {
                whole_repository = true;
                repository_root = Word::literal(":/");
                vec![&repository_root]
            } else {
                paths
            };
            (
                if resolved || update && !renormalize {
                    "addable-tracked"
                } else if renormalize {
                    "renormalized"
                } else if force {
                    "addable-all"
                } else {
                    "addable"
                },
                paths,
            )
        }
        _ => return None,
    };
    // The filename observer uses its own repository discovery and clears
    // inherited Git configuration. Refuse those observations only for
    // commands whose contents actually depend on a selection.
    if s.globals.git_dir.is_some()
        || s.globals.work_tree.is_some()
        || [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
        ]
        .iter()
        .any(|name| s.ctx.environment_value(name).is_some())
        || s.globals.opaque_config
        || s.globals.configs.iter().any(|entry| entry.replaces)
    {
        super::git_argument_boundary(
            builder,
            s,
            "git content selection repository or configuration overrides are not observed",
        );
        return None;
    }
    let paths = paths
        .into_iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    let mut options = pathspec_options(s)?;
    // Literal pathspecs would read the added `:/` as a file name.
    if whole_repository {
        options.retain(|option| *option != "--literal-pathspecs");
    }
    let literal = options.iter().rev().find_map(|option| match *option {
        "--literal-pathspecs" => Some(true),
        "--no-literal-pathspecs" => Some(false),
        _ => None,
    });
    let unknown_pathspec =
        !separated && literal != Some(true) && paths.iter().any(|path| unknown_magic(path));
    if unknown_pathspec {
        super::git_argument_boundary(builder, s, "git pathspec magic is not observed");
    }
    let mut attrs = Attrs::from([
        ("content_selection".into(), AttrValue::String(kind.into())),
        (
            "content_directory".into(),
            AttrValue::String(directory.into()),
        ),
        (
            "content_pathspecs".into(),
            string_list(if unknown_pathspec { &[] } else { &paths }),
        ),
        ("content_pathspec_options".into(), string_list(&options)),
    ]);
    if unknown_pathspec || pathspecs_from_file {
        attrs.insert("content_pathspec_unknown".into(), AttrValue::Bool(true));
    }
    if changes_configuration_files(s) {
        attrs.insert(
            "content_user_configuration_changed".into(),
            AttrValue::Bool(true),
        );
    }
    let revisions = revisions.iter().map(String::as_str).collect::<Vec<_>>();
    if revisions
        .iter()
        .any(|revision| revision.is_empty() || revision.starts_with('-') || revision.contains(':'))
    {
        super::git_argument_boundary(builder, s, "git revision selection is not observed");
        return None;
    }
    // Preserve the accepted unseparated wildcard heuristic: these operands
    // may be pathspecs, but the model does not classify them as revisions.
    if !separated
        && revisions
            .iter()
            .any(|revision| revision.contains(['*', '?', '[']))
    {
        return None;
    }
    attrs.insert("content_revisions".into(), string_list(&revisions));
    attrs.insert(
        "content_revision_options".into(),
        string_list(&revision_options),
    );
    Some(attrs)
}

/// Whether the call itself sets or unsets a variable that chooses the
/// global or system configuration files Git reads, and so its global
/// excludes file. The filename observer asks Git with the host's own
/// values, so for such a call it leaves that file's rules out
/// (`content_user_configuration_changed`).
fn changes_configuration_files(s: &SubCtx) -> bool {
    let host = s.ctx.nest.host_environment_context();
    let unsets = s.ctx.nest.current_environment_unsets();
    [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
        "HOME",
        "XDG_CONFIG_HOME",
    ]
    .iter()
    .any(|name| {
        let host_value = host.and_then(|context| context.env.get(*name));
        match s.ctx.environment_value(name) {
            Some(ResourceExpr::Literal { value }) => host_value != Some(&value),
            Some(_) => true,
            // Absent here: the call unset it where the host has it, or where
            // the call's own unsets name it and the host may have it.
            None => {
                host_value.is_some()
                    || unsets.contains(*name)
                        && !host.is_some_and(|context| context.env_unset.contains(*name))
            }
        }
    })
}

/// git-add(1)'s options, scanned as parse-options reads them: anywhere
/// before `--`, clustered, and abbreviated where unambiguous.
pub(super) fn add_options<'a>(s: &'a SubCtx) -> Scanned<'a> {
    git_options(
        s,
        &FlagSpec {
            value_flags: ADD_VALUE_FLAGS,
            known_flags: ADD_FLAGS,
            allow_abbreviation: true,
        },
    )
}

/// git-commit(1)'s options, scanned as parse-options reads them. `-S` and
/// `-u` take an optional value Git reads only attached (`-Skey`, `-uno`),
/// so in a short cluster everything after either is its value, never more
/// options.
pub(super) fn commit_options<'a>(s: &'a SubCtx) -> Scanned<'a> {
    let mut parsed = git_options(
        s,
        &FlagSpec {
            value_flags: COMMIT_VALUE_FLAGS,
            known_flags: COMMIT_FLAGS,
            allow_abbreviation: true,
        },
    );
    let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
    for (index, word) in argv.iter().enumerate().skip(1) {
        let index = index as u32;
        if parsed.dashdash.is_some_and(|dashdash| index > dashdash) {
            break;
        }
        let Some(cluster) = word
            .as_literal()
            .and_then(|text| text.strip_prefix('-'))
            .filter(|cluster| !cluster.starts_with('-'))
        else {
            continue;
        };
        // Only a word the scan read as options: a value it took is none.
        if !parsed.flags.iter().any(|flag| flag.index == index)
            && !parsed.unknown_flags.iter().any(|(at, _)| *at == index)
        {
            continue;
        }
        let Some(at) = cluster.find(['S', 'u', 'm', 'F', 'C', 'c', 't']) else {
            continue;
        };
        if !matches!(&cluster[at..at + 1], "S" | "u") || at + 1 == cluster.len() {
            continue;
        }
        let Some(names) = cluster[..=at]
            .chars()
            .map(|short| {
                COMMIT_FLAGS
                    .iter()
                    .copied()
                    .find(|name| name.len() == 2 && name.ends_with(short))
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        // The scan may have taken the next word as a value the cluster's
        // tail seemed to need; Git reads it as the next argument.
        let took_next = parsed
            .flags
            .iter()
            .any(|flag| flag.index == index && flag.value_index == Some(index + 1));
        parsed.flags.retain(|flag| flag.index != index);
        parsed.unknown_flags.retain(|(at, _)| *at != index);
        parsed.flags.extend(names.into_iter().map(|name| Flag {
            name,
            value: None,
            index,
            value_index: None,
        }));
        if took_next {
            let next = &argv[index as usize + 1];
            if next.as_literal().is_some_and(|text| text.starts_with('-')) {
                // An option the scan never read: leave the selection unknown.
                parsed.unknown_flags.push((index + 1, next.render_raw()));
            } else {
                parsed.operands.push((index + 1, next));
                parsed.operands.sort_by_key(|(at, _)| *at);
            }
        }
    }
    parsed
}

/// git-commit(1)'s options that take a value, attached or as the next word.
const COMMIT_VALUE_FLAGS: &[&str] = &[
    "-m",
    "--message",
    "-F",
    "--file",
    "-C",
    "--reuse-message",
    "-c",
    "--reedit-message",
    "--author",
    "--date",
    "--cleanup",
    "-t",
    "--template",
    "--trailer",
    "--pathspec-from-file",
    "--fixup",
    "--squash",
];

/// git-commit(1)'s other options. What else an amend spells changes the new
/// commit, never whether the tip it replaces stays in the reflog.
const COMMIT_FLAGS: &[&str] = &[
    "--amend",
    "-n",
    "--no-verify",
    "--verify",
    "--no-edit",
    "-e",
    "--edit",
    "-a",
    "--all",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "-s",
    "--signoff",
    "--no-signoff",
    "--reset-author",
    "--allow-empty",
    "--allow-empty-message",
    "-o",
    "--only",
    "-i",
    "--include",
    "-p",
    "--patch",
    "--pathspec-file-nul",
    "-S",
    "--gpg-sign",
    "--no-gpg-sign",
    "--status",
    "--no-status",
    "--no-post-rewrite",
    "--dry-run",
    "--short",
    "--long",
    "--porcelain",
    "--branch",
    "-z",
    "--null",
    "-u",
    "--untracked-files",
    "--no-file",
    "--no-template",
];

/// Whether a `git add` with these options hashes file contents into the
/// index. An interactive or edited add stages what is chosen from the diff
/// whatever else is given, since Git enters those modes first; otherwise a
/// dry run, a refresh and an intent to add record none. Options Nah does not
/// know may stage anything.
pub(super) fn add_stages_contents(parsed: &Scanned<'_>) -> bool {
    !git_controls_known(parsed)
        || parsed_effective_flag(parsed, &["-i", "--interactive"], &["--no-interactive"])
        || parsed_effective_flag(parsed, &["-p", "--patch"], &["--no-patch"])
        || parsed_effective_flag(parsed, &["-e", "--edit"], &["--no-edit"])
        || !(parsed_effective_flag(parsed, &["-n", "--dry-run"], &["--no-dry-run"])
            || parsed_effective_flag(parsed, &["--refresh"], &["--no-refresh"])
            || parsed_effective_flag(parsed, &["-N", "--intent-to-add"], &["--no-intent-to-add"]))
}

/// git-add(1)'s options that take a value, attached or as the next word.
/// `-U` and `--inter-hunk-context` shape the hunks of `--patch` and have no
/// `--no-` form.
const ADD_VALUE_FLAGS: &[&str] = &[
    "--chmod",
    "--pathspec-from-file",
    "-U",
    "--unified",
    "--inter-hunk-context",
];

/// git-add(1)'s other options, each with the `--no-` form parse-options
/// gives it (builtin/add.c `builtin_add_options`, Git 2.56).
const ADD_FLAGS: &[&str] = &[
    "-n",
    "--dry-run",
    "--no-dry-run",
    "-v",
    "--verbose",
    "--no-verbose",
    "-i",
    "--interactive",
    "--no-interactive",
    "-p",
    "--patch",
    "--no-patch",
    "--auto-advance",
    "--no-auto-advance",
    "-e",
    "--edit",
    "--no-edit",
    "-f",
    "--force",
    "--no-force",
    "-u",
    "--update",
    "--no-update",
    "--renormalize",
    "--no-renormalize",
    "--resolved",
    "--no-resolved",
    "-N",
    "--intent-to-add",
    "--no-intent-to-add",
    "-A",
    "--all",
    "--no-all",
    "--ignore-removal",
    "--no-ignore-removal",
    "--refresh",
    "--no-refresh",
    "--ignore-errors",
    "--no-ignore-errors",
    "--ignore-missing",
    "--no-ignore-missing",
    "--sparse",
    "--no-sparse",
    "--no-chmod",
    "--warn-embedded-repo",
    "--no-warn-embedded-repo",
    "--no-pathspec-from-file",
    "--pathspec-file-nul",
    "--no-pathspec-file-nul",
];

/// Git's check_filename tests short magic's remainder, from the repository
/// root for `:/`. Long magic also passes verify_filename without a host path.
pub(super) fn pathspec_operand(builder: &mut PlanBuilder, s: &SubCtx, word: &Word) -> bool {
    let Some(mut text) = word.as_literal() else {
        return false;
    };
    if text.starts_with(":(") {
        return true;
    }
    let top = text.starts_with(":/");
    if let Some(rest) = text
        .strip_prefix(":/")
        .or_else(|| text.strip_prefix(":!"))
        .or_else(|| text.strip_prefix(":^"))
    {
        if rest.is_empty() {
            return true;
        }
        text = rest;
    }
    if !builder.is_host_realm() {
        return false;
    }
    let Some(mut directory) = s.cwd.clone() else {
        return false;
    };
    if top {
        // Git runs check_filename after changing to the repository root.
        // Metadata questions share the observation budget and cache.
        loop {
            match builder
                .budget()
                .observe_path(&crate::paths::join_cwd(&directory, ".git"))
            {
                ObservationOutcome::Path(fact) if fact.kind != PathKind::Missing => break,
                ObservationOutcome::Path(_) => {
                    let parent = crate::paths::parent_dir(&directory);
                    if parent == directory || !crate::paths::is_absolute(&parent) {
                        return false;
                    }
                    directory = parent;
                }
                _ => return false,
            }
        }
    }
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = resolve_fs_word(&Word::literal(text), Some(&directory))
    else {
        return false;
    };
    matches!(builder.budget().observe_path(&path), ObservationOutcome::Path(fact) if fact.kind != PathKind::Missing)
}

fn unknown_magic(path: &str) -> bool {
    if let Some(magic) = path.strip_prefix(":(") {
        !magic.split_once(')').is_some_and(|(magic, _)| {
            magic
                .split(',')
                .all(|word| matches!(word, "" | "top" | "glob" | "literal" | "icase" | "exclude"))
        })
    } else {
        path.starts_with(':')
            && path != ":"
            && ![":/", ":!", ":^"]
                .iter()
                .any(|magic| path.starts_with(magic))
    }
}

/// Selection-changing diff options omitted by the filename-only observation.
fn unobserved_diff_selection(flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        let name = flag.split('=').next().unwrap_or(flag);
        matches!(
            name,
            "--merge-base"
                | "--base"
                | "--ours"
                | "--theirs"
                | "--combined-all-paths"
                | "--relative"
                | "--diff-filter"
                | "--find-object"
                | "--skip-to"
                | "--rotate-to"
                | "--submodule"
                | "--ignore-submodules"
                | "--find-renames"
                | "--find-copies"
                | "--find-copies-harder"
                | "--break-rewrites"
                | "--ignore-cr-at-eol"
                | "--ignore-space-at-eol"
                | "--ignore-space-change"
                | "--ignore-all-space"
                | "--ignore-blank-lines"
                | "--ignore-matching-lines"
                | "--irreversible-delete"
        ) || flag.strip_prefix('-').is_some_and(|short| {
            !short.starts_with('-')
                && match short.chars().next() {
                    Some('B' | 'M' | 'C' | 'S' | 'G' | 'I') => true,
                    Some('U' | 'X' | 'l' | 'O') => false,
                    _ => short
                        .chars()
                        .any(|letter| matches!(letter, 'b' | 'w' | 'D' | '0' | '1' | '2' | '3')),
                }
        })
    })
}

struct HistoryArguments<'a> {
    revisions: Vec<&'a Word>,
    paths: Vec<&'a Word>,
    options: Vec<&'a str>,
}

/// Only pass selection switches that cannot launch programs or redirect output.
/// Unknown switches retain named reads and state a boundary instead.
fn history_arguments<'a>(
    builder: &mut PlanBuilder,
    s: &SubCtx<'a>,
    log: bool,
) -> Option<HistoryArguments<'a>> {
    let (mut revisions, mut paths, mut options) = (Vec::new(), Vec::new(), Vec::new());
    let mut words = s.rest.iter();
    while let Some(word) = words.next() {
        let text = word.as_literal()?;
        if text == "--" {
            paths.extend(words);
            break;
        }
        if !text.starts_with('-') {
            if pathspec_operand(builder, s, word) {
                paths.push(word);
                paths.extend(words);
                break;
            }
            revisions.push(word);
            continue;
        }
        let name = text.split('=').next()?;
        match name {
            "--follow" if log => options.push(text),
            "--cc" if log => return None,
            "--all"
            | "--branches"
            | "--tags"
            | "--remotes"
            | "--no-merges"
            | "--merges"
            | "--reverse"
            | "--topo-order"
            | "--date-order"
            | "--author-date-order" => options.push(text),
            "-n" | "--max-count" | "--skip" | "--since" | "--after" | "--until" | "--before" => {
                options.push(text);
                if !text.contains('=') {
                    options.push(words.next()?.as_literal()?);
                }
            }
            "--format" | "--pretty" | "--date" | "--encoding" => {
                if !text.contains('=') {
                    words.next()?;
                }
            }
            "-p" | "-u" | "--patch" | "--patch-with-stat" | "--patch-with-raw" | "--cc"
            | "--no-ext-diff" | "--no-textconv" | "--no-renames" | "--no-relative" | "--stat"
            | "--raw" | "--numstat" | "--oneline" | "--color" | "--no-color" | "--unified" => {}
            _ if text.starts_with("-U") || text.starts_with("--unified=") => {}
            _ if text.strip_prefix('-').is_some_and(|value| {
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
            }) || text.strip_prefix("-n").is_some_and(|value| {
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
            }) =>
            {
                options.push(text)
            }
            _ => return None,
        }
    }
    if !log && !options.is_empty() {
        return None;
    }
    Some(HistoryArguments {
        revisions,
        paths,
        options,
    })
}
