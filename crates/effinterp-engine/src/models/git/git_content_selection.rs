//! The repository selection of a content-printing Git read. The host can
//! answer these filename questions without running the requested search.

use super::git_read::{PrintedFileContent, grep_arguments, printed_file_content};
use super::{SubCtx, string_list};
use crate::builder::PlanBuilder;
use crate::models::common::Attrs;
use crate::paths::resolve_fs_word;
use crate::word::Word;
use effinterp_proto::{AttrValue, ObservationOutcome, PathKind, ResourceExpr, ResourceIdentity};

/// Static selection attributes shared by the repository read and its named
/// file reads. Unknown selections retain the evidence already named by the
/// invocation, without claiming to enumerate its files.
pub(super) fn content_selection(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) -> Option<Attrs> {
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
    {
        return None;
    }
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
        _ => return None,
    };
    if s.globals.opaque_config || s.globals.configs.iter().any(|entry| entry.replaces) {
        super::git_argument_boundary(
            builder,
            s,
            "git content selection configuration overrides are not observed",
        );
        return None;
    }
    let paths = paths
        .into_iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    let mut options = Vec::new();
    for (name, option) in [
        ("GIT_LITERAL_PATHSPECS", "--literal-pathspecs"),
        ("GIT_NOGLOB_PATHSPECS", "--noglob-pathspecs"),
        ("GIT_GLOB_PATHSPECS", "--glob-pathspecs"),
        ("GIT_ICASE_PATHSPECS", "--icase-pathspecs"),
    ] {
        if let Some(value) = s.ctx.environment_value(name) {
            let ResourceExpr::Literal { value } = value else {
                return None;
            };
            if super::git_config::git_bool(&value)? {
                options.push(option);
            }
        }
    }
    options.extend(s.globals.pathspec_options.iter().copied());
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
    if unknown_pathspec {
        attrs.insert("content_pathspec_unknown".into(), AttrValue::Bool(true));
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
