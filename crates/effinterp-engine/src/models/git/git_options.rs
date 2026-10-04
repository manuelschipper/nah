//! How a git subcommand's options are scanned, and whether the scan knows
//! every option, option value and operand it read.

use crate::models::args::{FlagSpec, Scanned, scan};
use crate::word::Word;

use super::SubCtx;

/// Scan supported options together, preserving clusters, order and `--`.
pub(super) fn git_options<'a>(s: &'a SubCtx, spec: &FlagSpec<'a>) -> Scanned<'a> {
    let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
    let mut parsed = scan(argv, spec);
    for flag in &parsed.flags {
        let word = &argv[flag.index as usize];
        if word.as_literal().is_none()
            || (spec.value_flags.contains(&flag.name) && flag.value.is_none())
            || (spec.known_flags.contains(&flag.name)
                && word
                    .as_literal()
                    .is_some_and(|text| text.starts_with("--") && text.contains('='))
                && !matches!(flag.name, "--force-with-lease" | "--signed")
                // git-rebase(1) names the two modes; any other exits first.
                && !word.as_literal().is_some_and(|text| {
                    flag.name == "--rebase-merges"
                        && text.split_once('=').is_some_and(|(_, mode)| {
                            matches!(mode, "rebase-cousins" | "no-rebase-cousins")
                        })
                }))
        {
            parsed.unknown_flags.push((flag.index, word.render_raw()));
        }
    }
    for (index, word) in &parsed.operands {
        if word.as_literal().is_none() && parsed.dashdash.is_none_or(|dd| *index < dd) {
            parsed.unknown_flags.push((*index, word.render_raw()));
        }
    }
    parsed
}

pub(super) fn git_controls_known(parsed: &Scanned<'_>) -> bool {
    git_options_known(parsed) && git_option_values_known(parsed)
}

/// Every option is a supported spelling; a dynamic operand is still an operand.
pub(super) fn git_options_known(parsed: &Scanned<'_>) -> bool {
    !parsed.unknown_flags.iter().any(|(index, _)| {
        !parsed
            .operands
            .iter()
            .any(|(operand_index, _)| operand_index == index)
    })
}

pub(super) fn git_option_values_known(parsed: &Scanned<'_>) -> bool {
    parsed.flags.iter().all(|flag| {
        flag.value
            .as_ref()
            .is_none_or(|value| value.as_literal().is_some())
    })
}

pub(super) fn git_operands_known(parsed: &Scanned<'_>) -> bool {
    parsed
        .operands
        .iter()
        .all(|(_, word)| word.as_literal().is_some())
}

pub(super) fn git_operands_are_not_options(s: &SubCtx<'_>, operands: &[(u32, &Word)]) -> bool {
    let dashdash = s
        .rest
        .iter()
        .position(|word| word.as_literal() == Some("--"))
        .map(|index| s.rest_offset - 1 + index as u32);
    operands.iter().all(|(index, word)| {
        dashdash.is_some_and(|separator| *index > separator)
            || !word
                .as_literal()
                .is_some_and(|value| value.starts_with('-'))
    })
}

/// Last occurrence wins, over a scan that already separated options from
/// pathspecs, so a `--force` after `--` stays an operand.
pub(super) fn parsed_effective_flag(
    parsed: &Scanned<'_>,
    positive: &[&str],
    negative: &[&str],
) -> bool {
    parsed
        .flags
        .iter()
        .rev()
        .find_map(|flag| {
            if positive.contains(&flag.name) {
                Some(true)
            } else if negative.contains(&flag.name) {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(false)
}

pub(super) fn git_effective_flag(s: &SubCtx<'_>, positive: &[&str], negative: &[&str]) -> bool {
    let names: Vec<_> = positive.iter().chain(negative).copied().collect();
    s.scanned(&names)
        .flags
        .iter()
        .rev()
        .find_map(|flag| {
            if positive.contains(&flag.name) {
                Some(true)
            } else if negative.contains(&flag.name) {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(false)
}

/// git's parse-options answers a help request with the usage message and
/// exits before the command runs. It reads `-h` and `--help` only where it is
/// still reading options, matches them exactly rather than by the abbreviation
/// it allows a command's own options, and never sees one it has already taken
/// as an option value.
pub(super) fn git_help_requested(parsed: &Scanned<'_>) -> bool {
    parsed
        .unknown_flags
        .iter()
        .any(|(_, flag)| flag == "-h" || flag == "--help")
}
