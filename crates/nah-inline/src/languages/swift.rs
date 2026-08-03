use crate::syntax::{
    code_segments, lexical_code_cased, lexical_code_exact, static_call_arguments_cased,
};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{DefinitionStyle, active_segments, add_named_destructive_target};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let code = super::deferred::mask(input.code, program);
    let mut foundation = false;
    let file_manager_shadowed = code_segments(&code, program).into_iter().any(|segment| {
        let (outside, _, _, _) = lexical_code_exact(segment, program);
        let source = outside.trim_start();
        ["class", "struct", "enum", "typealias", "let", "var"]
            .iter()
            .any(|kind| {
                source.strip_prefix(kind).and_then(|rest| {
                    rest.trim_start()
                        .split(|character: char| {
                            !character.is_ascii_alphanumeric() && character != '_'
                        })
                        .next()
                }) == Some("FileManager")
            })
    });
    for segment in active_segments(&code, program, DefinitionStyle::Braces, &mut report) {
        let (outside, strings, offsets, static_strings, _) = lexical_code_cased(segment, program);
        foundation |= outside.trim() == "import Foundation";
        if !foundation || file_manager_shadowed {
            continue;
        }
        let matching_outside = mask_untried_remove_calls(&outside);
        for arguments in static_call_arguments_cased(
            &matching_outside,
            &outside,
            &strings,
            &offsets,
            &static_strings,
            "FileManager.default.removeItem",
            false,
        ) {
            let [target] = arguments.as_slice() else {
                continue;
            };
            let Some((label, _)) = target.outside.split_once(':') else {
                continue;
            };
            if label.trim() != "atPath" {
                continue;
            }
            add_named_destructive_target(
                &mut report,
                Some(target),
                input.home,
                input.platform,
                &["atPath"],
            );
        }
    }
    super::common::with_protection(report, program, input, protection)
}

fn mask_untried_remove_calls(outside: &str) -> String {
    const NAME: &str = "FileManager.default.removeItem";
    let mut matching = outside.as_bytes().to_vec();
    for (index, _) in outside.match_indices(NAME) {
        if !preceded_by_try(outside, index) {
            matching[index..index + NAME.len()].fill(b' ');
        }
    }
    String::from_utf8(matching).unwrap_or_else(|_| outside.to_owned())
}

fn preceded_by_try(source: &str, call: usize) -> bool {
    let prefix = source[..call].trim_end();
    ["try", "try?", "try!"].iter().any(|marker| {
        prefix.strip_suffix(marker).is_some_and(|prefix| {
            prefix
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
        })
    })
}
