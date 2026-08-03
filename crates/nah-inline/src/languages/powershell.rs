use crate::syntax::lexical_code_cased;
use crate::{Finding, FindingKind, InlineInput, InlineReport, ProtectionInput};

use super::common::{DefinitionStyle, add_exact_argv, observe_shadow, ordered_active_segments};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut remove_item_shadowed = false;
    let mut invoke_expression_shadowed = false;
    let mut iex_shadowed = false;
    let mut start_process_shadowed = false;
    for segment in
        ordered_active_segments(input.code, program, DefinitionStyle::Braces, &mut report)
    {
        if !segment.executable {
            observe_powershell_shadows(
                segment.source,
                program,
                &mut remove_item_shadowed,
                &mut invoke_expression_shadowed,
                &mut iex_shadowed,
                &mut start_process_shadowed,
            );
            continue;
        }
        let (outside, strings, offsets, static_strings, _) =
            lexical_code_cased(segment.source, program);
        let lowercase = outside.to_ascii_lowercase();
        let command = lowercase
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default();
        let recursive = lowercase
            .split_ascii_whitespace()
            .any(|word| matches!(word, "-recurse" | "-r" | "/s"));
        let what_if = lowercase
            .split_ascii_whitespace()
            .any(|word| word == "-whatif" || word == "-whatif:$true");
        let destructive = if program == "cmd" {
            matches!(command, "rd" | "rmdir")
        } else {
            command == "remove-item"
        };
        if recursive && destructive && !what_if && !remove_item_shadowed {
            let targets =
                if program == "cmd" {
                    strings
                        .iter()
                        .map(String::as_str)
                        .chain(lowercase.split_ascii_whitespace().filter(|word| {
                            matches!(*word, "/" | "\\" | "~") || *word == input.home
                        }))
                        .collect::<Vec<_>>()
                } else {
                    associated_remove_item_targets(&lowercase, &strings, &offsets)
                };
            if targets
                .iter()
                .any(|target| *target == "/" || *target == "\\")
            {
                report.push(Finding::exact(FindingKind::RootDestruction));
            }
            if targets.iter().any(|target| {
                *target == input.home
                    || matches!(
                        target.to_ascii_lowercase().as_str(),
                        "~" | "$home" | "$env:home"
                    )
            }) {
                report.push(Finding::exact(FindingKind::HomeDestruction));
            }
        }
        let invoke_expression_owned = command == "invoke-expression" && !invoke_expression_shadowed
            || command == "iex" && !iex_shadowed;
        if invoke_expression_owned
            && static_strings == [true]
            && let [code] = strings.as_slice()
        {
            report.extend(crate::analyze_at(
                InlineInput { code, ..*input },
                None,
                depth + 1,
            ));
        }
        add_static_powershell_child(&mut report, &lowercase, &strings, start_process_shadowed);
        observe_powershell_shadows(
            segment.source,
            program,
            &mut remove_item_shadowed,
            &mut invoke_expression_shadowed,
            &mut iex_shadowed,
            &mut start_process_shadowed,
        );
    }
    super::common::with_protection(report, program, input, protection)
}

fn add_static_powershell_child(
    report: &mut InlineReport,
    outside: &str,
    strings: &[String],
    start_process_shadowed: bool,
) {
    let words = outside.split_ascii_whitespace().collect::<Vec<_>>();
    if words.as_slice() == ["&", "nah", "nap"] && strings.is_empty() {
        add_exact_argv(report, vec!["nah".into(), "nap".into()]);
        return;
    }
    if words.as_slice() == ["&"]
        && matches!(strings, [program, argument] if program.eq_ignore_ascii_case("nah") && argument.eq_ignore_ascii_case("nap"))
    {
        add_exact_argv(report, vec!["nah".into(), "nap".into()]);
        return;
    }
    if !start_process_shadowed
        && words.as_slice() == ["start-process", "nah", "-argumentlist", "nap"]
        && strings.is_empty()
    {
        add_exact_argv(report, vec!["nah".into(), "nap".into()]);
    }
}

fn observe_powershell_shadows(
    source: &str,
    program: &str,
    remove_item: &mut bool,
    invoke_expression: &mut bool,
    iex: &mut bool,
    start_process: &mut bool,
) {
    for (shadowed, name) in [
        (remove_item, "remove-item"),
        (invoke_expression, "invoke-expression"),
        (iex, "iex"),
        (start_process, "start-process"),
    ] {
        observe_shadow(shadowed, source, program, name);
    }
}

enum PowerShellToken<'a> {
    Word(&'a str),
    Literal(&'a str),
}

fn associated_remove_item_targets<'a>(
    outside: &'a str,
    strings: &'a [String],
    offsets: &[usize],
) -> Vec<&'a str> {
    let mut tokens = Vec::new();
    let bytes = outside.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if start < index {
            tokens.push((start, PowerShellToken::Word(&outside[start..index])));
        }
    }
    tokens.extend(
        strings
            .iter()
            .zip(offsets)
            .map(|(value, offset)| (*offset, PowerShellToken::Literal(value))),
    );
    tokens.sort_by_key(|(offset, _)| *offset);

    enum Association {
        Positional,
        Path,
        Other,
    }
    let mut association = Association::Positional;
    let mut command_seen = false;
    let mut targets = Vec::new();
    for (_, token) in tokens {
        match token {
            PowerShellToken::Word(word) => {
                let word = word.trim_matches([',', ';', '(', ')']);
                if word.is_empty() {
                    continue;
                }
                if !command_seen {
                    command_seen = true;
                    continue;
                }
                if word.starts_with('-') {
                    let parameter = word.split(':').next().unwrap_or(word);
                    association = if matches!(parameter, "-path" | "-literalpath") {
                        Association::Path
                    } else if matches!(
                        parameter,
                        "-recurse"
                            | "-r"
                            | "-force"
                            | "-whatif"
                            | "-confirm"
                            | "-verbose"
                            | "-debug"
                    ) {
                        Association::Positional
                    } else {
                        Association::Other
                    };
                } else if matches!(association, Association::Other) {
                    association = Association::Positional;
                }
            }
            PowerShellToken::Literal(value) => match association {
                Association::Positional | Association::Path => targets.push(value),
                Association::Other => association = Association::Positional,
            },
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(code: &str) -> InlineReport {
        analyze(
            "pwsh",
            &InlineInput {
                program: "pwsh",
                code,
                home: "/home/dev",
                platform: nah_proto::ctx::Platform::Linux,
            },
            None,
            0,
        )
    }

    #[test]
    fn powershell_command_replacements_remove_builtin_ownership() {
        let nested = "Remove-Item -Recurse '/'";
        assert!(
            report(&format!("Invoke-Expression \"{nested}\""))
                .contains_exact(FindingKind::RootDestruction)
        );
        assert!(
            !report(&format!(
                "function Invoke-Expression {{}}\nInvoke-Expression \"{nested}\""
            ))
            .contains_exact(FindingKind::RootDestruction)
        );
        assert!(
            !report(&format!("function iex {{}}\niex \"{nested}\""))
                .contains_exact(FindingKind::RootDestruction)
        );
        assert!(
            report("function Start-Process {}\nStart-Process nah -ArgumentList nap")
                .nested_executions()
                .is_empty()
        );
    }

    #[test]
    fn remove_item_uses_only_path_parameters_and_positional_targets() {
        for source in [
            "Remove-Item -Recurse '/'",
            "Remove-Item -Path '/' -Recurse",
            "Remove-Item -LiteralPath '/' -Recurse",
        ] {
            assert!(
                report(source).contains_exact(FindingKind::RootDestruction),
                "{source}"
            );
        }
        for source in [
            "Remove-Item -Filter '/' -Recurse 'safe'",
            "Remove-Item -ErrorAction '/' -Recurse 'safe'",
        ] {
            assert!(
                !report(source).contains_exact(FindingKind::RootDestruction),
                "{source}"
            );
        }
    }
}
