use crate::syntax::{lexical_code_cased, named_call_argument, static_call_arguments_cased};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_named_destructive_target_with_bindings, add_static_bound_shell_call,
    assigned_identifier, named_boolean, observe_shadow, ordered_active_segments,
    update_static_binding,
};

#[derive(Clone, Default)]
struct RState {
    unlink_shadowed: bool,
    system_shadowed: bool,
    bindings: Vec<(String, String)>,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut states = vec![(0usize, RState::default())];
    for segment in
        ordered_active_segments(input.code, program, DefinitionStyle::Braces, &mut report)
    {
        let scope = segment.scope;
        if !states.iter().any(|(known, _)| *known == scope) {
            states.push((scope, states[0].1.clone()));
        }
        let state_index = states
            .iter()
            .position(|(known, _)| *known == scope)
            .expect("scope was inserted");
        let state = &mut states[state_index].1;
        if segment.executable {
            let (outside, strings, offsets, static_strings, _) =
                lexical_code_cased(segment.source, program);
            if !segment.state_exact {
                state.bindings.clear();
                state.unlink_shadowed = true;
                state.system_shadowed = true;
            }
            update_static_binding(
                &mut state.bindings,
                segment.source,
                program,
                segment.state_exact,
            );
            if !state.unlink_shadowed {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    "unlink",
                    true,
                ) {
                    if matches!(arguments.as_slice(), [_, recursive]
                        if named_boolean(
                            recursive,
                            "recursive",
                            &["TRUE"],
                            &["FALSE"]
                        ) == Some(true))
                        && r_argument_slot(&arguments[0], &["x"])
                    {
                        add_named_destructive_target_with_bindings(
                            &mut report,
                            arguments.first(),
                            input.home,
                            input.platform,
                            &state.bindings,
                            &["x"],
                        );
                    }
                }
            }
            if !state.system_shadowed {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    "system",
                    true,
                ) {
                    let Some(stdout_inherited) = r_system_stdout(&arguments) else {
                        continue;
                    };
                    if arguments
                        .first()
                        .is_none_or(|argument| !r_argument_slot(argument, &["command"]))
                    {
                        continue;
                    }
                    add_static_bound_shell_call(
                        &mut report,
                        &arguments,
                        input.platform,
                        stdout_inherited,
                        &state.bindings,
                        &["command"],
                    );
                }
            }
        }
        observe_shadow(
            &mut state.unlink_shadowed,
            segment.source,
            program,
            "unlink",
        );
        observe_shadow(
            &mut state.system_shadowed,
            segment.source,
            program,
            "system",
        );
        if scope != 0
            && segment.source.contains("<<-")
            && let Some(name) = assigned_identifier(segment.source)
        {
            let root = &mut states[0].1;
            root.bindings.retain(|(bound, _)| bound != name);
            if name == "system" {
                root.system_shadowed = true;
            } else if name == "unlink" {
                root.unlink_shadowed = true;
            }
        }
    }
    super::common::with_protection(report, program, input, protection)
}

fn r_system_stdout(arguments: &[crate::syntax::StaticCallArgument]) -> Option<bool> {
    let mut stdout_inherited = true;
    let mut positional = 0usize;
    let mut named_seen = false;
    let mut intern_seen = false;
    let mut ignore_stdout_seen = false;
    for argument in arguments.iter().skip(1) {
        let (slot, value) = if named_call_argument(argument, &["intern"]) {
            named_seen = true;
            if intern_seen {
                return None;
            }
            intern_seen = true;
            (
                0,
                named_boolean(argument, "intern", &["TRUE", "1"], &["FALSE", "0"]),
            )
        } else if named_call_argument(argument, &["ignore.stdout"]) {
            named_seen = true;
            if ignore_stdout_seen {
                return None;
            }
            ignore_stdout_seen = true;
            (
                1,
                named_boolean(argument, "ignore.stdout", &["TRUE", "1"], &["FALSE", "0"]),
            )
        } else {
            if named_seen || positional > 1 {
                return None;
            }
            let slot = positional;
            positional += 1;
            if slot == 0 {
                intern_seen = true;
            } else {
                ignore_stdout_seen = true;
            }
            (slot, r_boolean(argument))
        };
        let value = value?;
        if value && slot <= 1 {
            stdout_inherited = false;
        }
    }
    Some(stdout_inherited)
}

fn r_boolean(argument: &crate::syntax::StaticCallArgument) -> Option<bool> {
    if !argument.strings.is_empty() {
        return None;
    }
    match argument.outside.trim() {
        "TRUE" | "1" => Some(true),
        "FALSE" | "0" => Some(false),
        _ => None,
    }
}

fn r_argument_slot(argument: &crate::syntax::StaticCallArgument, names: &[&str]) -> bool {
    let outside = argument.outside.trim_start();
    let name_end = outside
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(outside.len());
    let name = &outside[..name_end];
    if name.is_empty() {
        return true;
    }
    let rest = outside[name_end..].trim_start();
    match rest.chars().next() {
        Some('=') => names.contains(&name),
        Some(':') => false,
        _ => true,
    }
}
