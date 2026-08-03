use crate::syntax::{lexical_code_cased, static_call_arguments_cased};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_exact_shell, add_static_bound_shell_call, observe_shadow,
    ordered_active_segments, update_static_binding,
};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let names = ["exec", "system", "shell_exec", "passthru", "proc_open"];
    let mut shadowed = [false; 5];
    let mut scoped_bindings = vec![(0usize, Vec::new())];
    let code = super::deferred::mask(input.code, program);
    for segment in ordered_active_segments(&code, program, DefinitionStyle::Braces, &mut report) {
        if segment.executable {
            if !scoped_bindings
                .iter()
                .any(|(scope, _)| *scope == segment.scope)
            {
                scoped_bindings.push((segment.scope, Vec::new()));
            }
            let bindings = &mut scoped_bindings
                .iter_mut()
                .find(|(scope, _)| *scope == segment.scope)
                .expect("scope was inserted")
                .1;
            let (exact_outside, strings, offsets, static_strings, backtick_exec) =
                lexical_code_cased(segment.source, program);
            let outside = exact_outside.to_ascii_lowercase();
            if !segment.state_exact {
                bindings.clear();
                shadowed.fill(true);
            }
            update_static_binding(bindings, segment.source, program, segment.state_exact);
            if backtick_exec
                && outside.trim().is_empty()
                && static_strings == [true]
                && let [code] = strings.as_slice()
            {
                add_exact_shell(&mut report, code, input.platform);
            }
            for (index, name) in names.iter().enumerate() {
                if shadowed[index] {
                    continue;
                }
                for arguments in static_call_arguments_cased(
                    &outside,
                    &exact_outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    name,
                    true,
                ) {
                    let Some(arguments) = supported_php_arguments(name, &arguments) else {
                        continue;
                    };
                    add_static_bound_shell_call(
                        &mut report,
                        arguments,
                        input.platform,
                        matches!(*name, "system" | "passthru"),
                        bindings,
                        &["command"],
                    );
                }
            }
        }
        for (index, name) in names.iter().enumerate() {
            observe_shadow(&mut shadowed[index], segment.source, program, name);
        }
    }
    super::common::with_protection(report, program, input, protection)
}

fn supported_php_arguments<'a>(
    name: &str,
    arguments: &'a [crate::syntax::StaticCallArgument],
) -> Option<&'a [crate::syntax::StaticCallArgument]> {
    let arguments = if arguments.last().is_some_and(empty_argument) {
        &arguments[..arguments.len() - 1]
    } else {
        arguments
    };
    let mut named_seen = false;
    for argument in arguments {
        let named = argument.outside.contains(':');
        if named_seen && !named {
            return None;
        }
        named_seen |= named;
    }
    let shape = match name {
        "shell_exec" => arguments.len() == 1 && slot(&arguments[0], "command", false),
        "system" | "passthru" => {
            (1..=2).contains(&arguments.len())
                && slot(&arguments[0], "command", false)
                && arguments
                    .get(1)
                    .is_none_or(|argument| slot(argument, "result_code", true))
        }
        "exec" => {
            (1..=3).contains(&arguments.len())
                && slot(&arguments[0], "command", false)
                && arguments
                    .get(1)
                    .is_none_or(|argument| slot(argument, "output", true))
                && arguments
                    .get(2)
                    .is_none_or(|argument| slot(argument, "result_code", true))
        }
        "proc_open" => {
            arguments.len() == 3
                && slot(&arguments[0], "command", false)
                && empty_array_slot(&arguments[1], "descriptor_spec")
                && slot(&arguments[2], "pipes", true)
        }
        _ => false,
    };
    shape.then_some(arguments)
}

fn empty_argument(argument: &crate::syntax::StaticCallArgument) -> bool {
    argument.outside.trim().is_empty() && argument.strings.is_empty()
}

fn slot(argument: &crate::syntax::StaticCallArgument, name: &str, variable: bool) -> bool {
    let outside = argument.outside.trim();
    let (expression, named) = outside
        .split_once(':')
        .map(|(actual, expression)| (expression.trim(), actual.trim() == name))
        .unwrap_or((outside, true));
    if !named {
        return false;
    }
    if variable {
        return argument.strings.is_empty()
            && expression.strip_prefix('$').is_some_and(php_identifier);
    }
    !expression.contains(':')
}

fn empty_array_slot(argument: &crate::syntax::StaticCallArgument, name: &str) -> bool {
    let outside = argument.outside.trim();
    let (expression, named) = outside
        .split_once(':')
        .map(|(actual, expression)| (expression.trim(), actual.trim() == name))
        .unwrap_or((outside, true));
    named && argument.strings.is_empty() && matches!(expression, "[]" | "array()")
}

fn php_identifier(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
