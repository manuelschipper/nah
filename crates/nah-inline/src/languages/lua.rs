use crate::syntax::{lexical_code_cased, lexical_code_exact, static_call_arguments_cased};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_static_inherited_shell_call, add_static_shell_call, observe_shadow,
    ordered_active_segments, state_mutation_candidate,
};

#[derive(Clone, Default)]
struct LuaState {
    execute_shadowed: bool,
    popen_shadowed: bool,
    os_shadowed: bool,
    io_shadowed: bool,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut states = vec![(0usize, LuaState::default())];
    for segment in ordered_active_segments(input.code, program, DefinitionStyle::End, &mut report) {
        let scope = segment.scope;
        if !states.iter().any(|(known, _)| *known == scope) {
            states.push((scope, states[0].1.clone()));
        }
        let state_index = states
            .iter()
            .position(|(known, _)| *known == scope)
            .expect("scope was inserted");
        let state = &mut states[state_index].1;
        if !segment.state_exact {
            state.execute_shadowed = true;
            state.popen_shadowed = true;
            state.os_shadowed = true;
            state.io_shadowed = true;
        }
        if segment.executable {
            let (outside, strings, offsets, static_strings, _) =
                lexical_code_cased(segment.source, program);
            if state_mutation_candidate(segment.source, program) {
                state.execute_shadowed = true;
                state.popen_shadowed = true;
                state.os_shadowed = true;
                state.io_shadowed = true;
            }
            for (name, shadowed) in [
                ("os.execute", state.execute_shadowed || state.os_shadowed),
                ("io.popen", state.popen_shadowed || state.io_shadowed),
            ] {
                if shadowed {
                    continue;
                }
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    name,
                    false,
                ) {
                    if name == "os.execute" {
                        add_static_inherited_shell_call(&mut report, &arguments, input.platform);
                    } else {
                        add_static_shell_call(&mut report, &arguments, input.platform);
                    }
                }
            }
        }
        observe_shadow(
            &mut state.execute_shadowed,
            segment.source,
            program,
            "os.execute",
        );
        observe_shadow(
            &mut state.popen_shadowed,
            segment.source,
            program,
            "io.popen",
        );
        let os_replaced = lua_namespace_replaced(segment.source, program, "os");
        let io_replaced = lua_namespace_replaced(segment.source, program, "io");
        state.os_shadowed |= os_replaced;
        state.io_shadowed |= io_replaced;
        if scope != 0 && !segment.source.trim_start().starts_with("local ") {
            states[0].1.execute_shadowed |=
                super::common::shadowed(segment.source, program, "os.execute");
            states[0].1.popen_shadowed |=
                super::common::shadowed(segment.source, program, "io.popen");
            states[0].1.os_shadowed |= os_replaced;
            states[0].1.io_shadowed |= io_replaced;
        }
    }
    super::common::with_protection(report, program, input, protection)
}

fn lua_namespace_replaced(source: &str, program: &str, namespace: &str) -> bool {
    let outside = lexical_code_exact(source, program).0;
    let source = outside.trim_start();
    let declaration = source
        .strip_prefix("function ")
        .or_else(|| source.strip_prefix("local function "))
        .and_then(|rest| rest.split(['(', ' ']).next());
    if declaration == Some(namespace) {
        return true;
    }
    let local = source.strip_prefix("local ");
    let source = local.unwrap_or(source);
    if local.is_some()
        && source
            .split(['=', ',', ' '])
            .next()
            .is_some_and(|name| name == namespace)
    {
        return true;
    }
    source.match_indices('=').any(|(index, _)| {
        let previous = source[..index].bytes().next_back();
        let next = source.as_bytes().get(index + 1).copied();
        !matches!(previous, Some(b'=' | b'~' | b'<' | b'>'))
            && next != Some(b'=')
            && source[..index].trim() == namespace
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(code: &str) -> InlineReport {
        analyze(
            "lua",
            &InlineInput {
                program: "lua",
                code,
                home: "/home/dev",
                platform: nah_proto::ctx::Platform::Linux,
            },
            None,
        )
    }

    #[test]
    fn replaced_standard_namespaces_do_not_own_child_execution() {
        assert!(
            report("os.execute('rm -rf /')")
                .nested_executions()
                .iter()
                .next()
                .is_some()
        );
        assert!(
            report("os = {}; os.execute('rm -rf /')")
                .nested_executions()
                .is_empty()
        );
        assert!(
            report("local io = {}; io.popen('rm -rf /')")
                .nested_executions()
                .is_empty()
        );
        assert!(
            report("os == other; os.execute('rm -rf /')")
                .nested_executions()
                .iter()
                .next()
                .is_some()
        );
    }

    #[test]
    fn later_namespace_replacement_does_not_hide_an_earlier_call() {
        assert!(
            !report("os.execute('rm -rf /'); os = {}")
                .nested_executions()
                .is_empty()
        );
    }
}
