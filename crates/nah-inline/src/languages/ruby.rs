use crate::syntax::{StaticCallArgument, lexical_code_cased, static_call_arguments_cased};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_destructive_target_with_bindings, add_exact_inherited_argv,
    add_exact_shell, add_static_bound_shell_call, exact_string, exact_string_array, observe_shadow,
    ordered_active_segments, update_static_binding,
};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut fileutils = false;
    let mut kernel_owned = true;
    let mut system_shadowed = false;
    let mut exec_shadowed = false;
    let mut scoped_bindings = vec![(0usize, Vec::new())];
    let code = super::deferred::mask(input.code, program);
    for segment in ordered_active_segments(&code, program, DefinitionStyle::End, &mut report) {
        if !segment.executable {
            if super::common::shadowed(segment.source, program, "FileUtils")
                || ruby_namespace_reopened(segment.source, program, "FileUtils")
            {
                fileutils = false;
            }
            if super::common::shadowed(segment.source, program, "Kernel")
                || ruby_namespace_reopened(segment.source, program, "Kernel")
            {
                kernel_owned = false;
                system_shadowed = true;
                exec_shadowed = true;
            }
            observe_shadow(&mut system_shadowed, segment.source, program, "system");
            observe_shadow(&mut exec_shadowed, segment.source, program, "exec");
            continue;
        }
        if super::common::shadowed(segment.source, program, "FileUtils") {
            fileutils = false;
        }
        if super::common::shadowed(segment.source, program, "Kernel") {
            kernel_owned = false;
        }
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
        if !segment.state_exact {
            bindings.clear();
            fileutils = false;
            kernel_owned = false;
            system_shadowed = true;
            exec_shadowed = true;
        }
        let (outside, strings, offsets, static_strings, backtick_exec) =
            lexical_code_cased(segment.source, program);
        update_static_binding(bindings, segment.source, program, segment.state_exact);
        if backtick_exec
            && outside.trim().is_empty()
            && static_strings == [true]
            && let [code] = strings.as_slice()
        {
            add_exact_shell(&mut report, code, input.platform);
        }
        let compact = outside
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect::<String>();
        fileutils |= strings.as_slice() == ["fileutils"]
            && matches!(compact.as_str(), "require" | "require()");
        if fileutils {
            for name in ["FileUtils.rm_rf", "FileUtils.rm_r"] {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    name,
                    false,
                ) {
                    if arguments.len() != 1 {
                        continue;
                    }
                    add_destructive_target_with_bindings(
                        &mut report,
                        arguments.first(),
                        input.home,
                        input.platform,
                        bindings,
                    );
                }
            }
        }
        for (name, shadowed) in [("system", system_shadowed), ("exec", exec_shadowed)] {
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
                true,
            ) {
                add_ruby_process_call(&mut report, &arguments, input.platform, bindings);
            }
            if kernel_owned {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &format!("Kernel.{name}"),
                    false,
                ) {
                    add_ruby_process_call(&mut report, &arguments, input.platform, bindings);
                }
            }
        }
        observe_shadow(&mut system_shadowed, segment.source, program, "system");
        observe_shadow(&mut exec_shadowed, segment.source, program, "exec");
    }
    super::common::with_protection(report, program, input, protection)
}

fn ruby_namespace_reopened(source: &str, program: &str, expected: &str) -> bool {
    let source = crate::syntax::lexical_code_exact(source, program).0;
    ["class ", "module "]
        .iter()
        .find_map(|prefix| source.trim_start().strip_prefix(prefix))
        .and_then(|source| source.split([' ', '<']).next())
        == Some(expected)
}

fn add_ruby_process_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: nah_proto::ctx::Platform,
    bindings: &[(String, String)],
) {
    if arguments.len() == 1 && exact_string_array(&arguments[0]).is_none() {
        add_static_bound_shell_call(report, arguments, platform, true, bindings, &[]);
        return;
    }
    let Some(first) = arguments.first() else {
        return;
    };
    let mut argv = if let Some(pair) = exact_string_array(first) {
        let [program, _argv_zero] = pair.as_slice() else {
            return;
        };
        vec![program.clone()]
    } else if let Some(program) = exact_string(first) {
        vec![program.to_owned()]
    } else {
        return;
    };
    for argument in &arguments[1..] {
        let Some(value) = exact_string(argument) else {
            return;
        };
        argv.push(value.to_owned());
    }
    add_exact_inherited_argv(report, argv);
}
