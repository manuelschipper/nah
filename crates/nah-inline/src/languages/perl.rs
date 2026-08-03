use crate::syntax::{StaticCallArgument, lexical_code_cased, static_call_arguments_cased};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_destructive_target_with_bindings, add_exact_inherited_argv,
    add_exact_shell, add_static_bound_shell_call, assigned_identifier, exact_string,
    observe_shadow, ordered_active_segments, update_static_binding,
};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut file_path = false;
    let mut remove_tree_shadowed = false;
    let mut rmtree_shadowed = false;
    let mut system_shadowed = false;
    let mut exec_shadowed = false;
    let mut scoped_bindings = vec![(0usize, Vec::new())];
    let code = super::deferred::mask(input.code, program);
    for segment in ordered_active_segments(&code, program, DefinitionStyle::Braces, &mut report) {
        let scope = segment.scope;
        if !scoped_bindings.iter().any(|(known, _)| *known == scope) {
            scoped_bindings.push((scope, scoped_bindings[0].1.clone()));
        }
        let binding_index = scoped_bindings
            .iter()
            .position(|(known, _)| *known == scope)
            .expect("scope was inserted");
        let declaration = segment.source.trim_start().starts_with("sub ");
        if declaration {
            observe_shadow(
                &mut remove_tree_shadowed,
                segment.source,
                program,
                "remove_tree",
            );
            observe_shadow(&mut rmtree_shadowed, segment.source, program, "rmtree");
            observe_shadow(&mut system_shadowed, segment.source, program, "system");
            observe_shadow(&mut exec_shadowed, segment.source, program, "exec");
        }
        if !segment.executable {
            continue;
        }
        file_path |= segment.source.trim_start().starts_with("use File::Path");
        let (outside, strings, offsets, static_strings, backtick_exec) =
            lexical_code_cased(segment.source, program);
        let bindings = &mut scoped_bindings[binding_index].1;
        if !segment.state_exact {
            bindings.clear();
            file_path = false;
            remove_tree_shadowed = true;
            rmtree_shadowed = true;
            system_shadowed = true;
            exec_shadowed = true;
        }
        update_static_binding(bindings, segment.source, program, segment.state_exact);
        if backtick_exec
            && outside.trim().is_empty()
            && static_strings == [true]
            && let [code] = strings.as_slice()
        {
            add_exact_shell(&mut report, code, input.platform);
        }
        if file_path {
            for (name, shadowed) in [
                ("remove_tree", remove_tree_shadowed),
                ("rmtree", rmtree_shadowed),
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
                    true,
                ) {
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
                add_perl_process_call(&mut report, &arguments, input.platform, bindings);
            }
        }
        observe_shadow(
            &mut remove_tree_shadowed,
            segment.source,
            program,
            "remove_tree",
        );
        observe_shadow(&mut rmtree_shadowed, segment.source, program, "rmtree");
        observe_shadow(&mut system_shadowed, segment.source, program, "system");
        observe_shadow(&mut exec_shadowed, segment.source, program, "exec");
        let local = segment.source.trim_start();
        if scope != 0
            && !local.starts_with("my ")
            && !local.starts_with("local ")
            && let Some(name) = assigned_identifier(&outside)
        {
            scoped_bindings[0].1.retain(|(bound, _)| bound != name);
        }
    }
    super::common::with_protection(report, program, input, protection)
}

fn add_perl_process_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: nah_proto::ctx::Platform,
    bindings: &[(String, String)],
) {
    if arguments.len() == 1 {
        add_static_bound_shell_call(report, arguments, platform, true, bindings, &[]);
        return;
    }
    let mut argv = Vec::new();
    for argument in arguments {
        let Some(value) = exact_string(argument) else {
            return;
        };
        argv.push(value.to_owned());
    }
    add_exact_inherited_argv(report, argv);
}
