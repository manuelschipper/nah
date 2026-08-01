//! Bounded inline interpreter analysis for self-protection.

mod syntax;

use nah_parse::Word;
use nah_proto::action::SemanticCode;
use nah_proto::ctx::{AbsolutePath, Platform};

use crate::bash_execution::{is_perl_interpreter, is_python_interpreter};
use crate::bash_model::{InvocationDraft, VariableValue};
use crate::paths::resolve_from_cwd;

use super::{
    EnvironmentVariables, environment_operation, normalized_program,
    protected_access_control_operation, protected_path, protected_path_ancestor,
    runtime_launch_bypass, runtime_launch_program, runtime_name,
};
use syntax::{
    StaticCallArgument, code_segments, contains_call, lexical_code, lexical_code_exact,
    named_call_argument, static_call_arguments, static_call_arguments_at,
};

pub(crate) fn reclassify_inline(
    invocation: &mut InvocationDraft,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
) {
    let InvocationDraft::CodeExecution {
        program,
        code: Some(code),
        ..
    } = invocation
    else {
        return;
    };
    if !inline_critical_mutation(
        program,
        code,
        home,
        critical_paths,
        platform,
        baseline_variables,
    ) {
        return;
    }
    let InvocationDraft::CodeExecution {
        program,
        words,
        argv,
        ..
    } = invocation.clone()
    else {
        unreachable!("the invocation was checked above");
    };
    *invocation = InvocationDraft::Known {
        program,
        operation: SemanticCode::CRITICAL_MUTATION,
        words,
        argv,
    };
}

fn inline_critical_mutation(
    program: &str,
    code: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
) -> bool {
    inline_critical_mutation_inner(
        program,
        code,
        home,
        critical_paths,
        platform,
        baseline_variables,
        0,
    )
}

fn inline_critical_mutation_inner(
    program: &str,
    code: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
    depth: usize,
) -> bool {
    let mut program = normalized_program(program);
    if is_perl_interpreter(&program) {
        program = "perl".to_owned();
    }
    if !matches!(
        program.as_str(),
        "node"
            | "nodejs"
            | "perl"
            | "ruby"
            | "php"
            | "lua"
            | "r"
            | "rscript"
            | "julia"
            | "swift"
            | "powershell"
            | "pwsh"
            | "cmd"
    ) && !is_python_interpreter(&program)
    {
        return false;
    }

    let segments = code_segments(code, &program);
    if is_python_interpreter(&program)
        && python_variable_mutates_protected(
            &segments,
            home,
            critical_paths,
            platform,
            baseline_variables,
        )
    {
        return true;
    }
    let python = is_python_interpreter(&program);
    let mut python_os_shadowed = false;
    let mut python_subprocess_shadowed = false;
    for code in segments {
        let (outside, strings, string_offsets, backtick_exec) = lexical_code(code, &program);
        let mutates = (depth < 16
            && strings
                .iter()
                .zip(&string_offsets)
                .filter(|(_, offset)| direct_code_string(&program, &outside, **offset))
                .any(|(nested, _)| {
                    inline_critical_mutation_inner(
                        &program,
                        nested,
                        home,
                        critical_paths,
                        platform,
                        baseline_variables,
                        depth + 1,
                    )
                }))
            || (mutation_action(
                &program,
                &outside,
                &strings,
                backtick_exec,
                python_os_shadowed,
            ) && protected_target(
                &outside,
                &strings,
                home,
                critical_paths,
                platform,
                !matches!(program.as_str(), "powershell" | "pwsh" | "cmd"),
                baseline_variables,
            ))
            || (is_python_interpreter(&program)
                && python_mutates_protected_ancestor(
                    &outside,
                    &strings,
                    &string_offsets,
                    home,
                    critical_paths,
                    platform,
                ))
            || role_sensitive_mutation(
                &program,
                &outside,
                &strings,
                &string_offsets,
                home,
                critical_paths,
                platform,
                baseline_variables,
                python_os_shadowed,
                python_subprocess_shadowed,
            )
            || inline_direct_runtime_bypass(
                &outside,
                &strings,
                &string_offsets,
                &program,
                home,
                platform,
            );
        if mutates {
            return true;
        }
        if python {
            python_os_shadowed |= python_receiver_reassigned(&outside, "os");
            python_subprocess_shadowed |= python_receiver_reassigned(&outside, "subprocess");
        }
    }
    false
}

fn python_variable_mutates_protected(
    segments: &[&str],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
) -> bool {
    let mut protected_variables = Vec::<String>::new();
    let mut protected_ancestor_variables = Vec::<String>::new();
    for segment in segments {
        let (outside, strings, string_offsets, _) = lexical_code_exact(segment, "python");
        if protected_python_variable_is_mutated(
            &outside,
            &strings,
            &string_offsets,
            &protected_variables,
        ) {
            return true;
        }
        if protected_python_ancestor_variable_is_mutated(
            &outside,
            &strings,
            &string_offsets,
            &protected_ancestor_variables,
        ) {
            return true;
        }
        let Some((name, expression)) = python_assignment(&outside) else {
            continue;
        };
        let path_expression = python_path_expression(expression);
        let protected = path_expression
            && protected_target(
                expression,
                &strings,
                home,
                critical_paths,
                platform,
                false,
                baseline_variables,
            );
        let protected_ancestor = path_expression
            && protected_namespace_ancestor_target(
                expression,
                &strings,
                home,
                critical_paths,
                platform,
            );
        protected_variables.retain(|variable| variable != name);
        protected_ancestor_variables.retain(|variable| variable != name);
        if protected {
            protected_variables.push(name.to_owned());
        }
        if protected_ancestor {
            protected_ancestor_variables.push(name.to_owned());
        }
    }
    false
}

fn python_assignment(outside: &str) -> Option<(&str, &str)> {
    let (name, expression) = outside.split_once('=')?;
    let name = name.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || name.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || expression.trim_start().starts_with('=')
    {
        return None;
    }
    Some((name, expression))
}

fn python_path_expression(expression: &str) -> bool {
    let expression = expression.trim();
    let lower = expression.to_ascii_lowercase();
    expression.is_empty()
        || [
            "path(",
            "path.home(",
            "os.path.",
            "expanduser(",
            "abspath(",
            "realpath(",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn protected_python_variable_is_mutated(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    variables: &[String],
) -> bool {
    variables.iter().any(|variable| {
        [
            "unlink",
            "rename",
            "replace",
            "write_text",
            "write_bytes",
            "touch",
            "mkdir",
            "rmdir",
            "chmod",
            "hardlink_to",
            "link_to",
            "symlink_to",
        ]
        .iter()
        .any(|method| contains_call(outside, &format!("{variable}.{method}"), false))
            || [
                ("os.remove", 1),
                ("os.unlink", 1),
                ("os.rename", 2),
                ("os.replace", 2),
                ("os.link", 2),
                ("os.symlink", 2),
                ("os.chmod", 1),
                ("os.chown", 1),
                ("os.lchown", 1),
                ("os.mkdir", 1),
                ("os.makedirs", 1),
                ("os.rmdir", 1),
                ("os.removedirs", 1),
                ("os.truncate", 1),
                ("shutil.rmtree", 1),
                ("shutil.move", 2),
                (".rename", 1),
                (".replace", 1),
                (".hardlink_to", 1),
                (".link_to", 1),
                (".symlink_to", 1),
            ]
            .iter()
            .any(|(call, targets)| {
                static_call_arguments(outside, strings, string_offsets, call, false)
                    .iter()
                    .any(|arguments| {
                        arguments
                            .iter()
                            .take(*targets)
                            .any(|argument| argument_mentions_variable(argument, variable))
                    })
            })
    })
}

fn argument_mentions_variable(argument: &StaticCallArgument, variable: &str) -> bool {
    argument
        .outside
        .split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .any(|word| word == variable)
}

fn protected_python_ancestor_variable_is_mutated(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    variables: &[String],
) -> bool {
    variables.iter().any(|variable| {
        ["unlink", "rename", "replace", "rmdir", "chmod"]
            .iter()
            .any(|method| contains_call(outside, &format!("{variable}.{method}"), false))
            || [
                ("os.remove", 1),
                ("os.unlink", 1),
                ("os.rename", 2),
                ("os.replace", 2),
                ("os.rmdir", 1),
                ("os.removedirs", 1),
                ("os.chmod", 1),
                ("os.chown", 1),
                ("os.lchown", 1),
                ("shutil.rmtree", 1),
                ("shutil.move", 2),
                (".rename", 1),
                (".replace", 1),
            ]
            .iter()
            .any(|(call, targets)| {
                static_call_arguments(outside, strings, string_offsets, call, false)
                    .iter()
                    .any(|arguments| {
                        arguments
                            .iter()
                            .take(*targets)
                            .any(|argument| argument_mentions_variable(argument, variable))
                    })
            })
    })
}

fn direct_code_string(program: &str, outside: &str, offset: usize) -> bool {
    let before = outside[..offset].trim_end();
    if matches!(program, "powershell" | "pwsh")
        && ["invoke-expression", "iex"]
            .iter()
            .any(|name| before.strip_suffix(name).is_some_and(word_prefix))
    {
        return true;
    }
    if matches!(program, "r" | "rscript")
        && before
            .strip_suffix("eval(parse(text=")
            .is_some_and(word_prefix)
    {
        return true;
    }
    let Some(before_parenthesis) = before.strip_suffix('(') else {
        return false;
    };
    let before_parenthesis = before_parenthesis.trim_end();
    let names: &[&str] = if is_python_interpreter(program) {
        &["eval", "exec"]
    } else {
        match program {
            "node" | "nodejs" => &["eval", "function"],
            "perl" | "ruby" | "php" => &["eval"],
            _ => &[],
        }
    };
    names.iter().any(|name| {
        before_parenthesis.strip_suffix(name).is_some_and(|prefix| {
            !prefix
                .chars()
                .next_back()
                .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
        })
    }) || (program == "lua"
        && before_parenthesis
            .strip_suffix("load")
            .is_some_and(word_prefix)
        && outside[offset..].trim_start().starts_with(")()"))
        || (is_python_interpreter(program)
            && before_parenthesis
                .strip_suffix("exec(compile")
                .is_some_and(word_prefix))
        || (matches!(program, "r" | "rscript")
            && before_parenthesis
                .strip_suffix("eval(parse")
                .is_some_and(word_prefix))
        || (program == "julia"
            && before_parenthesis
                .strip_suffix("eval(meta.parse")
                .is_some_and(word_prefix))
}

fn word_prefix(prefix: &str) -> bool {
    !prefix
        .chars()
        .next_back()
        .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[allow(clippy::too_many_arguments)]
fn role_sensitive_mutation(
    program: &str,
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
    python_os_shadowed: bool,
    python_subprocess_shadowed: bool,
) -> bool {
    let protected_argument = |argument: &StaticCallArgument| {
        protected_target(
            &argument.outside,
            &argument.strings,
            home,
            critical_paths,
            platform,
            false,
            baseline_variables,
        )
    };
    if static_dispatch_mutates_protected(
        program,
        outside,
        strings,
        string_offsets,
        home,
        critical_paths,
        platform,
        baseline_variables,
        python_os_shadowed,
        python_subprocess_shadowed,
    ) {
        return true;
    }
    let copy_calls: &[(&str, bool)] = if is_python_interpreter(program) {
        &[
            ("shutil.copy", false),
            ("shutil.copy2", false),
            ("shutil.copyfile", false),
            ("shutil.copytree", false),
            ("shutil.copymode", false),
            ("copy", true),
            ("copy2", true),
            ("copyfile", true),
            ("copytree", true),
        ]
    } else {
        match program {
            "perl" | "php" => &[("copy", true)],
            "julia" => &[("cp", true)],
            "node" | "nodejs" => &[
                (".copyfile", false),
                (".copyfilesync", false),
                ("copyfile", true),
                ("copyfilesync", true),
            ],
            "ruby" => &[("fileutils.cp", false), ("fileutils.copy", false)],
            "r" | "rscript" => &[("file.copy", false)],
            "swift" => &[(".copyitem", false)],
            _ => &[],
        }
    };
    for (name, bare) in copy_calls {
        for arguments in static_call_arguments(outside, strings, string_offsets, name, *bare) {
            let target = arguments
                .iter()
                .find(|argument| {
                    named_call_argument(argument, &["dst", "destination", "to", "topath"])
                })
                .or_else(|| arguments.get(1));
            if target.is_some_and(&protected_argument) {
                return true;
            }
        }
    }
    if !is_python_interpreter(program) {
        return false;
    }
    for (name, bare) in [("open", true), ("io.fileio", false)] {
        for arguments in static_call_arguments(outside, strings, string_offsets, name, bare) {
            let target = arguments
                .iter()
                .find(|argument| named_call_argument(argument, &["file"]))
                .or_else(|| arguments.first());
            let mode = arguments
                .iter()
                .find(|argument| named_call_argument(argument, &["mode"]))
                .or_else(|| arguments.get(1));
            if target.is_some_and(&protected_argument)
                && mode.is_some_and(|mode| write_mode(&mode.strings))
            {
                return true;
            }
        }
    }
    for name in [
        "subprocess.run",
        "subprocess.call",
        "subprocess.popen",
        "os.system",
    ] {
        if python_subprocess_shadowed && name.starts_with("subprocess.")
            || python_os_shadowed && name.starts_with("os.")
        {
            continue;
        }
        for arguments in static_call_arguments(outside, strings, string_offsets, name, false) {
            let values = arguments
                .first()
                .map(|argument| argument.strings.as_slice())
                .unwrap_or_default();
            let lifecycle = values.get(..4).is_some_and(|parts| {
                normalized_program(&parts[0]) == "nah"
                    && parts[1] == "hook"
                    && runtime_name(&parts[2])
                    && matches!(parts[3].as_str(), "install" | "uninstall")
            });
            if lifecycle
                || inline_runtime_bypass(values, home, critical_paths, platform, baseline_variables)
                || exact_child_mutates_protected(values, home, critical_paths, platform)
            {
                return true;
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn static_dispatch_mutates_protected(
    program: &str,
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
    python_os_shadowed: bool,
    python_subprocess_shadowed: bool,
) -> bool {
    // Selector mentions stay inert unless an exact receiver invokes them with
    // a protected target or a recognized hook-skipping runtime launch.
    let protected = |argument: &StaticCallArgument| {
        protected_target(
            &argument.outside,
            &argument.strings,
            home,
            critical_paths,
            platform,
            false,
            baseline_variables,
        )
    };
    let mutating_arguments = |arguments: &[StaticCallArgument], skip: usize, count: usize| {
        arguments
            .iter()
            .skip(skip)
            .take(count)
            .any(|argument| python_direct_static_argument(argument) && protected(argument))
    };
    let runtime_arguments = |arguments: &[StaticCallArgument], skip: usize| {
        let values = arguments
            .iter()
            .skip(skip)
            .flat_map(|argument| argument.strings.iter().cloned())
            .collect::<Vec<_>>();
        inline_runtime_bypass(&values, home, critical_paths, platform, baseline_variables)
    };
    let python_runtime_arguments = |arguments: &[StaticCallArgument]| {
        let Some(argument) = arguments.first() else {
            return false;
        };
        argument.outside.bytes().all(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'[' | b']' | b'(' | b')' | b',')
        }) && inline_runtime_bypass(
            &argument.strings,
            home,
            critical_paths,
            platform,
            baseline_variables,
        )
    };

    if is_python_interpreter(program) {
        for (selector, offset) in strings.iter().zip(string_offsets) {
            if !python_os_shadowed
                && let Some(open) = python_getattr_call_open(outside, *offset, "os")
                && static_call_arguments_at(outside, strings, string_offsets, open).is_some_and(
                    |arguments| {
                        python_os_target_count(selector)
                            .is_some_and(|count| mutating_arguments(&arguments, 0, count))
                    },
                )
            {
                return true;
            }
            if !python_subprocess_shadowed
                && let Some(open) = python_getattr_call_open(outside, *offset, "subprocess")
                && matches!(
                    selector.to_ascii_lowercase().as_str(),
                    "run" | "call" | "popen"
                )
                && static_call_arguments_at(outside, strings, string_offsets, open)
                    .is_some_and(|arguments| python_runtime_arguments(&arguments))
            {
                return true;
            }
        }
    }

    if matches!(program, "node" | "nodejs") {
        for selector_index in 1..strings.len() {
            let selector = &strings[selector_index];
            let module = strings[selector_index - 1].as_str();
            let Some(open) =
                node_require_selector_call_open(outside, string_offsets, selector_index, module)
            else {
                continue;
            };
            let Some(arguments) = static_call_arguments_at(outside, strings, string_offsets, open)
            else {
                continue;
            };
            if matches!(module, "fs" | "node:fs")
                && node_fs_target_count(selector)
                    .is_some_and(|count| mutating_arguments(&arguments, 0, count))
                || matches!(module, "child_process" | "node:child_process")
                    && matches!(
                        selector.to_ascii_lowercase().as_str(),
                        "exec" | "execfile" | "fork" | "spawn"
                    )
                    && runtime_arguments(&arguments, 0)
            {
                return true;
            }
        }
    }

    if program == "ruby" {
        for arguments in static_call_arguments(outside, strings, string_offsets, "file.send", false)
        {
            if arguments
                .first()
                .and_then(static_selector)
                .is_some_and(|selector| {
                    ruby_file_target_count(&selector)
                        .is_some_and(|count| mutating_arguments(&arguments, 1, count))
                })
            {
                return true;
            }
        }
        for arguments in
            static_call_arguments(outside, strings, string_offsets, "process.send", false)
        {
            if arguments
                .first()
                .and_then(static_selector)
                .is_some_and(|selector| selector == "spawn" && runtime_arguments(&arguments, 1))
            {
                return true;
            }
        }
    }

    if program == "php" {
        for arguments in
            static_call_arguments(outside, strings, string_offsets, "call_user_func", true)
        {
            let Some(selector) = arguments.first().and_then(static_selector) else {
                continue;
            };
            if php_target_count(&selector)
                .is_some_and(|count| mutating_arguments(&arguments, 1, count))
                || matches!(selector.as_str(), "exec" | "system")
                    && runtime_arguments(&arguments, 1)
            {
                return true;
            }
        }
    }
    false
}

fn python_os_target_count(selector: &str) -> Option<usize> {
    match selector.to_ascii_lowercase().as_str() {
        "remove" | "unlink" | "rmdir" | "removedirs" | "chmod" | "chown" | "lchown"
        | "truncate" => Some(1),
        "rename" | "replace" | "link" | "symlink" => Some(2),
        _ => None,
    }
}

fn node_fs_target_count(selector: &str) -> Option<usize> {
    match selector.to_ascii_lowercase().as_str() {
        "unlink" | "unlinksync" | "rm" | "rmsync" | "rmdir" | "chmod" | "chmodsync" | "chown"
        | "chownsync" | "truncate" | "truncatesync" | "writefile" | "writefilesync"
        | "appendfile" | "appendfilesync" | "createwritestream" => Some(1),
        "rename" | "renamesync" | "link" | "linksync" | "symlink" | "symlinksync" => Some(2),
        _ => None,
    }
}

fn ruby_file_target_count(selector: &str) -> Option<usize> {
    match selector {
        "delete" | "unlink" | "truncate" => Some(1),
        "rename" | "link" | "symlink" => Some(2),
        _ => None,
    }
}

fn php_target_count(selector: &str) -> Option<usize> {
    match selector {
        "unlink" | "rmdir" | "chmod" | "chown" | "touch" | "file_put_contents" => Some(1),
        "rename" | "link" | "symlink" => Some(2),
        _ => None,
    }
}

fn python_getattr_call_open(
    outside: &str,
    selector_offset: usize,
    receiver: &str,
) -> Option<usize> {
    let before = outside[..selector_offset].trim_end();
    if python_receiver_reassigned(before, receiver) {
        return None;
    }
    let start = before.rfind("getattr")?;
    if !word_prefix(&before[..start]) {
        return None;
    }
    let call = before[start..]
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if call != format!("getattr({receiver},") {
        return None;
    }
    call_open_after_selector(outside, selector_offset, ')')
}

fn python_receiver_reassigned(source: &str, receiver: &str) -> bool {
    let bytes = source.as_bytes();
    let receiver = receiver.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ if depth == 0 && bytes.get(index..index + receiver.len()) == Some(receiver) => {
                let before = index.checked_sub(1).and_then(|index| bytes.get(index));
                let mut after = index + receiver.len();
                let boundary = before
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                    && bytes
                        .get(after)
                        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
                while bytes.get(after).is_some_and(u8::is_ascii_whitespace) {
                    after += 1;
                }
                if boundary
                    && bytes.get(after) == Some(&b'=')
                    && bytes.get(after + 1) != Some(&b'=')
                {
                    return true;
                }
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn python_direct_static_argument(argument: &StaticCallArgument) -> bool {
    argument.outside.bytes().all(|byte| {
        byte.is_ascii_whitespace()
            || matches!(byte, b'[' | b']' | b'{' | b'}' | b'(' | b')' | b',' | b'+')
    })
}

fn node_require_selector_call_open(
    outside: &str,
    string_offsets: &[usize],
    selector_index: usize,
    module: &str,
) -> Option<usize> {
    if !matches!(
        module,
        "fs" | "node:fs" | "child_process" | "node:child_process"
    ) {
        return None;
    }
    let module_offset = *string_offsets.get(selector_index - 1)?;
    let selector_offset = *string_offsets.get(selector_index)?;
    let before = outside[..module_offset].trim_end();
    let prefix = before.strip_suffix("require(")?;
    if !word_prefix(prefix) {
        return None;
    }
    let between = outside[module_offset..selector_offset]
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if between != ")[" {
        return None;
    }
    call_open_after_selector(outside, selector_offset, ']')
}

fn call_open_after_selector(outside: &str, selector_offset: usize, close: char) -> Option<usize> {
    let tail = &outside[selector_offset..];
    let close_offset =
        selector_offset + tail.find(|character: char| !character.is_ascii_whitespace())?;
    if outside[close_offset..].chars().next()? != close {
        return None;
    }
    let after_close = close_offset + close.len_utf8();
    let tail = &outside[after_close..];
    let open = after_close + tail.find(|character: char| !character.is_ascii_whitespace())?;
    (outside.as_bytes().get(open) == Some(&b'(')).then_some(open)
}

fn static_selector(argument: &StaticCallArgument) -> Option<String> {
    if argument.strings.len() == 1 && argument.outside.trim().is_empty() {
        return Some(argument.strings[0].to_ascii_lowercase());
    }
    let selector = argument.outside.trim().strip_prefix(':')?;
    (!selector.is_empty()
        && selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then(|| selector.to_ascii_lowercase())
}

fn exact_child_mutates_protected(
    values: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let words = if values.len() == 1 {
        values[0]
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        values.to_vec()
    };
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    let program = normalized_program(program);
    if matches!(program.as_str(), "sh" | "bash")
        && arguments.first().is_some_and(|argument| argument == "-c")
    {
        return arguments.get(1).is_some_and(|code| {
            exact_child_mutates_protected(&[code.to_owned()], home, critical_paths, platform)
        });
    }
    let argument_words = arguments
        .iter()
        .map(|argument| Word::from_literal(argument))
        .collect::<Vec<_>>();
    if protected_access_control_operation(
        &program,
        &argument_words,
        None,
        home,
        critical_paths,
        platform,
    )
    .is_some()
    {
        return true;
    }
    if !matches!(program.as_str(), "rm" | "rmdir" | "unlink") {
        return false;
    }
    arguments
        .iter()
        .skip_while(|argument| argument.starts_with('-') && argument.as_str() != "--")
        .filter(|argument| argument.as_str() != "--")
        .any(|target| {
            let target = resolve_from_cwd(None, None, target, home, platform, true)
                .unwrap_or_else(|| target.to_owned());
            protected_path(&target, home, critical_paths, platform)
        })
}

fn contains_command_alias(source: &str, aliases: &[&str]) -> bool {
    source
        .split(['|', '&', '{', '}'])
        .map(str::trim_start)
        .any(|command| {
            aliases.iter().any(|alias| {
                command
                    .strip_prefix(alias)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
            })
        })
}

fn contains_word(source: &str, word: &str) -> bool {
    source.match_indices(word).any(|(index, _)| {
        let identifier = |character: char| character.is_ascii_alphanumeric() || character == '_';
        !source[..index].chars().next_back().is_some_and(identifier)
            && !source[index + word.len()..]
                .chars()
                .next()
                .is_some_and(identifier)
    })
}

fn write_mode(strings: &[String]) -> bool {
    strings.iter().any(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "w" | "wb"
                | "w+"
                | "wb+"
                | "w+b"
                | "a"
                | "ab"
                | "a+"
                | "ab+"
                | "a+b"
                | "x"
                | "xb"
                | "x+"
                | "xb+"
                | "x+b"
                | "c"
                | "c+"
                | ">"
                | ">>"
                | "+>"
        ) || value.starts_with(">:")
    })
}

fn mutation_action(
    program: &str,
    outside: &str,
    strings: &[String],
    backtick_exec: bool,
    python_os_shadowed: bool,
) -> bool {
    let contains_any = |needles: &[&str]| needles.iter().any(|needle| outside.contains(needle));
    let contains_calls =
        |names: &[&str]| names.iter().any(|name| contains_call(outside, name, false));
    let contains_bare_calls =
        |names: &[&str]| names.iter().any(|name| contains_call(outside, name, true));
    let language_action = if is_python_interpreter(program) {
        (!python_os_shadowed
            && contains_calls(&[
                "os.remove",
                "os.unlink",
                "os.rename",
                "os.replace",
                "os.link",
                "os.symlink",
                "os.chmod",
                "os.chown",
                "os.lchown",
                "os.mkdir",
                "os.makedirs",
                "os.rmdir",
                "os.removedirs",
                "os.truncate",
            ]))
            || contains_calls(&[
                "shutil.rmtree",
                "shutil.move",
                ".unlink",
                ".rename",
                ".replace",
                ".write_text",
                ".write_bytes",
                ".touch",
                ".mkdir",
                ".rmdir",
                ".chmod",
                ".hardlink_to",
                ".link_to",
                ".symlink_to",
            ])
            || contains_bare_calls(&["remove", "unlink", "rename", "replace", "rmtree", "move"])
            || (strings.iter().any(|value| value == "os")
                && contains_call(outside, "__import__", true)
                && contains_calls(&[
                    ".remove", ".unlink", ".rename", ".replace", ".link", ".symlink", ".chmod",
                    ".chown", ".rmdir",
                ]))
            || !python_os_shadowed
                && contains_call(outside, "os.open", false)
                && contains_any(&["o_wronly", "o_rdwr", "o_append", "o_creat", "o_trunc"])
    } else {
        match program {
            "perl" => {
                contains_any(&[
                    "unlink ",
                    "link ",
                    "symlink ",
                    "rename ",
                    "rmdir ",
                    "mkdir ",
                    "chmod ",
                    "chown ",
                    "truncate ",
                    "system ",
                    "exec ",
                ]) || contains_bare_calls(&[
                    "unlink",
                    "link",
                    "symlink",
                    "rename",
                    "rmdir",
                    "mkdir",
                    "chmod",
                    "chown",
                    "truncate",
                    "move",
                    "remove_tree",
                    "rmtree",
                    "make_path",
                    "system",
                    "exec",
                ]) || (contains_bare_calls(&["sysopen"])
                    && contains_any(&["o_wronly", "o_rdwr", "o_append", "o_creat", "o_trunc"]))
            }
            "node" | "nodejs" => {
                contains_calls(&[
                    ".remove",
                    ".unlink",
                    ".unlinksync",
                    ".rename",
                    ".renamesync",
                    ".rm",
                    ".rmsync",
                    ".writefile",
                    ".writefilesync",
                    ".appendfile",
                    ".appendfilesync",
                    ".createwritestream",
                    ".link",
                    ".linksync",
                    ".symlink",
                    ".symlinksync",
                    ".truncate",
                    ".truncatesync",
                    ".chmod",
                    ".chmodsync",
                    ".chown",
                    ".chownsync",
                    ".mkdir",
                    ".mkdirsync",
                    "child_process.exec",
                    "child_process.spawn",
                ]) || contains_bare_calls(&[
                    "remove",
                    "unlink",
                    "unlinksync",
                    "rename",
                    "renamesync",
                    "rm",
                    "rmsync",
                    "writefile",
                    "writefilesync",
                    "appendfile",
                    "appendfilesync",
                    "createwritestream",
                    "link",
                    "linksync",
                    "symlink",
                    "symlinksync",
                    "truncate",
                    "truncatesync",
                    "chmod",
                    "chmodsync",
                    "chown",
                    "chownsync",
                    "mkdir",
                    "mkdirsync",
                ]) || ((contains_calls(&[".open", ".opensync"])
                    || contains_bare_calls(&["open", "opensync"]))
                    && write_mode(strings))
                    || strings.iter().any(|value| {
                        matches!(value.as_str(), "child_process" | "node:child_process")
                    }) && contains_calls(&[".exec", ".execfile", ".fork", ".spawn"])
            }
            "ruby" => {
                contains_calls(&[
                    "file.delete",
                    "file.unlink",
                    "file.rename",
                    "file.link",
                    "file.symlink",
                    "file.truncate",
                    "file.write",
                    "io.write",
                    "fileutils.rm",
                    "fileutils.rm_rf",
                    "fileutils.mv",
                    "dir.mkdir",
                    "spawn",
                ]) || contains_any(&["system ", "exec "])
                    || contains_bare_calls(&["system", "exec"])
            }
            "php" => contains_bare_calls(&[
                "unlink",
                "rename",
                "rmdir",
                "mkdir",
                "chmod",
                "chown",
                "touch",
                "link",
                "symlink",
                "file_put_contents",
                "exec",
                "system",
            ]),
            "lua" => {
                contains_calls(&["os.remove", "os.rename", "os.execute"])
                    || contains_calls(&["io.open"]) && write_mode(strings)
            }
            "r" | "rscript" => contains_calls(&[
                "file.remove",
                "unlink",
                "file.rename",
                "file.create",
                "dir.create",
                "writelines",
                "system",
                "system2",
            ]),
            "julia" => {
                contains_bare_calls(&["rm", "mv", "touch", "mkdir", "mkpath", "chmod", "run"])
                    || contains_bare_calls(&["open"]) && write_mode(strings)
            }
            "swift" => contains_calls(&[
                ".removeitem",
                ".moveitem",
                ".createfile",
                ".createdirectory",
                ".setattributes",
            ]),
            "powershell" | "pwsh" => {
                contains_any(&[
                    "remove-item",
                    "move-item",
                    "rename-item",
                    "set-content",
                    "clear-content",
                    "out-file",
                    "start-process",
                ]) || contains_command_alias(
                    outside,
                    &[
                        "rm", "del", "erase", "rd", "rmdir", "ri", "mv", "move", "mi", "ren", "rni",
                    ],
                ) || outside.contains("new-item") && outside.contains("hardlink")
            }
            "cmd" => {
                contains_any(&[
                    "del ",
                    "erase ",
                    "move ",
                    "rename ",
                    "copy ",
                    "xcopy ",
                    "robocopy ",
                ]) || outside.contains("mklink") && outside.contains("/h")
            }
            _ => false,
        }
    };
    let destructive_open = if is_python_interpreter(program) {
        contains_calls(&[".open"]) && write_mode(strings)
    } else {
        match program {
            "perl" => {
                (contains_bare_calls(&["open"]) || contains_word(outside, "open"))
                    && write_mode(strings)
            }
            "ruby" => {
                (contains_bare_calls(&["open"]) || contains_calls(&["file.open", "io.open"]))
                    && write_mode(strings)
            }
            "php" => contains_bare_calls(&["fopen"]) && write_mode(strings),
            _ => false,
        }
    };
    language_action
        || destructive_open
        || backtick_exec
            && strings.iter().any(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("rm ") || value.contains("unlink ") || value.contains("nah hook ")
            })
}

fn python_mutates_protected_ancestor(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let protected_argument = |argument: &StaticCallArgument| {
        protected_namespace_ancestor_target(
            &argument.outside,
            &argument.strings,
            home,
            critical_paths,
            platform,
        )
    };
    let calls = [
        ("os.remove", false, 1),
        ("os.unlink", false, 1),
        ("os.rename", false, 2),
        ("os.replace", false, 2),
        ("os.rmdir", false, 1),
        ("os.removedirs", false, 1),
        ("os.chmod", false, 1),
        ("os.chown", false, 1),
        ("os.lchown", false, 1),
        ("shutil.rmtree", false, 1),
        ("shutil.move", false, 2),
        ("remove", true, 1),
        ("unlink", true, 1),
        ("rename", true, 2),
        ("replace", true, 2),
        ("rmtree", true, 1),
        ("move", true, 2),
    ];
    if calls.iter().any(|(name, bare, targets)| {
        static_call_arguments(outside, strings, string_offsets, name, *bare)
            .iter()
            .any(|arguments| arguments.iter().take(*targets).any(&protected_argument))
    }) {
        return true;
    }

    [".unlink", ".rename", ".replace", ".rmdir", ".chmod"]
        .iter()
        .any(|method| {
            outside.match_indices(method).any(|(method_offset, _)| {
                let Some((path, path_offset)) = strings
                    .iter()
                    .zip(string_offsets)
                    .filter(|(_, offset)| **offset < method_offset)
                    .max_by_key(|(_, offset)| **offset)
                else {
                    return false;
                };
                let before = outside[..*path_offset].trim_end().to_ascii_lowercase();
                let between = &outside[*path_offset..method_offset];
                before.ends_with("path(")
                    && between
                        .chars()
                        .all(|character| character.is_ascii_whitespace() || character == ')')
                    && protected_path_ancestor(path, home, critical_paths, platform)
            })
        })
}

fn protected_namespace_ancestor_target(
    outside: &str,
    strings: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let joined = strings.join(" ");
    let concatenated = strings.concat();
    let candidates = strings
        .iter()
        .map(String::as_str)
        .chain([joined.as_str(), concatenated.as_str()])
        .chain(outside.split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(
                    character,
                    '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '=' | '"' | '\''
                )
        }))
        .collect::<Vec<_>>();
    if candidates
        .iter()
        .any(|path| protected_path_ancestor(path, home, critical_paths, platform))
    {
        return true;
    }

    let visible = format!("{outside} {joined} {concatenated}").to_ascii_lowercase();
    let home_reference = [
        "path.home",
        "expanduser",
        "process.env.home",
        "env[",
        "$env{home}",
        "$env:home",
        "$home",
        "${home}",
    ]
    .iter()
    .any(|marker| visible.contains(marker));
    home_reference
        && candidates.iter().any(|path| {
            let lowercase = path.to_ascii_lowercase();
            let relative = [
                "~",
                "$home",
                "$env:home",
                "$env{home}",
                "process.env.home",
                "path.home()",
                "${home}",
            ]
            .iter()
            .find_map(|prefix| lowercase.starts_with(prefix).then(|| &path[prefix.len()..]))
            .unwrap_or(path)
            .trim_start_matches(['/', '\\']);
            protected_path_ancestor(
                &format!("{home}/{relative}"),
                home,
                critical_paths,
                platform,
            )
        })
}

fn protected_target(
    outside: &str,
    strings: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    inline_runtime: bool,
    baseline_variables: &[(String, VariableValue)],
) -> bool {
    let joined = strings.join(" ");
    let concatenated = strings.concat();
    let mut path_candidates = strings
        .iter()
        .map(String::as_str)
        .chain([joined.as_str(), concatenated.as_str()])
        .collect::<Vec<_>>();
    path_candidates.extend(outside.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(
                character,
                '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '=' | '"' | '\''
            )
    }));
    if path_candidates
        .iter()
        .any(|path| protected_path(path, home, critical_paths, platform))
    {
        return true;
    }
    let mut visible = format!("{outside} {joined} {concatenated}").replace('\\', "/");
    if platform == Platform::Windows {
        visible.make_ascii_lowercase();
    }
    let mut targets = critical_paths
        .iter()
        .map(|path| path.as_str().replace('\\', "/"))
        .collect::<Vec<_>>();
    targets.extend([
        format!("{home}/.nah"),
        format!("{home}/.local/bin/nah"),
        format!("{home}/.cargo/bin/nah"),
        "/usr/local/bin/nah".into(),
        "/usr/bin/nah".into(),
    ]);
    for target in &mut targets {
        *target = target.replace('\\', "/");
    }
    if platform == Platform::Windows {
        for target in &mut targets {
            target.make_ascii_lowercase();
        }
    }
    if targets.iter().any(|target| visible.contains(target)) {
        return true;
    }

    let normalized_home = home.replace('\\', "/");
    let home_reference = [
        "path.home",
        "expanduser",
        "homedir",
        "process.env.home",
        "env[",
        "$env{home}",
        "$env:home",
        "$home",
        "${home}",
    ]
    .iter()
    .any(|marker| visible.to_ascii_lowercase().contains(marker))
        || strings
            .iter()
            .any(|value| value.eq_ignore_ascii_case("home"))
            && ["getenv", "environ.get", "env.fetch", "sys.getenv", "$env{"]
                .iter()
                .any(|marker| outside.contains(marker));
    if home_reference
        && path_candidates.iter().any(|path| {
            let lowercase = path.to_ascii_lowercase();
            let relative = [
                "~",
                "$home",
                "$env:home",
                "$env{home}",
                "process.env.home",
                "path.home()",
                "${home}",
            ]
            .iter()
            .find_map(|prefix| lowercase.starts_with(prefix).then(|| &path[prefix.len()..]))
            .unwrap_or(path)
            .trim_start_matches(['/', '\\']);
            protected_path(
                &format!("{home}/{relative}"),
                home,
                critical_paths,
                platform,
            )
        })
    {
        return true;
    }
    if home_reference
        && targets.iter().any(|target| {
            target
                .strip_prefix(&normalized_home)
                .map(|relative| relative.trim_start_matches('/'))
                .is_some_and(|relative| !relative.is_empty() && visible.contains(relative))
        })
    {
        return true;
    }

    let words = visible
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let lifecycle = words.windows(4).any(|parts| {
        parts[0] == "nah"
            && parts[1] == "hook"
            && runtime_name(&parts[2])
            && matches!(parts[3].as_str(), "install" | "uninstall")
    });
    let which_nah = (outside.contains("which(")
        || outside.contains("shutil.which")
        || outside.contains("where("))
        && strings.iter().any(|value| value == "nah");
    lifecycle
        || which_nah
        || inline_runtime
            && inline_runtime_bypass(strings, home, critical_paths, platform, baseline_variables)
}

fn inline_runtime_bypass(
    strings: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
) -> bool {
    let ignored_prefix = |value: &str| {
        matches!(
            value,
            "fs" | "node:fs" | "child_process" | "node:child_process"
        )
    };
    let start = strings
        .iter()
        .position(|value| !ignored_prefix(value))
        .unwrap_or(strings.len());
    let words = strings[start..]
        .iter()
        .flat_map(|value| value.split_ascii_whitespace())
        .map(|value| {
            value.trim_matches(|character: char| {
                matches!(character, '[' | ']' | '(' | ')' | ',' | ';')
            })
        })
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    inline_runtime_words(&words, home, critical_paths, platform, baseline_variables)
}

fn inline_runtime_words(
    words: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, VariableValue)],
) -> bool {
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    let program = normalized_program(program);
    if matches!(program.as_str(), "bash" | "sh")
        && arguments.first().is_some_and(|word| word == "-c")
    {
        return inline_runtime_words(
            &arguments[1..],
            home,
            critical_paths,
            platform,
            baseline_variables,
        );
    }
    if runtime_launch_bypass(&program, arguments, Some(home), Some(platform)) {
        return true;
    }
    let mut assignments = Vec::new();
    let mut index = usize::from(program == "env");
    if program == "env" {
        while let Some(word) = words.get(index) {
            if matches!(word.as_str(), "-i" | "--ignore-environment" | "--") {
                index += 1;
            } else if matches!(word.as_str(), "-u" | "--unset") {
                index += 2;
            } else if word.starts_with("--unset=") {
                index += 1;
            } else {
                break;
            }
        }
    }
    while let Some(word) = words.get(index) {
        let Some((name, value)) = word.split_once('=') else {
            break;
        };
        assignments.push((name.to_owned(), Some(value.to_owned())));
        index += 1;
    }
    words.get(index).is_some_and(|program| {
        environment_operation(
            program,
            &words[index + 1..],
            &assignments,
            EnvironmentVariables {
                visible: &[],
                runtime: baseline_variables,
            },
            home,
            critical_paths,
            platform,
        )
        .is_some()
    })
}

fn inline_direct_runtime_bypass(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    program: &str,
    home: &str,
    platform: Platform,
) -> bool {
    if !matches!(program, "powershell" | "pwsh" | "cmd") {
        return false;
    }
    let words = outside
        .split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(character, '[' | ']' | '(' | ')' | ',' | ';')
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    if words.first().copied() == Some("start-process")
        && let Some(file_path) = words.iter().position(|word| *word == "-filepath")
    {
        let runtime = match words.get(file_path + 1).copied() {
            Some(runtime) if runtime_launch_program(runtime) => runtime,
            Some(option) if !option.starts_with('-') => return false,
            _ => {
                let offset = outside
                    .find("-filepath")
                    .expect("the exact word was found above");
                let Some(runtime) = strings
                    .iter()
                    .zip(string_offsets)
                    .find(|(_, string_offset)| **string_offset > offset)
                    .map(|(runtime, _)| runtime)
                else {
                    return false;
                };
                if !runtime_launch_program(runtime) {
                    return false;
                }
                runtime
            }
        };
        let arguments = words[1..]
            .iter()
            .map(|word| (*word).to_owned())
            .chain(strings.iter().cloned())
            .collect::<Vec<_>>();
        return runtime_launch_bypass(runtime, &arguments, Some(home), Some(platform));
    }
    let start = match words.first().copied() {
        Some("&" | "." | "start-process") => 1,
        Some(_) => 0,
        None => return false,
    };
    let (runtime, argument_start, first_string_argument) =
        if words.get(start).copied() == Some("-filepath") {
            match words.get(start + 1).copied() {
                Some(runtime) if runtime_launch_program(runtime) => (runtime, start + 2, 0),
                Some(option) if option.starts_with('-') => {
                    let Some(runtime) = strings.first() else {
                        return false;
                    };
                    (runtime.as_str(), start + 1, 1)
                }
                None => {
                    let Some(runtime) = strings.first() else {
                        return false;
                    };
                    (runtime.as_str(), start + 1, 1)
                }
                Some(_) => return false,
            }
        } else if let Some(runtime) = words
            .get(start)
            .filter(|runtime| runtime_launch_program(runtime))
        {
            (*runtime, start + 1, 0)
        } else if start > 0 && words.get(start).is_none_or(|word| word.starts_with('-')) {
            let Some(runtime) = strings.first() else {
                return false;
            };
            (runtime.as_str(), start, 1)
        } else {
            return false;
        };
    let arguments = words[argument_start..]
        .iter()
        .map(|word| (*word).to_owned())
        .chain(strings[first_string_argument..].iter().cloned())
        .collect::<Vec<_>>();
    runtime_launch_bypass(runtime, &arguments, Some(home), Some(platform))
}
