//! Conservative inline interpreter findings for structural self-protection.

use nah_proto::ctx::{AbsolutePath, Platform};

use crate::syntax::{
    StaticCallArgument, code_segments, lexical_code, named_call_argument, static_call_arguments,
    static_call_arguments_at,
};
use crate::{
    EnvironmentValue, Finding, FindingKind, InlineReport, is_python_interpreter, normalized_program,
};

use self::support::{protected_access_control_operation, protected_path, resolve_from_cwd};

mod catalog;
mod protected;
mod python;
mod support;

pub(in crate::languages) use support::is_perl_interpreter;
pub(in crate::languages) use support::runtime_name;

use catalog::{mutation_action, write_mode};
use protected::{
    inline_direct_runtime_bypass, inline_runtime_bypass, protected_target,
    python_mutates_protected_ancestor,
};
use python::python_variable_mutates_protected;

const WORK_LIMIT: usize = 4 * 1024 * 1024;

struct WorkBudget {
    remaining: usize,
    refusal: Option<crate::InlineRefusal>,
}

struct ProtectionContext<'a> {
    home: &'a str,
    critical_paths: &'a [AbsolutePath],
    platform: Platform,
    baseline_variables: &'a [(String, EnvironmentValue)],
}

impl WorkBudget {
    fn spend(&mut self, amount: usize) -> bool {
        let Some(remaining) = self.remaining.checked_sub(amount) else {
            self.remaining = 0;
            self.refusal = Some(crate::InlineRefusal::WorkLimit);
            return false;
        };
        self.remaining = remaining;
        true
    }
}

pub(in crate::languages) fn analyze(
    program: &str,
    code: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> InlineReport {
    let (mutates, refusal) = inline_critical_mutation(
        program,
        code,
        home,
        critical_paths,
        platform,
        baseline_variables,
    );
    let mut report = InlineReport::default();
    if mutates {
        report.push(Finding::conservative(FindingKind::NahTampering));
    }
    if let Some(refusal) = refusal {
        report.refuse(refusal);
    }
    report
}

fn inline_critical_mutation(
    program: &str,
    code: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> (bool, Option<crate::InlineRefusal>) {
    let mut budget = WorkBudget {
        remaining: WORK_LIMIT,
        refusal: None,
    };
    let context = ProtectionContext {
        home,
        critical_paths,
        platform,
        baseline_variables,
    };
    let mutates = inline_critical_mutation_inner(program, code, &context, 0, &mut budget);
    (mutates, budget.refusal)
}

fn inline_critical_mutation_inner(
    program: &str,
    code: &str,
    context: &ProtectionContext<'_>,
    depth: usize,
    budget: &mut WorkBudget,
) -> bool {
    if !budget.spend(code.len().saturating_add(1)) {
        return false;
    }
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

    let home = context.home;
    let critical_paths = context.critical_paths;
    let platform = context.platform;
    let baseline_variables = context.baseline_variables;

    let segments = code_segments(code, &program);
    if is_python_interpreter(&program) {
        match python_variable_mutates_protected(
            &segments,
            home,
            critical_paths,
            platform,
            baseline_variables,
        ) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(()) => budget.refusal = Some(crate::InlineRefusal::WorkLimit),
        }
    }
    let python = is_python_interpreter(&program);
    let mut python_os_shadowed = false;
    let mut python_subprocess_shadowed = false;
    for code in segments {
        let (outside, strings, string_offsets, backtick_exec) = lexical_code(code, &program);
        let mut nested_mutates = false;
        for (nested, _) in strings
            .iter()
            .zip(&string_offsets)
            .filter(|(_, offset)| direct_code_string(&program, &outside, **offset))
        {
            if depth >= 16 {
                budget.refusal = Some(crate::InlineRefusal::RecursionLimit);
                break;
            }
            if inline_critical_mutation_inner(&program, nested, context, depth + 1, budget) {
                nested_mutates = true;
                break;
            }
        }
        let mutates = nested_mutates
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
    baseline_variables: &[(String, EnvironmentValue)],
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
    baseline_variables: &[(String, EnvironmentValue)],
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
    let argument_words = arguments.to_vec();
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
