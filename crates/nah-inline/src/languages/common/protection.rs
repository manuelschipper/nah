//! Conservative inline interpreter findings for structural self-protection.

use nah_proto::ctx::{AbsolutePath, Platform};

use crate::syntax::{
    StaticCallArgument, code_segments, lexical_code, named_call_argument, static_call_arguments,
};
use crate::{EnvironmentValue, Finding, FindingKind, InlineReport, normalized_program};

mod catalog;
mod protected;
mod support;

pub(in crate::languages) use support::is_perl_interpreter;

use catalog::mutation_action;
use protected::{inline_direct_runtime_bypass, inline_runtime_bypass, protected_target};

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

pub(super) fn typed_target_protected(
    target: &str,
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> bool {
    protected_target(
        target,
        &[],
        home,
        critical_paths,
        platform,
        false,
        baseline_variables,
    )
}

pub(super) fn typed_argv_protected(
    argv: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> bool {
    protected::inline_runtime_bypass(argv, home, critical_paths, platform, baseline_variables)
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
        "perl"
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
    ) {
        return false;
    }

    let home = context.home;
    let critical_paths = context.critical_paths;
    let platform = context.platform;
    let baseline_variables = context.baseline_variables;

    for code in code_segments(code, &program) {
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
            || (mutation_action(&program, &outside, &strings, backtick_exec)
                && protected_target(
                    &outside,
                    &strings,
                    home,
                    critical_paths,
                    platform,
                    !matches!(program.as_str(), "powershell" | "pwsh" | "cmd"),
                    baseline_variables,
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
    let names: &[&str] = match program {
        "perl" | "ruby" | "php" => &["eval"],
        _ => &[],
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
    ) {
        return true;
    }
    let copy_calls: &[(&str, bool)] = match program {
        "perl" | "php" => &[("copy", true)],
        "julia" => &[("cp", true)],
        "ruby" => &[("fileutils.cp", false), ("fileutils.copy", false)],
        "r" | "rscript" => &[("file.copy", false)],
        "swift" => &[(".copyitem", false)],
        _ => &[],
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
            .any(|argument| direct_static_argument(argument) && protected(argument))
    };
    let runtime_arguments = |arguments: &[StaticCallArgument], skip: usize| {
        let values = arguments
            .iter()
            .skip(skip)
            .flat_map(|argument| argument.strings.iter().cloned())
            .collect::<Vec<_>>();
        inline_runtime_bypass(&values, home, critical_paths, platform, baseline_variables)
    };
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

fn direct_static_argument(argument: &StaticCallArgument) -> bool {
    argument.outside.bytes().all(|byte| {
        byte.is_ascii_whitespace()
            || matches!(byte, b'[' | b']' | b'{' | b'}' | b'(' | b')' | b',' | b'+')
    })
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
