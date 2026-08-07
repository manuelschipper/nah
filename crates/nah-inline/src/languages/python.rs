use crate::syntax::{
    code_segments, contains_call, lexical_code_cased, lexical_code_exact,
    static_call_arguments_cased,
};
use crate::{Finding, FindingKind, InlineInput, InlineReport, ProtectionInput};

use super::common::{
    add_exact_shell_with_stdout, add_named_destructive_target_with_bindings,
    add_static_bound_shell_call, add_static_exec_argv_call, assigned_identifier,
    contains_zero_argument_call, exact_argv_argument, exact_code, exact_named_string,
    exact_named_string_array, exact_string, member_assigned, named_boolean,
    state_mutation_candidate, unmodeled_control_flow, update_static_binding,
};

mod parser;

pub(super) fn source_status(code: &str, program: &str) -> Result<bool, crate::InlineRefusal> {
    parser::source_status(code, program)
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut state = PythonState::default();
    let mut budget = WorkBudget::default();
    let code = super::deferred::mask(input.code, program);
    if let Some(items) = active_items(&code, program, depth, &mut Vec::new(), &mut budget) {
        scan_items(&items, program, input, depth, &mut state, &mut report);
    } else {
        report.refuse(budget.refusal.unwrap_or(crate::InlineRefusal::WorkLimit));
    }
    super::common::with_protection(report, program, input, protection)
}

const MAX_ACTIVE_ITEMS: usize = 4_096;
const MAX_DEFINITIONS: usize = 128;
const MAX_EXPANDED_BYTES: usize = 4 * 1024 * 1024;

struct WorkBudget {
    remaining_bytes: usize,
    items: usize,
    refusal: Option<crate::InlineRefusal>,
}

impl Default for WorkBudget {
    fn default() -> Self {
        Self {
            remaining_bytes: MAX_EXPANDED_BYTES,
            items: 0,
            refusal: None,
        }
    }
}

impl WorkBudget {
    fn enter_source(&mut self, source: &str) -> bool {
        let Some(remaining) = self
            .remaining_bytes
            .checked_sub(source.len().saturating_add(1))
        else {
            self.remaining_bytes = 0;
            self.refusal = Some(crate::InlineRefusal::WorkLimit);
            return false;
        };
        self.remaining_bytes = remaining;
        true
    }

    fn add_item(&mut self) -> bool {
        self.items += 1;
        let allowed = self.items <= MAX_ACTIVE_ITEMS;
        if !allowed {
            self.refusal = Some(crate::InlineRefusal::WorkLimit);
        }
        allowed
    }
}

#[derive(Clone)]
struct PythonState {
    bindings: Vec<(String, String)>,
    shutil_receivers: Vec<String>,
    rmtree_names: Vec<String>,
    os_receivers: Vec<String>,
    os_shell_names: Vec<(String, String)>,
    os_exec_names: Vec<(String, String)>,
    subprocess_receivers: Vec<String>,
    subprocess_names: Vec<(String, String)>,
    base64_receivers: Vec<String>,
    eval_owned: bool,
    exec_owned: bool,
}

impl Default for PythonState {
    fn default() -> Self {
        Self {
            bindings: Vec::new(),
            shutil_receivers: Vec::new(),
            rmtree_names: Vec::new(),
            os_receivers: Vec::new(),
            os_shell_names: Vec::new(),
            os_exec_names: Vec::new(),
            subprocess_receivers: Vec::new(),
            subprocess_names: Vec::new(),
            base64_receivers: Vec::new(),
            eval_owned: true,
            exec_owned: true,
        }
    }
}

enum ActiveItem {
    Segment(String),
    Scope(Vec<ActiveItem>),
    Binding(String),
    StateBarrier,
}

fn scan_items(
    items: &[ActiveItem],
    program: &str,
    input: &InlineInput<'_>,
    depth: usize,
    state: &mut PythonState,
    report: &mut InlineReport,
) {
    let mut state_exact = true;
    for item in items {
        let segment = match item {
            ActiveItem::Segment(segment) => segment,
            ActiveItem::Scope(items) => {
                let mut local_state = state.clone();
                scan_items(items, program, input, depth + 1, &mut local_state, report);
                continue;
            }
            ActiveItem::Binding(name) => {
                invalidate_python_binding(state, name);
                continue;
            }
            ActiveItem::StateBarrier => {
                clear_python_aliases(state);
                state_exact = false;
                continue;
            }
        };
        for name in imported_python_names(segment) {
            invalidate_python_binding(state, &name);
        }
        if state_exact {
            update_module_receivers(segment, "shutil", &mut state.shutil_receivers);
            update_imported_names(segment, "shutil", "rmtree", &mut state.rmtree_names);
            update_module_receivers(segment, "os", &mut state.os_receivers);
            for name in ["system", "popen"] {
                update_imported_selectors(segment, "os", name, &mut state.os_shell_names);
            }
            for name in ["execl", "execlp", "execle", "execv", "execvp", "execvpe"] {
                update_imported_selectors(segment, "os", name, &mut state.os_exec_names);
            }
            update_module_receivers(segment, "subprocess", &mut state.subprocess_receivers);
            for name in ["run", "call", "Popen", "check_call", "check_output"] {
                update_imported_selectors(segment, "subprocess", name, &mut state.subprocess_names);
            }
            update_module_receivers(segment, "base64", &mut state.base64_receivers);
        }
        let (outside, strings, offsets, static_strings, _) = lexical_code_cased(segment, program);
        if let Some(name) = assigned_identifier(&outside) {
            invalidate_python_binding(state, name);
        } else if state_mutation_candidate(segment, program) {
            clear_python_aliases(state);
        }
        update_static_binding(&mut state.bindings, segment, program, state_exact);
        state
            .shutil_receivers
            .retain(|receiver| !member_assigned(&outside, receiver, "rmtree"));
        state.os_receivers.retain(|receiver| {
            ![
                "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execvpe",
            ]
            .iter()
            .any(|member| member_assigned(&outside, receiver, member))
        });
        state.subprocess_receivers.retain(|receiver| {
            !["run", "call", "Popen", "check_call", "check_output"]
                .iter()
                .any(|member| member_assigned(&outside, receiver, member))
        });
        state.base64_receivers.retain(|receiver| {
            !["b64decode", "urlsafe_b64decode"]
                .iter()
                .any(|member| member_assigned(&outside, receiver, member))
        });
        for receiver in &state.shutil_receivers {
            for arguments in static_call_arguments_cased(
                &outside,
                &outside,
                &strings,
                &offsets,
                &static_strings,
                &format!("{receiver}.rmtree"),
                false,
            ) {
                if !one_python_argument(&arguments) {
                    continue;
                }
                if !python_argument_slot(&arguments[0], &["path"]) {
                    continue;
                }
                add_named_destructive_target_with_bindings(
                    report,
                    arguments.first(),
                    input.home,
                    input.platform,
                    &state.bindings,
                    &["path"],
                );
            }
        }
        for name in &state.rmtree_names {
            for arguments in static_call_arguments_cased(
                &outside,
                &outside,
                &strings,
                &offsets,
                &static_strings,
                name,
                true,
            ) {
                if !one_python_argument(&arguments) {
                    continue;
                }
                if !python_argument_slot(&arguments[0], &["path"]) {
                    continue;
                }
                add_named_destructive_target_with_bindings(
                    report,
                    arguments.first(),
                    input.home,
                    input.platform,
                    &state.bindings,
                    &["path"],
                );
            }
        }
        for receiver in &state.os_receivers {
            for selector in ["system", "popen"] {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &format!("{receiver}.{selector}"),
                    false,
                ) {
                    if !one_python_argument(&arguments) {
                        continue;
                    }
                    let slot = if selector == "system" {
                        &["command"][..]
                    } else {
                        &["cmd"][..]
                    };
                    if !python_argument_slot(&arguments[0], slot) {
                        continue;
                    }
                    if arguments.first().is_some_and(|argument| {
                        decoded_expression(argument, &state.base64_receivers)
                    }) {
                        report.push(Finding::exact(FindingKind::DecodedExecution));
                    }
                    add_static_bound_shell_call(
                        report,
                        &arguments,
                        input.platform,
                        selector == "system",
                        &state.bindings,
                        if selector == "system" {
                            &["command"]
                        } else {
                            &["cmd"]
                        },
                    );
                }
            }
            for selector in ["execl", "execlp", "execle", "execv", "execvp", "execvpe"] {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &format!("{receiver}.{selector}"),
                    false,
                ) {
                    if supported_exec_arguments(selector, &arguments) {
                        add_static_exec_argv_call(report, &arguments);
                    }
                }
            }
        }
        for (name, selector) in &state.os_shell_names {
            for arguments in static_call_arguments_cased(
                &outside,
                &outside,
                &strings,
                &offsets,
                &static_strings,
                name,
                true,
            ) {
                if !one_python_argument(&arguments) {
                    continue;
                }
                let slot = if selector == "system" {
                    &["command"][..]
                } else {
                    &["cmd"][..]
                };
                if !python_argument_slot(&arguments[0], slot) {
                    continue;
                }
                add_static_bound_shell_call(
                    report,
                    &arguments,
                    input.platform,
                    selector == "system",
                    &state.bindings,
                    if selector == "system" {
                        &["command"]
                    } else {
                        &["cmd"]
                    },
                );
            }
        }
        for (name, selector) in &state.os_exec_names {
            for arguments in static_call_arguments_cased(
                &outside,
                &outside,
                &strings,
                &offsets,
                &static_strings,
                name,
                true,
            ) {
                if supported_exec_arguments(selector, &arguments) {
                    add_static_exec_argv_call(report, &arguments);
                }
            }
        }
        for receiver in &state.subprocess_receivers {
            for name in ["run", "call", "Popen", "check_call", "check_output"] {
                for arguments in static_call_arguments_cased(
                    &outside,
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &format!("{receiver}.{name}"),
                    false,
                ) {
                    add_subprocess_call(report, &arguments, input, &state.base64_receivers, name);
                }
            }
        }
        for (name, selector) in &state.subprocess_names {
            for arguments in static_call_arguments_cased(
                &outside,
                &outside,
                &strings,
                &offsets,
                &static_strings,
                name,
                true,
            ) {
                add_subprocess_call(report, &arguments, input, &state.base64_receivers, selector);
            }
        }
        for (name, owned) in [("eval", state.eval_owned), ("exec", state.exec_owned)] {
            if !owned {
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
                if supported_dynamic_execution(name, &arguments)
                    && let Some(nested) = arguments.first().and_then(exact_code)
                {
                    report.extend(crate::analyze_at(
                        InlineInput {
                            code: &nested,
                            ..*input
                        },
                        None,
                        depth + 1,
                    ));
                }
            }
        }
    }
}

fn one_python_argument(arguments: &[crate::syntax::StaticCallArgument]) -> bool {
    arguments.len() == 1
}

fn supported_exec_arguments(
    selector: &str,
    arguments: &[crate::syntax::StaticCallArgument],
) -> bool {
    match selector {
        "execl" | "execlp" => {
            arguments.len() >= 2
                && arguments
                    .iter()
                    .all(|argument| exact_string(argument).is_some())
        }
        "execv" | "execvp" => arguments.len() == 2 && exact_argv_argument(&arguments[1]).is_some(),
        _ => false,
    }
}

fn invalidate_python_binding(state: &mut PythonState, name: &str) {
    state.bindings.retain(|(bound, _)| bound != name);
    for receivers in [
        &mut state.shutil_receivers,
        &mut state.rmtree_names,
        &mut state.os_receivers,
        &mut state.subprocess_receivers,
        &mut state.base64_receivers,
    ] {
        receivers.retain(|receiver| receiver != name);
    }
    state.os_exec_names.retain(|(receiver, _)| receiver != name);
    state
        .os_shell_names
        .retain(|(receiver, _)| receiver != name);
    state
        .subprocess_names
        .retain(|(receiver, _)| receiver != name);
    if name == "eval" {
        state.eval_owned = false;
    } else if name == "exec" {
        state.exec_owned = false;
    }
}

fn clear_python_aliases(state: &mut PythonState) {
    state.bindings.clear();
    state.shutil_receivers.clear();
    state.rmtree_names.clear();
    state.os_receivers.clear();
    state.os_shell_names.clear();
    state.os_exec_names.clear();
    state.subprocess_receivers.clear();
    state.subprocess_names.clear();
    state.base64_receivers.clear();
    state.eval_owned = false;
    state.exec_owned = false;
}

fn add_subprocess_call(
    report: &mut InlineReport,
    arguments: &[crate::syntax::StaticCallArgument],
    input: &InlineInput<'_>,
    base64_receivers: &[String],
    selector: &str,
) {
    let Some(command) = arguments.first() else {
        return;
    };
    if !python_argument_slot(command, &["args"]) {
        return;
    }
    let Some((shell, stdout_inherited)) = subprocess_options(selector, arguments) else {
        return;
    };
    if shell && decoded_expression(command, base64_receivers) {
        report.push(Finding::exact(FindingKind::DecodedExecution));
    }
    if shell {
        let code = exact_named_string_array(command, &["args"])
            .and_then(|argv| argv.into_iter().next())
            .or_else(|| exact_named_string(command, &["args"]).map(str::to_owned));
        if let Some(code) = code {
            add_exact_shell_with_stdout(report, &code, input.platform, stdout_inherited);
        }
    } else if let Some(argv) = exact_argv_argument(command) {
        report.push_nested_execution(crate::NestedExecution::Command {
            argv,
            stdout_inherited,
        });
    }
}

fn supported_dynamic_execution(
    name: &str,
    arguments: &[crate::syntax::StaticCallArgument],
) -> bool {
    let Some(source) = arguments.first() else {
        return false;
    };
    if !python_positional_argument(source) {
        return false;
    }
    if (1..=3).contains(&arguments.len()) && arguments[1..].iter().all(python_positional_argument) {
        return true;
    }
    name == "exec"
        && arguments.len() == 4
        && arguments[1..3].iter().all(python_positional_argument)
        && arguments[3].strings.is_empty()
        && arguments[3].outside.trim() == "closure=None"
}

fn python_argument_slot(argument: &crate::syntax::StaticCallArgument, names: &[&str]) -> bool {
    match argument_label(argument) {
        None => true,
        Some((name, separator)) => separator == '=' && names.contains(&name),
    }
}

fn python_positional_argument(argument: &crate::syntax::StaticCallArgument) -> bool {
    argument_label(argument).is_none()
}

fn argument_label(argument: &crate::syntax::StaticCallArgument) -> Option<(&str, char)> {
    let outside = argument.outside.trim_start();
    let name_end = outside
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(outside.len());
    let name = &outside[..name_end];
    if name.is_empty() {
        return None;
    }
    let rest = outside[name_end..].trim_start();
    let separator = rest.chars().next()?;
    matches!(separator, '=' | ':').then_some((name, separator))
}

fn subprocess_options(
    selector: &str,
    arguments: &[crate::syntax::StaticCallArgument],
) -> Option<(bool, bool)> {
    let mut shell = false;
    let mut stdout_inherited = selector != "check_output";
    let mut seen = Vec::<&str>::new();
    for (index, argument) in arguments[1..].iter().enumerate() {
        if argument.outside.trim().is_empty() && argument.strings.is_empty() {
            if index + 2 == arguments.len() {
                continue;
            }
            return None;
        }
        let name = python_keyword(argument)?;
        if seen.contains(&name) {
            return None;
        }
        seen.push(name);
        match name {
            "shell" => {
                shell = named_boolean(argument, "shell", &["True", "1"], &["False", "0", "None"])?;
            }
            "capture_output" if selector == "run" => {
                if named_boolean(
                    argument,
                    "capture_output",
                    &["True", "1"],
                    &["False", "0", "None"],
                )? {
                    stdout_inherited = false;
                }
            }
            "check" if selector == "run" => {
                named_boolean(argument, "check", &["True", "1"], &["False", "0", "None"])?;
            }
            "cwd" if selector == "Popen" => {
                exact_named_string(argument, &["cwd"])?;
            }
            _ => return None,
        }
    }
    Some((shell, stdout_inherited))
}

fn python_keyword(argument: &crate::syntax::StaticCallArgument) -> Option<&str> {
    let (name, _) = argument.outside.trim().split_once('=')?;
    let name = name.trim();
    identifier(name).then_some(name)
}

fn decoded_expression(argument: &crate::syntax::StaticCallArgument, receivers: &[String]) -> bool {
    let compact = argument
        .outside
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>();
    let compact = ["args=", "command=", "cmd="]
        .iter()
        .find_map(|prefix| compact.strip_prefix(prefix))
        .unwrap_or(&compact);
    receivers.iter().any(|receiver| {
        ["b64decode(", "urlsafe_b64decode("].iter().any(|name| {
            let prefix = format!("{receiver}.{name}");
            compact.strip_prefix(&prefix).is_some_and(|rest| {
                rest.contains(')') && (rest.ends_with(')') || rest.ends_with(").decode()"))
            })
        })
    })
}

fn update_module_receivers(segment: &str, module: &str, receivers: &mut Vec<String>) {
    let source = lexical_code_exact(segment, "python").0;
    let source = source.trim();
    if let Some(imports) = source.strip_prefix("import ") {
        for import in imports.split([',', ';']) {
            let words = import.split_ascii_whitespace().collect::<Vec<_>>();
            let receiver = match words.as_slice() {
                [imported] if *imported == module => module,
                [imported, "as", alias] if *imported == module => alias,
                _ => continue,
            };
            if !receivers.iter().any(|existing| existing == receiver) {
                receivers.push(receiver.to_owned());
            }
        }
    }
    receivers.retain(|receiver| !assigned(source, receiver));
}

fn update_imported_names(segment: &str, module: &str, expected: &str, names: &mut Vec<String>) {
    let source = lexical_code_exact(segment, "python").0;
    let source = source.trim();
    let prefix = format!("from {module} import ");
    if let Some(imports) = source.strip_prefix(&prefix) {
        for import in imports.split([',', ';']) {
            let words = import.split_ascii_whitespace().collect::<Vec<_>>();
            let name = match words.as_slice() {
                [imported] if *imported == expected => expected,
                [imported, "as", alias] if *imported == expected => alias,
                _ => continue,
            };
            if !names.iter().any(|existing| existing == name) {
                names.push(name.to_owned());
            }
        }
    }
    names.retain(|name| !assigned(source, name));
}

fn update_imported_selectors(
    segment: &str,
    module: &str,
    expected: &str,
    names: &mut Vec<(String, String)>,
) {
    let source = lexical_code_exact(segment, "python").0;
    let source = source.trim();
    let prefix = format!("from {module} import ");
    if let Some(imports) = source.strip_prefix(&prefix) {
        for import in imports.split([',', ';']) {
            let words = import.split_ascii_whitespace().collect::<Vec<_>>();
            let name = match words.as_slice() {
                [imported] if *imported == expected => expected,
                [imported, "as", alias] if *imported == expected => alias,
                _ => continue,
            };
            names.retain(|(existing, _)| existing != name);
            names.push((name.to_owned(), expected.to_owned()));
        }
    }
    names.retain(|(name, _)| !assigned(source, name));
}

fn imported_python_names(segment: &str) -> Vec<String> {
    let (source, _, _, _) = lexical_code_exact(segment, "python");
    let source = source.trim();
    let (imports, from_import) = if let Some(imports) = source.strip_prefix("import ") {
        (imports, false)
    } else if let Some((_, imports)) = source
        .strip_prefix("from ")
        .and_then(|source| source.split_once(" import "))
    {
        (imports, true)
    } else {
        return Vec::new();
    };
    imports
        .split(',')
        .filter_map(|import| {
            let words = import
                .trim_matches(|character: char| {
                    character.is_ascii_whitespace() || matches!(character, '(' | ')')
                })
                .split_ascii_whitespace()
                .collect::<Vec<_>>();
            let name = match words.as_slice() {
                [imported] if from_import => *imported,
                [imported] => imported.split('.').next().unwrap_or(imported),
                [_, "as", alias] => *alias,
                _ => return None,
            };
            identifier(name).then(|| name.to_owned())
        })
        .collect()
}

fn assigned(source: &str, name: &str) -> bool {
    assigned_identifier(source) == Some(name)
}

fn lambda_member_assignment(source: &str) -> Option<&str> {
    let (before, _) = source.split_once("lambda")?;
    let target = before.trim_end().strip_suffix('=')?;
    let (receiver, member) = target.trim_end().rsplit_once('.')?;
    (identifier(receiver.trim()) && identifier(member.trim())).then_some(before)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Clone)]
struct Definition {
    name: String,
    body: Option<String>,
}

fn active_items(
    code: &str,
    program: &str,
    depth: usize,
    stack: &mut Vec<String>,
    budget: &mut WorkBudget,
) -> Option<Vec<ActiveItem>> {
    if depth >= 16 {
        budget.refusal = Some(crate::InlineRefusal::RecursionLimit);
        return None;
    }
    if !budget.enter_source(code) {
        return None;
    }
    let lines = code.lines().collect::<Vec<_>>();
    let mut items = Vec::new();
    let mut definitions = Vec::<Definition>::new();
    let mut pending = Vec::<&str>::new();
    let mut decorated = false;
    let mut uncertain_flow = false;
    let mut barrier_emitted = false;
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent == 0 && trimmed.starts_with('@') {
            append_python_chunk(
                &mut items,
                &mut definitions,
                &pending.join("\n"),
                program,
                depth,
                stack,
                budget,
            )?;
            pending.clear();
            decorated = true;
            index += 1;
            continue;
        }

        let (outside, _, _, _) = lexical_code_exact(trimmed, program);
        let source = outside.trim_start();
        let function = source
            .strip_prefix("def ")
            .map(|rest| (rest, false))
            .or_else(|| source.strip_prefix("async def ").map(|rest| (rest, true)));
        let skipped_block = function.is_some()
            || source.starts_with("class ")
            || source.starts_with("if False:")
            || source.starts_with("while False:")
            || source.starts_with("for ") && source.ends_with(" in []:");
        if skipped_block {
            append_python_chunk(
                &mut items,
                &mut definitions,
                &pending.join("\n"),
                program,
                depth,
                stack,
                budget,
            )?;
            pending.clear();
            let (end, body) = python_block(&lines, index, indent, trimmed, source);
            if let Some((header, asynchronous)) = function
                && indent == 0
                && let Some(name) = python_definition_name(header)
            {
                if !budget.add_item() {
                    return None;
                }
                items.push(ActiveItem::Binding(name.to_owned()));
                definitions.retain(|definition| definition.name != name);
                definitions.push(Definition {
                    name: name.to_owned(),
                    body: (!asynchronous
                        && !decorated
                        && parameterless_python_definition(header).is_some())
                    .then_some(body),
                });
                if definitions.len() > MAX_DEFINITIONS {
                    budget.refusal = Some(crate::InlineRefusal::WorkLimit);
                    return None;
                }
            }
            decorated = false;
            index = end;
            continue;
        }
        uncertain_flow |= unmodeled_control_flow(source, program);
        if uncertain_flow && state_mutation_candidate(source, program) && !barrier_emitted {
            append_python_chunk(
                &mut items,
                &mut definitions,
                &pending.join("\n"),
                program,
                depth,
                stack,
                budget,
            )?;
            pending.clear();
            items.push(ActiveItem::StateBarrier);
            barrier_emitted = true;
        }
        if !trimmed.is_empty() {
            decorated = false;
        }
        pending.push(line);
        index += 1;
    }
    append_python_chunk(
        &mut items,
        &mut definitions,
        &pending.join("\n"),
        program,
        depth,
        stack,
        budget,
    )?;
    Some(items)
}

fn python_block(
    lines: &[&str],
    start: usize,
    indent: usize,
    header: &str,
    outside: &str,
) -> (usize, String) {
    let inline = outside
        .rfind(':')
        .filter(|colon| !outside[colon + 1..].trim().is_empty())
        .and_then(|colon| header.get(colon + 1..))
        .map(str::trim)
        .unwrap_or_default();
    if !inline.is_empty() {
        return (start + 1, inline.to_owned());
    }
    let mut end = start + 1;
    while end < lines.len() {
        let trimmed = lines[end].trim_start();
        let current_indent = lines[end].len() - trimmed.len();
        if !trimmed.is_empty() && current_indent <= indent {
            break;
        }
        end += 1;
    }
    (end, dedent(&lines[start + 1..end]))
}

fn dedent(lines: &[&str]) -> String {
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|line| line.get(indent..).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

fn append_python_chunk(
    items: &mut Vec<ActiveItem>,
    definitions: &mut Vec<Definition>,
    chunk: &str,
    program: &str,
    depth: usize,
    stack: &mut Vec<String>,
    budget: &mut WorkBudget,
) -> Option<()> {
    for segment in code_segments(chunk, program) {
        let (outside, _, _, _) = lexical_code_exact(segment, program);
        if outside.trim_start().starts_with("False and ") {
            continue;
        }
        let source = outside.trim_start();
        if source == "return"
            || source.starts_with("return ")
            || source == "raise"
            || source.starts_with("raise ")
        {
            break;
        }
        if let Some(name) = outside
            .trim_start()
            .strip_prefix("def ")
            .and_then(|header| header.split('(').next())
            .filter(|name| identifier(name))
        {
            if !budget.add_item() {
                return None;
            }
            items.push(ActiveItem::Binding(name.to_owned()));
            definitions.retain(|definition| definition.name != name);
            continue;
        }
        definitions.retain(|definition| !assigned(outside.trim_start(), &definition.name));
        if outside.contains("lambda") {
            if let Some(name) = assigned_identifier(&outside) {
                if !budget.add_item() {
                    return None;
                }
                items.push(ActiveItem::Binding(name.to_owned()));
            } else if let Some(assignment) = lambda_member_assignment(&outside) {
                if !budget.add_item() {
                    return None;
                }
                // The lambda body is dormant, but the member assignment still
                // revokes ownership of the imported standard-library function.
                items.push(ActiveItem::Segment(assignment.to_owned()));
            }
            continue;
        }
        if !budget.add_item() {
            return None;
        }
        items.push(ActiveItem::Segment(segment.to_owned()));
        let visible = lexical_code_exact(segment, program).0;
        let called = definitions
            .iter()
            .filter(|definition| {
                !stack.contains(&definition.name)
                    && if definition.body.is_some() {
                        contains_zero_argument_call(segment, program, &definition.name)
                    } else {
                        contains_call(&visible, &definition.name, true)
                    }
            })
            .cloned()
            .collect::<Vec<_>>();
        for definition in called {
            let Some(body) = definition.body else {
                if !budget.add_item() {
                    return None;
                }
                items.push(ActiveItem::StateBarrier);
                continue;
            };
            stack.push(definition.name);
            let nested = active_items(&body, program, depth + 1, stack, budget)?;
            stack.pop();
            if !budget.add_item() {
                return None;
            }
            items.push(ActiveItem::Scope(nested));
        }
    }
    Some(())
}

fn parameterless_python_definition(header: &str) -> Option<&str> {
    let name = python_definition_name(header)?;
    let (_, parameters) = header.split_once('(')?;
    let parameters = parameters.split_once(')')?.0;
    parameters.trim().is_empty().then_some(name)
}

fn python_definition_name(header: &str) -> Option<&str> {
    let (name, parameters) = header.split_once('(')?;
    (identifier(name) && parameters.contains(')')).then_some(name)
}

#[cfg(test)]
mod tests {
    use nah_proto::ctx::Platform;

    use super::*;
    use crate::NestedExecution;

    fn report(code: &str) -> InlineReport {
        analyze(
            "python3",
            &InlineInput {
                program: "python3",
                code,
                home: "/home/dev",
                platform: Platform::Linux,
            },
            None,
            0,
        )
    }

    fn stdout_inherited(code: &str) -> Option<bool> {
        report(code)
            .nested_executions()
            .first()
            .map(|execution| match execution {
                NestedExecution::Shell {
                    stdout_inherited, ..
                }
                | NestedExecution::Command {
                    stdout_inherited, ..
                } => *stdout_inherited,
            })
    }

    #[test]
    fn later_imports_revoke_prior_owned_aliases() {
        for code in [
            "import os as api\nimport types as api\napi.system('rm -rf /')",
            "from os import system as launch\nfrom math import sqrt as launch\nlaunch('rm -rf /')",
            "from subprocess import run as launch\nfrom math import sqrt as launch\nlaunch(['rm', '-rf', '/'])",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }
    }

    #[test]
    fn rebound_eval_is_not_treated_as_the_builtin() {
        for code in [
            "eval = print\neval(\"import shutil; shutil.rmtree('/')\")",
            "from builtins import print as eval\neval(\"import shutil; shutil.rmtree('/')\")",
            "def eval(value):\n    pass\neval(\"import shutil; shutil.rmtree('/')\")",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }
    }

    #[test]
    fn imported_child_apis_preserve_their_stdout_contract() {
        for code in [
            "from os import system as launch\nlaunch('printf child')",
            "from subprocess import run as launch\nlaunch(['printf', 'child'])",
        ] {
            assert_eq!(stdout_inherited(code), Some(true), "{code}");
        }
        for code in [
            "from os import popen as launch\nlaunch('printf child')",
            "from subprocess import check_output as launch\nlaunch(['printf', 'child'])",
        ] {
            assert_eq!(stdout_inherited(code), Some(false), "{code}");
        }
    }

    #[test]
    fn capture_output_requires_an_exact_boolean() {
        assert_eq!(
            stdout_inherited(
                "import subprocess\nsubprocess.run(['printf', 'child'], capture_output=False)"
            ),
            Some(true)
        );
        assert_eq!(
            stdout_inherited(
                "import subprocess\nsubprocess.run(['printf', 'child'], capture_output=True)"
            ),
            Some(false)
        );
        assert_eq!(
            stdout_inherited(
                "import subprocess\nsubprocess.run(['printf', 'child'], capture_output=flag)"
            ),
            None
        );
    }

    #[test]
    fn first_argument_keywords_are_api_specific() {
        for code in [
            "import subprocess\nsubprocess.run(not_args=['rm', '-rf', '/'])",
            "import os\nos.system(not_command='rm -rf /')",
            "import os\nos.system('rm -rf /', 'extra')",
            "import shutil\nshutil.rmtree(not_path='/')",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }

        assert!(
            report("import subprocess\nsubprocess.run(args=['rm', '-rf', '/'])")
                .nested_executions()
                .len()
                == 1
        );
        assert_eq!(
            stdout_inherited("import os\nos.system(command='printf child')"),
            Some(true)
        );
        assert_eq!(
            stdout_inherited("import os\nos.popen(cmd='printf child')"),
            Some(false)
        );
        assert!(
            report("import shutil\nshutil.rmtree(path='/')")
                .contains_exact(FindingKind::RootDestruction)
        );
    }

    #[test]
    fn exec_accepts_only_its_exact_supported_arity() {
        let code = "exec(\"import shutil; shutil.rmtree('/')\", {}, {}, closure=None)";
        let (outside, strings, offsets, static_strings, _) = lexical_code_cased(code, "python3");
        let calls = static_call_arguments_cased(
            &outside,
            &outside,
            &strings,
            &offsets,
            &static_strings,
            "exec",
            true,
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0]
                .iter()
                .map(|argument| argument.outside.trim())
                .collect::<Vec<_>>(),
            vec!["", "{}", "{}", "closure=None"],
        );
        assert!(supported_dynamic_execution("exec", &calls[0]));
        assert_eq!(
            exact_code(&calls[0][0]).as_deref(),
            Some("import shutil; shutil.rmtree('/')"),
        );
        assert_ne!(report(code), InlineReport::default());
    }
}
