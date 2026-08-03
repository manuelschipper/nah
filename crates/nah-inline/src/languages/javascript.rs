use crate::syntax::{
    StaticCallArgument, code_segments, lexical_code_cased, lexical_code_exact,
    static_call_arguments_at_cased, static_call_arguments_cased,
};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_destructive_target_with_bindings, add_exact_argv,
    add_static_bound_shell_call, assigned_identifier, exact_code, exact_string, exact_string_array,
    member_assigned, observe_shadow, ordered_active_segments, state_mutation_candidate,
    update_static_binding,
};

#[derive(Clone)]
struct JavaScriptState {
    require_owned: bool,
    eval_shadowed: bool,
    fs_receivers: Vec<String>,
    child_receivers: Vec<String>,
    child_functions: Vec<(String, String)>,
    bindings: Vec<(String, String)>,
}

impl Default for JavaScriptState {
    fn default() -> Self {
        Self {
            require_owned: true,
            eval_shadowed: false,
            fs_receivers: Vec::new(),
            child_receivers: Vec::new(),
            child_functions: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut states = vec![(0usize, JavaScriptState::default())];
    let code = super::deferred::mask(input.code, program);
    for segment in ordered_active_segments(&code, program, DefinitionStyle::Braces, &mut report) {
        let scope = segment.scope;
        let segment_state_exact = segment.state_exact;
        if !states.iter().any(|(scope, _)| *scope == segment.scope) {
            states.push((segment.scope, states[0].1.clone()));
        }
        let state_index = states
            .iter()
            .position(|(scope, _)| *scope == segment.scope)
            .expect("scope was inserted");
        let state = &mut states[state_index].1;
        if !segment_state_exact {
            state.bindings.clear();
            state.fs_receivers.clear();
            state.child_receivers.clear();
            state.child_functions.clear();
            state.require_owned = false;
            state.eval_shadowed = true;
        }
        if !segment.executable {
            state.require_owned &= !declares_javascript_name(segment.source, program, "require");
            observe_shadow(&mut state.eval_shadowed, segment.source, program, "eval");
            continue;
        }
        let segment = segment.source;
        let (outside, strings, offsets, static_strings, _) = lexical_code_cased(segment, program);
        if state_mutation_candidate(segment, program)
            && assigned_identifier(&outside).is_none()
            && !destructured_require_declaration(&outside, &strings, &offsets)
        {
            state.bindings.clear();
            state.fs_receivers.clear();
            state.child_receivers.clear();
            state.child_functions.clear();
            if outside
                .split(|character: char| {
                    !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$')
                })
                .any(|identifier| identifier == "require")
            {
                state.require_owned = false;
            }
            if outside
                .split(|character: char| {
                    !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$')
                })
                .any(|identifier| identifier == "eval")
            {
                state.eval_shadowed = true;
            }
        }
        state.require_owned &= !require_is_shadowed(segment, program);
        update_static_binding(&mut state.bindings, segment, program, segment_state_exact);
        if state.require_owned && segment_state_exact {
            update_require_bindings(
                &outside,
                &strings,
                &offsets,
                &["fs", "node:fs"],
                &mut state.fs_receivers,
            );
            update_require_bindings(
                &outside,
                &strings,
                &offsets,
                &["child_process", "node:child_process"],
                &mut state.child_receivers,
            );
            update_destructured_require_bindings(
                &outside,
                &strings,
                &offsets,
                &["child_process", "node:child_process"],
                &mut state.child_functions,
            );
        }
        let member_shadow = direct_require_member_assigned(
            &outside,
            &strings,
            &offsets,
            &static_strings,
            &[
                "rm",
                "rmSync",
                "exec",
                "execSync",
                "spawn",
                "spawnSync",
                "execFile",
                "execFileSync",
            ],
        );
        state.require_owned &= !member_shadow;
        state.fs_receivers.retain(|receiver| {
            !["rm", "rmSync"]
                .iter()
                .any(|member| member_assigned(&outside, receiver, member))
        });
        state.child_receivers.retain(|receiver| {
            ![
                "exec",
                "execSync",
                "spawn",
                "spawnSync",
                "execFile",
                "execFileSync",
            ]
            .iter()
            .any(|member| member_assigned(&outside, receiver, member))
        });
        for selector in ["rmSync", "rm"] {
            let module_calls = if state.require_owned {
                module_calls(
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &["fs", "node:fs"],
                    selector,
                )
            } else {
                Vec::new()
            };
            let calls = module_calls
                .into_iter()
                .chain(state.fs_receivers.iter().flat_map(|receiver| {
                    static_call_arguments_cased(
                        &outside,
                        &outside,
                        &strings,
                        &offsets,
                        &static_strings,
                        &format!("{receiver}.{selector}"),
                        false,
                    )
                }));
            for arguments in calls {
                let supported = match (selector, arguments.as_slice()) {
                    ("rmSync", [_, options]) => javascript_recursive(options) == Some(true),
                    ("rm", [_, options, callback]) => {
                        javascript_recursive(options) == Some(true)
                            && static_javascript_callback(callback)
                    }
                    _ => false,
                };
                if supported {
                    add_destructive_target_with_bindings(
                        &mut report,
                        arguments.first(),
                        input.home,
                        input.platform,
                        &state.bindings,
                    );
                }
            }
        }
        for selector in ["exec", "execSync"] {
            let module_calls = if state.require_owned {
                module_calls(
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &["child_process", "node:child_process"],
                    selector,
                )
            } else {
                Vec::new()
            };
            let calls = module_calls
                .into_iter()
                .chain(state.child_receivers.iter().flat_map(|receiver| {
                    static_call_arguments_cased(
                        &outside,
                        &outside,
                        &strings,
                        &offsets,
                        &static_strings,
                        &format!("{receiver}.{selector}"),
                        false,
                    )
                }));
            for arguments in calls {
                add_node_shell_call(&mut report, &arguments, input.platform, &state.bindings);
            }
            for (name, bound_selector) in &state.child_functions {
                if bound_selector == selector {
                    for arguments in static_call_arguments_cased(
                        &outside,
                        &outside,
                        &strings,
                        &offsets,
                        &static_strings,
                        name,
                        true,
                    ) {
                        add_node_shell_call(
                            &mut report,
                            &arguments,
                            input.platform,
                            &state.bindings,
                        );
                    }
                }
            }
        }
        for selector in ["spawn", "spawnSync", "execFile", "execFileSync"] {
            let module_calls = if state.require_owned {
                module_calls(
                    &outside,
                    &strings,
                    &offsets,
                    &static_strings,
                    &["child_process", "node:child_process"],
                    selector,
                )
            } else {
                Vec::new()
            };
            let calls = module_calls
                .into_iter()
                .chain(state.child_receivers.iter().flat_map(|receiver| {
                    static_call_arguments_cased(
                        &outside,
                        &outside,
                        &strings,
                        &offsets,
                        &static_strings,
                        &format!("{receiver}.{selector}"),
                        false,
                    )
                }));
            for arguments in calls {
                add_node_argv_call(&mut report, &arguments);
            }
            for (name, bound_selector) in &state.child_functions {
                if bound_selector == selector {
                    for arguments in static_call_arguments_cased(
                        &outside,
                        &outside,
                        &strings,
                        &offsets,
                        &static_strings,
                        name,
                        true,
                    ) {
                        add_node_argv_call(&mut report, &arguments);
                    }
                }
            }
        }
        if !state.eval_shadowed {
            for arguments in static_call_arguments_cased(
                &outside,
                &outside,
                &strings,
                &offsets,
                &static_strings,
                "eval",
                true,
            ) {
                if let Some(nested) = arguments.first().and_then(exact_code) {
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
        observe_shadow(&mut state.eval_shadowed, segment, program, "eval");
        if scope != 0 {
            let root = &mut states[0].1;
            let source = outside.trim_start();
            let local_declaration = ["const ", "let ", "var "]
                .iter()
                .any(|prefix| source.starts_with(prefix));
            if !local_declaration && let Some(name) = assigned_identifier(&outside) {
                invalidate_name(root, name);
            }
            if member_shadow {
                root.require_owned = false;
            }
            root.fs_receivers.retain(|receiver| {
                !["rm", "rmSync"]
                    .iter()
                    .any(|member| member_assigned(&outside, receiver, member))
            });
            root.child_receivers.retain(|receiver| {
                ![
                    "exec",
                    "execSync",
                    "spawn",
                    "spawnSync",
                    "execFile",
                    "execFileSync",
                ]
                .iter()
                .any(|member| member_assigned(&outside, receiver, member))
            });
        }
    }
    super::common::with_protection(report, program, input, protection)
}

fn declares_javascript_name(source: &str, program: &str, expected: &str) -> bool {
    let source = lexical_code_exact(source, program).0;
    let source = source.trim_start();
    ["function ", "class "]
        .iter()
        .find_map(|prefix| source.strip_prefix(prefix))
        .and_then(|source| source.split(['(', '{', ' ']).next())
        == Some(expected)
}

fn destructured_require_declaration(outside: &str, strings: &[String], offsets: &[usize]) -> bool {
    strings.iter().zip(offsets).any(|(module, offset)| {
        matches!(
            module.as_str(),
            "fs" | "node:fs" | "child_process" | "node:child_process"
        ) && outside.get(..*offset).is_some_and(|prefix| {
            let statement = prefix.rsplit([';', '\n']).next().unwrap_or_default().trim();
            ["const ", "let ", "var "]
                .iter()
                .find_map(|declaration| statement.strip_prefix(declaration))
                .and_then(|statement| statement.split_once('='))
                .is_some_and(|(receiver, value)| {
                    receiver.trim().starts_with('{') && value.trim() == "require("
                })
        })
    })
}

fn invalidate_name(state: &mut JavaScriptState, name: &str) {
    state.bindings.retain(|(bound, _)| bound != name);
    state.fs_receivers.retain(|receiver| receiver != name);
    state.child_receivers.retain(|receiver| receiver != name);
    state
        .child_functions
        .retain(|(function, _)| function != name);
    if name == "require" {
        state.require_owned = false;
    } else if name == "eval" {
        state.eval_shadowed = true;
    }
}

fn add_node_shell_call(
    report: &mut InlineReport,
    arguments: &[StaticCallArgument],
    platform: nah_proto::ctx::Platform,
    bindings: &[(String, String)],
) {
    let [_command] = arguments else {
        return;
    };
    add_static_bound_shell_call(report, arguments, platform, false, bindings, &[]);
}

fn add_node_argv_call(report: &mut InlineReport, arguments: &[StaticCallArgument]) {
    let Some(program) = arguments.first().and_then(exact_string) else {
        return;
    };
    let mut argv = vec![program.to_owned()];
    match arguments {
        [_] => {}
        [_, values] => {
            let Some(values) = exact_string_array(values) else {
                return;
            };
            argv.extend(values);
        }
        _ => return,
    }
    add_exact_argv(report, argv);
}

fn require_is_shadowed(code: &str, program: &str) -> bool {
    code_segments(code, program).into_iter().any(|segment| {
        let (source, _, _, _) = lexical_code_exact(segment, program);
        source.contains("function require")
            || declares_binding(&source, "require")
            || catch_binding(&source, "require")
            || assigned_identifier(&source) == Some("require")
            || source
                .split_once("=>")
                .is_some_and(|(parameters, _)| parameter_list_contains(parameters, "require"))
            || source.find("function").is_some_and(|start| {
                source[start..]
                    .split_once('(')
                    .and_then(|(_, rest)| rest.split_once(')'))
                    .is_some_and(|(parameters, _)| parameter_list_contains(parameters, "require"))
            })
    })
}

fn declares_binding(source: &str, expected: &str) -> bool {
    ["const", "let", "var"].iter().any(|declaration| {
        source.match_indices(declaration).any(|(index, _)| {
            let before = source[..index].chars().next_back();
            let rest = &source[index + declaration.len()..];
            let boundary = before.is_none_or(|character| {
                !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$')
            });
            boundary && binding_pattern_contains(rest.trim_start(), expected)
        })
    })
}

fn catch_binding(source: &str, expected: &str) -> bool {
    source.match_indices("catch").any(|(index, _)| {
        let before = source[..index].chars().next_back();
        let rest = source[index + "catch".len()..].trim_start();
        before.is_none_or(|character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$')
        }) && rest
            .strip_prefix('(')
            .and_then(|rest| rest.split_once(')'))
            .is_some_and(|(binding, _)| binding_pattern_contains(binding.trim(), expected))
    })
}

fn binding_pattern_contains(pattern: &str, expected: &str) -> bool {
    if pattern.strip_prefix(expected).is_some_and(|rest| {
        rest.chars().next().is_none_or(|character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$')
        })
    }) {
        return true;
    }
    let pattern = pattern
        .split_once('=')
        .map_or(pattern, |(pattern, _)| pattern)
        .trim();
    let Some(pattern) = pattern
        .strip_prefix('{')
        .and_then(|pattern| pattern.strip_suffix('}'))
        .or_else(|| {
            pattern
                .strip_prefix('[')
                .and_then(|pattern| pattern.strip_suffix(']'))
        })
    else {
        return false;
    };
    pattern.split(',').any(|binding| {
        binding
            .rsplit_once(':')
            .map_or(binding, |(_, binding)| binding)
            .trim()
            .trim_start_matches("...")
            == expected
    })
}

fn javascript_recursive(argument: &StaticCallArgument) -> Option<bool> {
    let outside = argument.outside.trim();
    let body = outside.strip_prefix('{')?.strip_suffix('}')?;
    let mut properties = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (index, byte) in body.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                properties.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    properties.push(&body[start..]);

    let mut recursive = None;
    let mut force = None;
    let property_count = properties.len();
    for (index, property) in properties.into_iter().enumerate() {
        let property = property.trim();
        if property.is_empty() {
            if index + 1 == property_count && body.trim_end().ends_with(',') {
                continue;
            }
            return None;
        }
        if property.starts_with("...") || property.starts_with('[') {
            return None;
        }
        let (name, value) = property.split_once(':')?;
        let value = match value.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => return None,
        };
        match name.trim() {
            "recursive" if recursive.is_none() => recursive = value,
            "force" if force.is_none() => force = value,
            _ => return None,
        }
    }
    recursive
}

fn static_javascript_callback(argument: &StaticCallArgument) -> bool {
    let compact = argument
        .outside
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    matches!(compact.as_str(), "()=>{}" | "function(){}")
}

fn parameter_list_contains(parameters: &str, expected: &str) -> bool {
    parameters
        .trim_matches(|character: char| matches!(character, '(' | ')' | ' '))
        .split(',')
        .any(|parameter| parameter.trim() == expected)
}

fn module_calls(
    outside: &str,
    strings: &[String],
    offsets: &[usize],
    static_strings: &[bool],
    modules: &[&str],
    selector: &str,
) -> Vec<Vec<StaticCallArgument>> {
    let mut calls = Vec::new();
    for (index, module) in strings.iter().enumerate() {
        if static_strings.get(index) != Some(&true) {
            continue;
        }
        if !modules.contains(&module.as_str()) {
            continue;
        }
        let offset = offsets[index];
        let Some(prefix) = outside.get(..offset) else {
            continue;
        };
        let prefix = prefix.trim_end();
        if !prefix.ends_with("require(") {
            continue;
        }
        let Some(suffix) = outside.get(offset + module.len() + 2..) else {
            continue;
        };
        let suffix = suffix.trim_start();
        let Some(suffix) = suffix.strip_prefix(')') else {
            continue;
        };
        let suffix = suffix.trim_start();
        let Some(suffix) = suffix.strip_prefix('.') else {
            continue;
        };
        let Some(suffix) = suffix.strip_prefix(selector) else {
            continue;
        };
        let whitespace = suffix.len() - suffix.trim_start().len();
        let open = outside.len() - suffix.len() + whitespace;
        if let Some(arguments) =
            static_call_arguments_at_cased(outside, outside, strings, offsets, static_strings, open)
        {
            calls.push(arguments);
        }
    }
    calls
}

fn direct_require_member_assigned(
    outside: &str,
    strings: &[String],
    offsets: &[usize],
    static_strings: &[bool],
    members: &[&str],
) -> bool {
    strings.iter().enumerate().any(|(index, module)| {
        static_strings.get(index) == Some(&true)
            && matches!(
                module.as_str(),
                "fs" | "node:fs" | "child_process" | "node:child_process"
            )
            && offsets.get(index).is_some_and(|offset| {
                let prefix = outside[..*offset].trim_end();
                let suffix = outside[offset + module.len() + 2..].trim_start();
                prefix.ends_with("require(")
                    && suffix.strip_prefix(')').is_some_and(|suffix| {
                        members.iter().any(|member| {
                            suffix
                                .trim_start()
                                .strip_prefix('.')
                                .and_then(|suffix| suffix.strip_prefix(member))
                                .is_some_and(|rest| {
                                    let rest = rest.trim_start();
                                    rest.starts_with('=') && !rest.starts_with("==")
                                })
                        })
                    })
            })
    })
}

fn update_destructured_require_bindings(
    outside: &str,
    strings: &[String],
    offsets: &[usize],
    modules: &[&str],
    bindings: &mut Vec<(String, String)>,
) {
    let statement = outside.trim_start();
    let statement = ["const ", "let ", "var "]
        .iter()
        .find_map(|prefix| statement.strip_prefix(prefix))
        .unwrap_or(statement);
    if let Some(name) = assigned_identifier(statement) {
        bindings.retain(|(bound, _)| bound != name);
    }
    for (module, offset) in strings.iter().zip(offsets) {
        if !modules.contains(&module.as_str()) {
            continue;
        }
        let Some(prefix) = outside.get(..*offset) else {
            continue;
        };
        let statement = prefix.rsplit([';', '\n']).next().unwrap_or_default().trim();
        let Some(statement) = ["const ", "let ", "var "]
            .iter()
            .find_map(|prefix| statement.strip_prefix(prefix))
        else {
            continue;
        };
        let Some((receiver, value)) = statement.split_once('=') else {
            continue;
        };
        if value.trim() != "require(" {
            continue;
        }
        let Some(properties) = receiver
            .trim()
            .strip_prefix('{')
            .and_then(|receiver| receiver.strip_suffix('}'))
        else {
            continue;
        };
        for property in properties.split(',') {
            let (selector, name) = property
                .split_once(':')
                .map_or((property, property), |(selector, alias)| (selector, alias));
            let selector = selector.trim();
            let name = name.trim();
            if !matches!(
                selector,
                "exec" | "execSync" | "spawn" | "spawnSync" | "execFile" | "execFileSync"
            ) || !identifier(name)
            {
                continue;
            }
            bindings.retain(|(bound, _)| bound != name);
            bindings.push((name.to_owned(), selector.to_owned()));
        }
    }
}

fn update_require_bindings(
    outside: &str,
    strings: &[String],
    offsets: &[usize],
    modules: &[&str],
    receivers: &mut Vec<String>,
) {
    let statement = outside.trim_start();
    let statement = ["const ", "let ", "var "]
        .iter()
        .find_map(|prefix| statement.strip_prefix(prefix))
        .unwrap_or(statement);
    if let Some(receiver) = assigned_identifier(statement) {
        receivers.retain(|existing| existing != receiver);
    }
    for (module, offset) in strings.iter().zip(offsets) {
        if !modules.contains(&module.as_str()) {
            continue;
        }
        let Some(prefix) = outside.get(..*offset) else {
            continue;
        };
        let statement = prefix.rsplit([';', '\n']).next().unwrap_or_default().trim();
        let Some(statement) = ["const ", "let ", "var "]
            .iter()
            .find_map(|prefix| statement.strip_prefix(prefix))
        else {
            continue;
        };
        let Some((receiver, value)) = statement.split_once('=') else {
            continue;
        };
        let receiver = receiver.trim();
        if !identifier(receiver) || value.trim() != "require(" {
            continue;
        }
        if !receivers.iter().any(|existing| existing == receiver) {
            receivers.push(receiver.to_owned());
        }
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(code: &str) -> InlineReport {
        analyze(
            "node",
            &InlineInput {
                program: "node",
                code,
                home: "/home/dev",
                platform: nah_proto::ctx::Platform::Linux,
            },
            None,
            0,
        )
    }

    #[test]
    fn rebound_eval_is_not_treated_as_the_javascript_builtin() {
        let dangerous = "require('child_process').execSync('rm -rf /')";
        assert!(
            report(&format!("eval = value => value; eval(\"{dangerous}\")"))
                .nested_executions()
                .is_empty()
        );
        assert!(
            report(&format!(
                "function eval(value) {{ return value; }}\neval(\"{dangerous}\")"
            ))
            .nested_executions()
            .is_empty()
        );
        assert!(
            !report(&format!("eval(\"{dangerous}\"); eval = value => value"))
                .nested_executions()
                .is_empty()
        );
    }

    #[test]
    fn direct_spawn_preserves_static_nah_argv() {
        let code = "require('child_process').spawn('nah', ['nap'])";
        let (outside, strings, offsets, static_strings, _) = lexical_code_cased(code, "node");
        let calls = module_calls(
            &outside,
            &strings,
            &offsets,
            &static_strings,
            &["child_process"],
            "spawn",
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);
        assert_eq!(calls[0][0].strings, ["nah"]);
        assert_eq!(calls[0][1].strings, ["nap"]);
        assert!(calls[0][0].outside.trim().is_empty());
        assert_eq!(
            calls[0][1]
                .outside
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect::<String>(),
            "[]"
        );
        let mut report = InlineReport::default();
        add_node_argv_call(&mut report, &calls[0]);
        assert_eq!(
            report.nested_executions(),
            [crate::NestedExecution::Command {
                argv: vec!["nah".into(), "nap".into()],
                stdout_inherited: false,
            }]
        );
    }
}
