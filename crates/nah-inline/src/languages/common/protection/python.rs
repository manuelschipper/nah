use std::collections::BTreeSet;

use nah_proto::ctx::{AbsolutePath, Platform};

use crate::EnvironmentValue;
use crate::syntax::{StaticCallArgument, contains_call, lexical_code_exact, static_call_arguments};

use super::protected::{protected_namespace_ancestor_target, protected_target};

const MAX_TRACKED_SEGMENTS: usize = 1_024;

pub(super) fn python_variable_mutates_protected(
    segments: &[&str],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> Result<bool, ()> {
    if segments.len() > MAX_TRACKED_SEGMENTS {
        return Err(());
    }
    let mut protected_variables = BTreeSet::<String>::new();
    let mut protected_ancestor_variables = BTreeSet::<String>::new();
    for segment in segments {
        let (outside, strings, string_offsets, _) = lexical_code_exact(segment, "python");
        if python_mutation_candidate(&outside) {
            if protected_python_variable_is_mutated(
                &outside,
                &strings,
                &string_offsets,
                &protected_variables,
            ) {
                return Ok(true);
            }
            if protected_python_ancestor_variable_is_mutated(
                &outside,
                &strings,
                &string_offsets,
                &protected_ancestor_variables,
            ) {
                return Ok(true);
            }
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
        protected_variables.remove(name);
        protected_ancestor_variables.remove(name);
        if protected {
            protected_variables.insert(name.to_owned());
        }
        if protected_ancestor {
            protected_ancestor_variables.insert(name.to_owned());
        }
    }
    Ok(false)
}

fn python_mutation_candidate(outside: &str) -> bool {
    [
        ".unlink(",
        ".rename(",
        ".replace(",
        ".write_text(",
        ".write_bytes(",
        ".touch(",
        ".mkdir(",
        ".rmdir(",
        ".chmod(",
        ".hardlink_to(",
        ".link_to(",
        ".symlink_to(",
        "os.remove(",
        "os.symlink(",
        "os.chown(",
        "os.lchown(",
        "os.makedirs(",
        "os.removedirs(",
        "os.truncate(",
        "shutil.rmtree(",
        "shutil.move(",
    ]
    .iter()
    .any(|marker| outside.contains(marker))
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
    variables: &BTreeSet<String>,
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
    }) || [
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
                    .any(|argument| argument_mentions_variable(argument, variables))
            })
    })
}

fn argument_mentions_variable(argument: &StaticCallArgument, variables: &BTreeSet<String>) -> bool {
    argument
        .outside
        .split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .any(|word| variables.contains(word))
}

fn protected_python_ancestor_variable_is_mutated(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    variables: &BTreeSet<String>,
) -> bool {
    variables.iter().any(|variable| {
        ["unlink", "rename", "replace", "rmdir", "chmod"]
            .iter()
            .any(|method| contains_call(outside, &format!("{variable}.{method}"), false))
    }) || [
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
                    .any(|argument| argument_mentions_variable(argument, variables))
            })
    })
}
