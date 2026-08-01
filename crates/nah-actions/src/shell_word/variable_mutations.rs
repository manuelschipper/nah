//! Detects shell-word expansions that can mutate Bash variable state.

use super::{ExpansionContext, resolve_word, valid_env_name};
use crate::bash_model::{ResolvedWord, VariableValue};

pub(crate) fn parameter_assignment_required(
    raw: &str,
    variables: &[(String, VariableValue)],
) -> bool {
    parameter_assignment_required_in(raw, variables, true, 0)
}

pub(crate) fn definite_parameter_assignments(
    raw: &str,
    variables: &[(String, VariableValue)],
) -> Vec<(String, String)> {
    definite_parameter_assignments_in(raw, variables, true)
}

pub(crate) fn here_document_definite_parameter_assignments(
    raw: &str,
    variables: &[(String, VariableValue)],
) -> Vec<(String, String)> {
    definite_parameter_assignments_in(raw, variables, false)
}

fn definite_parameter_assignments_in(
    raw: &str,
    variables: &[(String, VariableValue)],
    honor_quotes: bool,
) -> Vec<(String, String)> {
    let mut visible = variables.to_vec();
    let mut assignments = Vec::new();
    collect_definite_parameter_assignments(raw, &mut visible, &mut assignments, honor_quotes, 0);
    assignments
}

pub(crate) fn here_document_parameter_assignment_required(
    raw: &str,
    variables: &[(String, VariableValue)],
) -> bool {
    // Quotes are literal characters in an expanding here-document body.
    parameter_assignment_required_in(raw, variables, false, 0)
}

pub(crate) fn arithmetic_possibly_mutated_names(raw: &str) -> Option<Vec<String>> {
    const MAX_NAMES: usize = 256;

    let start = raw.find("((")? + 2;
    let end = raw.rfind("))")?;
    let expression = raw.get(start..end)?;
    if !arithmetic_may_mutate(expression.as_bytes()) {
        return Some(Vec::new());
    }

    let bytes = expression.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'_' && !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while bytes
            .get(index)
            .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
        {
            index += 1;
        }
        let name = &expression[start..index];
        if !names.iter().any(|candidate| candidate == name) {
            if names.len() == MAX_NAMES {
                return None;
            }
            names.push(name.to_owned());
        }
    }
    Some(names)
}

fn arithmetic_may_mutate(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|operator| matches!(operator, [b'<', b'<', b'='] | [b'>', b'>', b'=']))
        || bytes.windows(2).any(|pair| {
            matches!(
                pair,
                [b'+', b'+']
                    | [b'-', b'-']
                    | [b'+', b'=']
                    | [b'-', b'=']
                    | [b'*', b'=']
                    | [b'/', b'=']
                    | [b'%', b'=']
                    | [b'&', b'=']
                    | [b'|', b'=']
                    | [b'^', b'=']
            )
        })
        || bytes.iter().enumerate().any(|(index, byte)| {
            *byte == b'='
                && !matches!(
                    index.checked_sub(1).and_then(|prior| bytes.get(prior)),
                    Some(b'=' | b'!' | b'<' | b'>')
                )
                && bytes.get(index + 1) != Some(&b'=')
        })
}

const MAX_PARAMETER_ASSIGNMENT_DEPTH: usize = 64;

fn collect_definite_parameter_assignments(
    raw: &str,
    variables: &mut Vec<(String, VariableValue)>,
    assignments: &mut Vec<(String, String)>,
    honor_quotes: bool,
    depth: usize,
) {
    if depth >= MAX_PARAMETER_ASSIGNMENT_DEPTH {
        return;
    }
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut quote = None;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if honor_quotes && quote.is_none() => {
                quote = Some(b'\'');
                index += 1;
            }
            b'"' if honor_quotes && quote.is_none() => {
                quote = Some(b'"');
                index += 1;
            }
            byte if honor_quotes && quote == Some(byte) => {
                quote = None;
                index += 1;
            }
            b'\\' if quote != Some(b'\'') => index = (index + 2).min(bytes.len()),
            b'$' if quote != Some(b'\'') && bytes.get(index + 1) == Some(&b'{') => {
                if let Some(end) = parameter_expansion_end(raw, index + 2, honor_quotes) {
                    collect_definite_parameter_expansion(
                        &raw[index + 2..end],
                        variables,
                        assignments,
                        honor_quotes,
                        depth,
                    );
                    index = end + 1;
                } else {
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }
}

fn collect_definite_parameter_expansion(
    expansion: &str,
    variables: &mut Vec<(String, VariableValue)>,
    assignments: &mut Vec<(String, String)>,
    honor_quotes: bool,
    depth: usize,
) {
    let bytes = expansion.as_bytes();
    let mut index = 0;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        index += 1;
    }
    let name = &expansion[..index];
    if !valid_env_name(name) {
        collect_definite_parameter_assignments(
            expansion,
            variables,
            assignments,
            honor_quotes,
            depth + 1,
        );
        return;
    }
    if expansion[index..].starts_with("[0]") {
        index += 3;
    } else if bytes.get(index) == Some(&b'[') {
        collect_definite_parameter_assignments(
            &expansion[index..],
            variables,
            assignments,
            honor_quotes,
            depth + 1,
        );
        return;
    }
    let colon = bytes.get(index) == Some(&b':')
        && bytes
            .get(index + 1)
            .is_some_and(|operator| matches!(*operator, b'-' | b'+' | b'='));
    if colon {
        index += 1;
    }
    let Some(operator @ (b'-' | b'+' | b'=')) = bytes.get(index).copied() else {
        collect_definite_parameter_assignments(
            &expansion[index..],
            variables,
            assignments,
            honor_quotes,
            depth + 1,
        );
        return;
    };
    let word = &expansion[index + 1..];
    let value = variables
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value));
    let unset = matches!(value, None | Some(VariableValue::Unset));
    let empty = matches!(value, Some(VariableValue::Static(value)) if value.is_empty());
    let selected = match operator {
        b'-' | b'=' => unset || colon && empty,
        b'+' => matches!(value, Some(VariableValue::Static(_))) && (!colon || !empty),
        _ => unreachable!("parameter operator was matched"),
    };
    if !selected {
        return;
    }
    collect_definite_parameter_assignments(word, variables, assignments, honor_quotes, depth + 1);
    if operator != b'=' {
        return;
    }
    let resolved = resolve_word(word, &[], variables, ExpansionContext::Assignment, |_| None);
    let ResolvedWord::Static { value, .. } = resolved else {
        return;
    };
    if let Some((_, current)) = variables
        .iter_mut()
        .find(|(candidate, _)| candidate == name)
    {
        *current = VariableValue::Static(value.clone());
    } else {
        variables.push((name.to_owned(), VariableValue::Static(value.clone())));
    }
    assignments.push((name.to_owned(), value));
}

fn parameter_assignment_required_in(
    raw: &str,
    variables: &[(String, VariableValue)],
    honor_quotes: bool,
    depth: usize,
) -> bool {
    if depth >= MAX_PARAMETER_ASSIGNMENT_DEPTH {
        return true;
    }
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut quote = None;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if honor_quotes && quote.is_none() => {
                quote = Some(b'\'');
                index += 1;
            }
            b'"' if honor_quotes && quote.is_none() => {
                quote = Some(b'"');
                index += 1;
            }
            byte if honor_quotes && quote == Some(byte) => {
                quote = None;
                index += 1;
            }
            b'\\' if quote != Some(b'\'') => {
                index = (index + 2).min(bytes.len());
            }
            b'$' if quote != Some(b'\'') && bytes.get(index + 1) == Some(&b'{') => {
                if let Some(end) = parameter_expansion_end(raw, index + 2, honor_quotes) {
                    if parameter_expansion_assignment_required(
                        &raw[index + 2..end],
                        variables,
                        honor_quotes,
                        depth,
                    ) {
                        return true;
                    }
                    index = end + 1;
                } else {
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }
    false
}

fn parameter_expansion_end(raw: &str, start: usize, honor_quotes: bool) -> Option<usize> {
    let bytes = raw.as_bytes();
    let mut index = start;
    let mut depth = 1usize;
    let mut quote = None;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if honor_quotes && quote.is_none() => {
                quote = Some(b'\'');
                index += 1;
            }
            b'"' if honor_quotes && quote.is_none() => {
                quote = Some(b'"');
                index += 1;
            }
            byte if honor_quotes && quote == Some(byte) => {
                quote = None;
                index += 1;
            }
            b'\\' if quote != Some(b'\'') => {
                index = (index + 2).min(bytes.len());
            }
            b'$' if quote != Some(b'\'') && bytes.get(index + 1) == Some(&b'{') => {
                depth += 1;
                index += 2;
            }
            b'}' if quote != Some(b'\'') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn parameter_expansion_assignment_required(
    expansion: &str,
    variables: &[(String, VariableValue)],
    honor_quotes: bool,
    depth: usize,
) -> bool {
    let bytes = expansion.as_bytes();
    let mut index = 0;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        index += 1;
    }
    let name = &expansion[..index];
    if !valid_env_name(name) {
        return parameter_assignment_required_in(expansion, variables, honor_quotes, depth + 1);
    }
    if expansion[index..].starts_with("[0]") {
        index += 3;
    } else if bytes.get(index) == Some(&b'[') {
        return parameter_assignment_required_in(
            &expansion[index..],
            variables,
            honor_quotes,
            depth + 1,
        );
    }
    let colon = bytes.get(index) == Some(&b':')
        && bytes
            .get(index + 1)
            .is_some_and(|operator| matches!(*operator, b'-' | b'+' | b'='));
    if colon {
        index += 1;
    }
    let Some(operator @ (b'-' | b'+' | b'=')) = bytes.get(index).copied() else {
        return parameter_assignment_required_in(
            &expansion[index..],
            variables,
            honor_quotes,
            depth + 1,
        );
    };
    let word = &expansion[index + 1..];
    let value = variables
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value));
    let unset = matches!(value, None | Some(VariableValue::Unset));
    let empty = matches!(value, Some(VariableValue::Static(value)) if value.is_empty());
    let unknown = matches!(value, Some(VariableValue::Unknown));
    match operator {
        b'=' => unset || unknown || colon && empty,
        b'-' => {
            (unset || unknown || colon && empty)
                && parameter_assignment_required_in(word, variables, honor_quotes, depth + 1)
        }
        b'+' => {
            (!unset && (unknown || !colon || !empty))
                && parameter_assignment_required_in(word, variables, honor_quotes, depth + 1)
        }
        _ => unreachable!("parameter operator was matched"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::INVOCATION_EVIDENCE_CAP;

    #[test]
    fn parameter_assignment_detection_follows_selected_words_and_array_zero() {
        let variables = vec![
            (
                "OUTER".to_owned(),
                VariableValue::Static("present".to_owned()),
            ),
            ("EMPTY".to_owned(), VariableValue::Static(String::new())),
            ("UNSET".to_owned(), VariableValue::Unset),
            ("INNER".to_owned(), VariableValue::Unset),
            ("ROWS".to_owned(), VariableValue::Unset),
        ];

        for raw in [
            "\"${UNSET:-${INNER:=/}}\"",
            "\"${OUTER:+${INNER:=/}}\"",
            "\"${EMPTY+${INNER:=/}}\"",
            "\"${ROWS[0]:=/}\"",
        ] {
            assert!(parameter_assignment_required(raw, &variables), "{raw}");
        }
        for raw in [
            "\"${OUTER:-${INNER:=/}}\"",
            "\"${UNSET:+${INNER:=/}}\"",
            "'${INNER:=/}'",
            r#"\${INNER:=/}"#,
        ] {
            assert!(!parameter_assignment_required(raw, &variables), "{raw}");
        }

        assert!(here_document_parameter_assignment_required(
            "'${INNER:=/}'",
            &variables
        ));
        assert!(!here_document_parameter_assignment_required(
            r#"\${INNER:=/}"#,
            &variables
        ));
    }

    #[test]
    fn definite_parameter_assignments_keep_only_exact_selected_values() {
        let variables = vec![
            ("UNSET".to_owned(), VariableValue::Unset),
            ("EMPTY".to_owned(), VariableValue::Static(String::new())),
            (
                "SET".to_owned(),
                VariableValue::Static("present".to_owned()),
            ),
            ("UNKNOWN".to_owned(), VariableValue::Unknown),
        ];
        assert_eq!(
            definite_parameter_assignments(
                "${UNSET:=/} ${EMPTY:=/tmp} ${SET:=ignored}",
                &variables,
            ),
            vec![
                ("UNSET".to_owned(), "/".to_owned()),
                ("EMPTY".to_owned(), "/tmp".to_owned()),
            ]
        );
        assert!(definite_parameter_assignments("${UNKNOWN:=/}", &variables).is_empty());
        assert!(definite_parameter_assignments("'${UNSET:=/}'", &variables).is_empty());
        assert_eq!(
            here_document_definite_parameter_assignments("'${UNSET:=/}'", &variables),
            vec![("UNSET".to_owned(), "/".to_owned())]
        );
    }

    #[test]
    fn definite_parameter_assignments_follow_nested_and_prior_updates() {
        let variables = vec![
            ("OUTER".to_owned(), VariableValue::Unset),
            ("INNER".to_owned(), VariableValue::Unset),
            ("NEXT".to_owned(), VariableValue::Unset),
        ];
        assert_eq!(
            definite_parameter_assignments("${OUTER:-${INNER:=/}} ${NEXT:=$INNER}", &variables,),
            vec![
                ("INNER".to_owned(), "/".to_owned()),
                ("NEXT".to_owned(), "/".to_owned()),
            ]
        );
    }

    #[test]
    fn arithmetic_mutation_names_ignore_comparisons() {
        assert_eq!(
            arithmetic_possibly_mutated_names("((flag=1))").unwrap(),
            ["flag"]
        );
        assert_eq!(
            arithmetic_possibly_mutated_names("for ((i=0; i<3; i++));").unwrap(),
            ["i"]
        );
        assert_eq!(
            arithmetic_possibly_mutated_names("((array[index++] += value))").unwrap(),
            ["array", "index", "value"]
        );
        assert_eq!(
            arithmetic_possibly_mutated_names("((mask <<= shift))").unwrap(),
            ["mask", "shift"]
        );
        assert_eq!(
            arithmetic_possibly_mutated_names("((mask >>= shift))").unwrap(),
            ["mask", "shift"]
        );
        assert!(
            arithmetic_possibly_mutated_names("((count > 0))")
                .unwrap()
                .is_empty()
        );
        assert!(
            arithmetic_possibly_mutated_names("((left == right))")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn deeply_nested_parameter_words_fail_closed_without_unbounded_recursion() {
        let core = "${INNER:=/}";
        let layers = (INVOCATION_EVIDENCE_CAP - core.len()) / 6;
        let mut raw = String::with_capacity(INVOCATION_EVIDENCE_CAP);
        for _ in 0..layers {
            raw.push_str("${X:-");
        }
        raw.push_str(core);
        for _ in 0..layers {
            raw.push('}');
        }
        assert!(raw.len() <= INVOCATION_EVIDENCE_CAP);
        assert!(raw.len() + 6 > INVOCATION_EVIDENCE_CAP);
        assert!(parameter_assignment_required(
            &raw,
            &[
                ("X".to_owned(), VariableValue::Unset),
                ("INNER".to_owned(), VariableValue::Unset),
            ],
        ));
    }
}
