//! Extracts conservative static shell words; it does not expand or execute shell syntax.

use nah_parse::{Substitution, Word};

use crate::INVOCATION_EVIDENCE_CAP;
use crate::bash_model::{ResolvedWord, UnresolvedCause, VariableValue};

mod variable_mutations;

pub(crate) use variable_mutations::{
    arithmetic_possibly_mutated_names, definite_parameter_assignments,
    here_document_definite_parameter_assignments, here_document_parameter_assignment_required,
    parameter_assignment_required,
};

#[derive(Clone, Copy)]
pub(crate) enum ExpansionContext {
    Assignment,
    ShellWord,
}

#[derive(Clone, Copy)]
enum ResolutionFailure {
    UnknownValue,
    ShellTransformation,
}

pub(crate) fn resolve_word(
    raw: &str,
    substitutions: &[Substitution],
    variables: &[(String, VariableValue)],
    context: ExpansionContext,
    mut substitution_output: impl FnMut(&Substitution) -> Option<String>,
) -> ResolvedWord {
    let mut output = String::new();
    let mut chars = raw.chars().peekable();
    let mut substitutions = substitutions.iter();
    let mut quote = None;
    let mut changed = false;
    let mut forces_word = false;
    let mut pattern = false;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '$') if chars.peek() == Some(&'\'') => {
                chars.next();
                let Some(value) = ansi_c_quoted(&mut chars) else {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                };
                forces_word = true;
                output.push_str(&value);
            }
            (None, '\'') => {
                quote = Some('\'');
                forces_word = true;
            }
            (None, '"') => {
                quote = Some('"');
                forces_word = true;
            }
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), character) => {
                forces_word = true;
                output.push(character);
            }
            (None, '\\') => {
                let Some(escaped) = chars.next() else {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                };
                forces_word = true;
                if escaped != '\n' {
                    output.push(escaped);
                }
            }
            (Some('"'), '\\') => {
                let Some(escaped) = chars.next() else {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                };
                forces_word = true;
                if matches!(escaped, '$' | '`' | '"' | '\\') {
                    output.push(escaped);
                } else if escaped != '\n' {
                    output.push('\\');
                    output.push(escaped);
                }
            }
            (None | Some('"'), '$') if chars.peek() == Some(&'(') => {
                if chars.clone().nth(1) == Some('(') {
                    let Some(value) = static_arithmetic_expansion(&mut chars) else {
                        return unresolved(raw, UnresolvedCause::ShellTransformation);
                    };
                    changed = true;
                    output.push_str(&value);
                    continue;
                }
                let Some(substitution @ Substitution::Command { .. }) = substitutions.next() else {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                };
                let Some(value) = substitution_output(substitution) else {
                    return unresolved(raw, UnresolvedCause::UnknownValue);
                };
                if !consume_command_substitution(&mut chars) || value.contains('\0') {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                }
                changed = true;
                if quote.is_none() && matches!(context, ExpansionContext::ShellWord) {
                    if field_splitting_possible(&value, variables) {
                        return unresolved(raw, UnresolvedCause::ShellTransformation);
                    }
                    pattern |= contains_shell_pattern(&value);
                }
                output.push_str(&value);
            }
            (None | Some('"'), '$') => {
                let value = match parameter_value(&mut chars, variables) {
                    Ok(value) => value,
                    Err(ResolutionFailure::UnknownValue) => {
                        return unresolved(raw, UnresolvedCause::UnknownValue);
                    }
                    Err(ResolutionFailure::ShellTransformation) => {
                        return unresolved(raw, UnresolvedCause::ShellTransformation);
                    }
                };
                changed = true;
                if quote.is_none() && matches!(context, ExpansionContext::ShellWord) {
                    if field_splitting_possible(&value, variables) {
                        return unresolved(raw, UnresolvedCause::ShellTransformation);
                    }
                    pattern |= contains_shell_pattern(&value);
                }
                output.push_str(&value);
            }
            (None | Some('"'), '`') => {
                let Some(substitution @ Substitution::Backtick { .. }) = substitutions.next()
                else {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                };
                let Some(value) = substitution_output(substitution) else {
                    return unresolved(raw, UnresolvedCause::UnknownValue);
                };
                if !consume_backtick_substitution(&mut chars) || value.contains('\0') {
                    return unresolved(raw, UnresolvedCause::ShellTransformation);
                }
                changed = true;
                if quote.is_none() && matches!(context, ExpansionContext::ShellWord) {
                    if field_splitting_possible(&value, variables) {
                        return unresolved(raw, UnresolvedCause::ShellTransformation);
                    }
                    pattern |= contains_shell_pattern(&value);
                }
                output.push_str(&value);
            }
            (None, character) => {
                forces_word = true;
                pattern |= matches!(context, ExpansionContext::ShellWord)
                    && (matches!(character, '*' | '?' | '[' | '{')
                        || matches!(character, '@' | '+' | '!') && chars.peek() == Some(&'('));
                output.push(character);
            }
            (Some('"'), character) => {
                forces_word = true;
                output.push(character);
            }
            _ => unreachable!("all quote states are covered"),
        }
        if output.len() > INVOCATION_EVIDENCE_CAP {
            return unresolved(raw, UnresolvedCause::ShellTransformation);
        }
    }
    if quote.is_some() {
        return unresolved(raw, UnresolvedCause::ShellTransformation);
    }
    if substitutions.next().is_some() {
        return unresolved(raw, UnresolvedCause::ShellTransformation);
    }
    if output.is_empty()
        && changed
        && !forces_word
        && matches!(context, ExpansionContext::ShellWord)
    {
        return ResolvedWord::Absent;
    }
    if pattern {
        ResolvedWord::Pattern {
            value: output,
            changed,
        }
    } else {
        ResolvedWord::Static {
            value: output,
            changed,
        }
    }
}

fn field_splitting_possible(value: &str, variables: &[(String, VariableValue)]) -> bool {
    match variables
        .iter()
        .find_map(|(name, value)| (name == "IFS").then_some(value))
    {
        None | Some(VariableValue::Unset) => value.bytes().any(|byte| byte.is_ascii_whitespace()),
        Some(VariableValue::Static(ifs)) => {
            !ifs.is_empty() && value.chars().any(|character| ifs.contains(character))
        }
        Some(VariableValue::Unknown) => !value.is_empty(),
    }
}

pub(crate) fn materialize_word(original: &Word, resolved: &ResolvedWord) -> Option<Word> {
    match resolved {
        ResolvedWord::Absent => None,
        ResolvedWord::Static { changed: false, .. }
        | ResolvedWord::Pattern { changed: false, .. }
        | ResolvedWord::Unresolved { .. } => Some(original.clone()),
        ResolvedWord::Static {
            value,
            changed: true,
        } => Some(Word::from_literal(value)),
        ResolvedWord::Pattern {
            value,
            changed: true,
        } => Some(Word::from_expanded_pattern(value)),
    }
}

fn parameter_value(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    variables: &[(String, VariableValue)],
) -> Result<String, ResolutionFailure> {
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut name = String::new();
        if chars
            .peek()
            .is_some_and(|character| matches!(*character, '@' | '*'))
        {
            name.push(chars.next().expect("peeked positional parameter"));
        }
        while chars
            .peek()
            .is_some_and(|character| character.is_ascii_alphanumeric() || *character == '_')
        {
            name.push(chars.next().expect("peeked parameter character"));
        }
        if !valid_parameter_name(&name) {
            return Err(ResolutionFailure::ShellTransformation);
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            if chars.next() != Some('0') || chars.next() != Some(']') {
                return Err(ResolutionFailure::ShellTransformation);
            }
        }
        let value = variables
            .iter()
            .find_map(|(candidate, value)| (candidate == &name).then_some(value))
            .ok_or(ResolutionFailure::UnknownValue)?;
        let operator = chars.next().ok_or(ResolutionFailure::ShellTransformation)?;
        if operator == '}' {
            return variable_value(value).ok_or(ResolutionFailure::UnknownValue);
        }
        let (colon, operator) = if operator == ':' {
            (
                true,
                chars.next().ok_or(ResolutionFailure::ShellTransformation)?,
            )
        } else {
            (false, operator)
        };
        if !matches!(operator, '-' | '+' | '=') {
            return Err(ResolutionFailure::ShellTransformation);
        }
        let fallback =
            static_parameter_fallback(chars).ok_or(ResolutionFailure::ShellTransformation)?;
        match (operator, colon, value) {
            ('-' | '=', true, VariableValue::Unset) => Ok(fallback),
            ('-' | '=', true, VariableValue::Static(value)) if value.is_empty() => Ok(fallback),
            ('-' | '=', false, VariableValue::Unset) => Ok(fallback),
            ('-' | '=', _, VariableValue::Static(value)) => Ok(value.clone()),
            ('+', true, VariableValue::Unset) => Ok(String::new()),
            ('+', true, VariableValue::Static(value)) if value.is_empty() => Ok(String::new()),
            ('+', false, VariableValue::Unset) => Ok(String::new()),
            ('+', _, VariableValue::Static(_)) => Ok(fallback),
            (_, _, VariableValue::Unknown) => Err(ResolutionFailure::ShellTransformation),
            _ => Err(ResolutionFailure::ShellTransformation),
        }
    } else if chars
        .peek()
        .is_some_and(|character| character.is_ascii_digit() || matches!(*character, '@' | '*'))
    {
        let name = chars
            .next()
            .expect("peeked positional parameter")
            .to_string();
        variables
            .iter()
            .find_map(|(candidate, value)| (candidate == &name).then_some(value))
            .and_then(variable_value)
            .ok_or(ResolutionFailure::UnknownValue)
    } else {
        let mut name = String::new();
        while chars
            .peek()
            .is_some_and(|character| character.is_ascii_alphanumeric() || *character == '_')
        {
            name.push(chars.next().expect("peeked parameter character"));
        }
        if !valid_env_name(&name) {
            return Err(ResolutionFailure::ShellTransformation);
        }
        variables
            .iter()
            .find_map(|(candidate, value)| (candidate == &name).then_some(value))
            .and_then(variable_value)
            .ok_or(ResolutionFailure::UnknownValue)
    }
}

fn variable_value(value: &VariableValue) -> Option<String> {
    match value {
        VariableValue::Unset => Some(String::new()),
        VariableValue::Static(value) => Some(value.clone()),
        VariableValue::Unknown => None,
    }
}

fn static_parameter_fallback(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<String> {
    let mut fallback = String::new();
    for character in chars.by_ref() {
        if character == '}' {
            return static_word(&fallback, true);
        }
        fallback.push(character);
    }
    None
}

fn valid_parameter_name(name: &str) -> bool {
    valid_env_name(name)
        || matches!(name, "@" | "*")
        || !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
}

fn static_arithmetic_expansion(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<String> {
    if chars.next() != Some('(') || chars.next() != Some('(') {
        return None;
    }
    let mut expression = String::new();
    let mut depth = 0usize;
    while let Some(character) = chars.next() {
        match character {
            '(' => {
                depth += 1;
                expression.push(character);
            }
            ')' if depth > 0 => {
                depth -= 1;
                expression.push(character);
            }
            ')' if chars.next() == Some(')') => {
                return ArithmeticParser::new(&expression)
                    .parse()
                    .map(|value| value.to_string());
            }
            ')' => return None,
            character => expression.push(character),
        }
    }
    None
}

struct ArithmeticParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> ArithmeticParser<'a> {
    fn new(expression: &'a str) -> Self {
        Self {
            bytes: expression.as_bytes(),
            index: 0,
        }
    }

    fn parse(mut self) -> Option<i128> {
        let value = self.sum()?;
        self.skip_whitespace();
        (self.index == self.bytes.len()).then_some(value)
    }

    fn sum(&mut self) -> Option<i128> {
        let mut value = self.product()?;
        loop {
            self.skip_whitespace();
            value = match self.peek() {
                Some(b'+') => {
                    self.index += 1;
                    value.checked_add(self.product()?)?
                }
                Some(b'-') => {
                    self.index += 1;
                    value.checked_sub(self.product()?)?
                }
                _ => return Some(value),
            };
        }
    }

    fn product(&mut self) -> Option<i128> {
        let mut value = self.factor()?;
        loop {
            self.skip_whitespace();
            value = match self.peek() {
                Some(b'*') => {
                    self.index += 1;
                    value.checked_mul(self.factor()?)?
                }
                Some(b'/') => {
                    self.index += 1;
                    value.checked_div(self.factor()?)?
                }
                Some(b'%') => {
                    self.index += 1;
                    value.checked_rem(self.factor()?)?
                }
                _ => return Some(value),
            };
        }
    }

    fn factor(&mut self) -> Option<i128> {
        self.skip_whitespace();
        match self.peek()? {
            b'+' => {
                self.index += 1;
                self.factor()
            }
            b'-' => {
                self.index += 1;
                self.factor()?.checked_neg()
            }
            b'(' => {
                self.index += 1;
                let value = self.sum()?;
                self.skip_whitespace();
                (self.next() == Some(b')')).then_some(value)
            }
            digit if digit.is_ascii_digit() => self.integer(),
            _ => None,
        }
    }

    fn integer(&mut self) -> Option<i128> {
        let start = self.index;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.index += 1;
        }
        let digits = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        if digits.len() > 1 && digits.starts_with('0') {
            return None;
        }
        digits.parse().ok()
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.index += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.index += 1;
        Some(value)
    }
}

fn consume_command_substitution(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    if chars.next() != Some('(') {
        return false;
    }
    let mut depth = 1;
    let mut quote = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '\'') => quote = Some('\''),
            (None, '"') => quote = Some('"'),
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (None | Some('"'), '\\') => {
                if chars.next().is_none() {
                    return false;
                }
            }
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn consume_backtick_substitution(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    while let Some(character) = chars.next() {
        match character {
            '\\' => {
                if chars.next().is_none() {
                    return false;
                }
            }
            '`' => return true,
            _ => {}
        }
    }
    false
}

fn unresolved(raw: &str, cause: UnresolvedCause) -> ResolvedWord {
    let (literal_prefix, _) = shell_literal_prefix(raw);
    ResolvedWord::Unresolved {
        may_be_absolute: literal_prefix.is_empty(),
        literal_prefix,
        cause,
    }
}

pub(crate) fn contains_shell_pattern(value: &str) -> bool {
    value.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'['))
        || value
            .as_bytes()
            .windows(2)
            .any(|pair| matches!(pair, [b'@' | b'+' | b'!', b'(']))
}

/// Reports a pattern the shell itself expands. Quoted and escaped pattern
/// characters name a literal file, so only unquoted ones count.
pub(crate) fn contains_unquoted_pattern(raw: &str) -> bool {
    let mut chars = raw.chars();
    let mut quote = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '\'') => quote = Some('\''),
            (None, '"') => quote = Some('"'),
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (None | Some('"'), '\\') => {
                chars.next();
            }
            (None, '@' | '+' | '!') if chars.clone().next() == Some('(') => {
                return true;
            }
            (None, '*' | '?' | '[' | '{') => return true,
            _ => {}
        }
    }
    false
}

pub(crate) fn has_unmodeled_expansion(raw: &str) -> bool {
    let mut chars = raw.chars().peekable();
    let mut quote = None;
    let mut first = true;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '$') if chars.peek() == Some(&'\'') => {
                chars.next();
                if ansi_c_quoted(&mut chars).is_none() {
                    return true;
                }
            }
            (None, '\'') => quote = Some('\''),
            (None, '"') => quote = Some('"'),
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (None | Some('"'), '\\') => {
                chars.next();
            }
            (None | Some('"'), '$') => {
                let mut lookahead = chars.clone();
                if lookahead.next() != Some('(') || lookahead.next() == Some('(') {
                    return true;
                }
            }
            (None, '@' | '+' | '!') if chars.peek() == Some(&'(') => {
                return true;
            }
            (None, '*' | '?' | '[' | '{' | '}') => return true,
            (None, '~') if first => return true,
            _ => {}
        }
        first = false;
    }
    false
}

pub(crate) fn static_word(raw: &str, no_substitutions: bool) -> Option<String> {
    if !no_substitutions {
        return None;
    }
    let mut output = String::new();
    let mut chars = raw.chars().peekable();
    let mut quote = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '$') if chars.peek() == Some(&'\'') => {
                chars.next();
                output.push_str(&ansi_c_quoted(&mut chars)?);
            }
            (None, '\'') => quote = Some('\''),
            (None, '"') => quote = Some('"'),
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), character) => output.push(character),
            (None, '\\') => {
                let escaped = chars.next()?;
                if escaped != '\n' {
                    output.push(escaped);
                }
            }
            (Some('"'), '\\') => {
                let escaped = chars.next()?;
                if matches!(escaped, '$' | '`' | '"' | '\\') {
                    output.push(escaped);
                } else if escaped != '\n' {
                    output.push('\\');
                    output.push(escaped);
                }
            }
            (_, '$' | '`') => return None,
            (_, character) => output.push(character),
        }
    }
    quote.is_none().then_some(output)
}

pub(crate) fn shell_literal_prefix(raw: &str) -> (String, bool) {
    let mut output = String::new();
    let mut chars = raw.chars();
    let mut quote = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '\'') => quote = Some('\''),
            (None, '"') => quote = Some('"'),
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), character) => output.push(character),
            (None | Some('"'), '\\') => {
                if let Some(escaped) = chars.next() {
                    output.push(escaped);
                }
            }
            (None | Some('"'), '$' | '`') => return (output, true),
            (_, character) => output.push(character),
        }
    }
    (output, false)
}

fn ansi_c_quoted(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let mut output = String::new();
    loop {
        match chars.next()? {
            '\'' => return Some(output),
            '\\' => push_ansi_escape(chars, &mut output)?,
            character => output.push(character),
        }
    }
}

fn push_ansi_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
) -> Option<()> {
    let escaped = chars.next()?;
    let character = match escaped {
        'a' => '\u{7}',
        'b' => '\u{8}',
        'e' | 'E' => '\u{1b}',
        'f' => '\u{c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\u{b}',
        '\\' => '\\',
        '\'' => '\'',
        '"' => '"',
        '?' => '?',
        '\n' => return Some(()),
        'c' => {
            let control = chars.next()?.to_ascii_uppercase() as u32 & 0x1f;
            char::from_u32(control).filter(|character| *character != '\0')?
        }
        'x' => decode_digits(chars, 16, 2, 1)?,
        'u' => decode_digits(chars, 16, 4, 4)?,
        'U' => decode_digits(chars, 16, 8, 8)?,
        digit if matches!(digit, '0'..='7') => {
            let mut digits = String::from(digit);
            while digits.len() < 3 && chars.peek().is_some_and(|next| matches!(next, '0'..='7')) {
                digits.push(chars.next().expect("peeked octal digit"));
            }
            char::from_u32(u32::from_str_radix(&digits, 8).ok()?)
                .filter(|character| *character != '\0')?
        }
        _ => return None,
    };
    output.push(character);
    Some(())
}

fn decode_digits(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    maximum: usize,
    minimum: usize,
) -> Option<char> {
    let mut digits = String::new();
    while digits.len() < maximum && chars.peek().is_some_and(|next| next.is_digit(radix)) {
        digits.push(chars.next().expect("peeked digit"));
    }
    (digits.len() >= minimum)
        .then(|| u32::from_str_radix(&digits, radix).ok())
        .flatten()
        .and_then(char::from_u32)
        .filter(|character| *character != '\0')
}

pub(crate) fn static_filesystem_word(raw: &str, no_substitutions: bool) -> Option<String> {
    if let Some(value) = static_word(raw, no_substitutions) {
        // Preserve a quoted or escaped leading tilde as a relative literal. A
        // bare leading tilde is the only form the shell expands to HOME.
        return Some(if value.starts_with('~') && !raw.starts_with('~') {
            format!("./{value}")
        } else {
            value
        });
    }
    if !no_substitutions {
        return None;
    }
    if let Some(suffix) = static_environment_path_suffix(raw, "HOME") {
        return Some(format!("~{suffix}"));
    }
    if let Some(suffix) = static_environment_path_suffix(raw, "PWD") {
        return Some(format!("~+{suffix}"));
    }
    None
}

pub(crate) fn static_environment_path_suffix(raw: &str, name: &str) -> Option<String> {
    let (quoted, value) = match raw.strip_prefix('"') {
        Some(value) => (true, value),
        None => (false, raw),
    };
    let suffix = value
        .strip_prefix(&format!("${name}"))
        .or_else(|| value.strip_prefix(&format!("${{{name}}}")))?;
    // Adjacent quoted and unquoted fragments concatenate, so the quoting may
    // close right after the variable as in `"$HOME"/.ssh`. Reassemble both
    // spellings before resolving the rest of the path.
    let suffix = if quoted {
        suffix
            .strip_prefix('"')
            .or_else(|| suffix.strip_suffix('"'))?
    } else {
        suffix
    };
    if !suffix.is_empty() && !suffix.starts_with(['/', '\\']) {
        return None;
    }
    if suffix.contains(['$', '`', '\'', '"']) {
        return None;
    }
    Some(suffix.to_owned())
}

pub(crate) fn exact_env_name(raw: &str) -> Option<&str> {
    let raw = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    let name = raw
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .or_else(|| raw.strip_prefix('$'))?;
    valid_env_name(name).then_some(name)
}

pub(crate) fn referenced_env_names(raw: &str) -> Vec<String> {
    referenced_env_names_in(raw, true)
}

pub(crate) fn here_document_referenced_env_names(raw: &str) -> Vec<String> {
    referenced_env_names_in(raw, false)
}

fn referenced_env_names_in(raw: &str, honor_single_quotes: bool) -> Vec<String> {
    let bytes = raw.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    let mut single_quoted = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if honor_single_quotes => {
                single_quoted = !single_quoted;
                index += 1;
            }
            b'\\' if !single_quoted => index = (index + 2).min(bytes.len()),
            b'$' if !single_quoted => {
                let start = index + 1;
                let (name_start, braced) = if bytes.get(start) == Some(&b'{') {
                    (start + 1, true)
                } else {
                    (start, false)
                };
                let mut end = name_start;
                while bytes
                    .get(end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    end += 1;
                }
                let reference_end = if braced && bytes.get(end) == Some(&b'[') {
                    bytes[end + 1..]
                        .iter()
                        .position(|byte| *byte == b']')
                        .map(|offset| end + 1 + offset + 1)
                        .filter(|end| bytes.get(*end) == Some(&b'}'))
                        .map(|end| end + 1)
                } else if !braced || bytes.get(end) == Some(&b'}') {
                    Some(end + usize::from(braced))
                } else {
                    None
                };
                if end > name_start && valid_env_name(&raw[name_start..end]) {
                    names.push(raw[name_start..end].to_owned());
                }
                index = reference_end.unwrap_or(end).max(index + 1);
            }
            _ => index += 1,
        }
    }
    names.sort();
    names.dedup();
    names
}

pub(crate) fn referenced_positional_names(raw: &str) -> Vec<String> {
    let bytes = raw.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    let mut single_quoted = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                single_quoted = !single_quoted;
                index += 1;
            }
            b'\\' if !single_quoted => index = (index + 2).min(bytes.len()),
            b'$' if !single_quoted => {
                let start = index + 1;
                if bytes.get(start) == Some(&b'{') {
                    let name_start = start + 1;
                    let mut end = name_start;
                    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                        end += 1;
                    }
                    if end == name_start && bytes.get(end) == Some(&b'@') {
                        end += 1;
                    }
                    if end > name_start && bytes.get(end) == Some(&b'}') {
                        names.push(raw[name_start..end].to_owned());
                        index = end + 1;
                        continue;
                    }
                } else if bytes.get(start).is_some_and(u8::is_ascii_digit)
                    || bytes.get(start) == Some(&b'@')
                {
                    names.push(raw[start..start + 1].to_owned());
                    index = start + 1;
                    continue;
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    names.sort();
    names.dedup();
    names
}

fn valid_env_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests;
