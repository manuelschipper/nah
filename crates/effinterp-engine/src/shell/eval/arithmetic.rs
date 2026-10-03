//! Shell arithmetic: literal evaluation of `$((...))`, integer-declared
//! variables and the arithmetic `for` header.

use std::collections::HashMap;

use crate::shell::lex::Span;
use crate::shell::{Shell, ShellEnv};
use crate::word::{Word, WordPart};

impl Shell<'_> {
    /// The value `declare -i` stores: the arithmetic result of a literal
    /// expression, or unknown when the expression is not a literal one.
    pub(super) fn declared_integer(&self, env: &ShellEnv, word: &Word) -> Word {
        let value = word.as_literal().and_then(|text| {
            let mut rest = text.trim();
            // A variable's contents are arithmetic too; names nested in them
            // are not followed.
            let mut variable = |name: &str| {
                let contents = self.parameter_literal(env, name, None)?;
                let mut rest = contents.trim();
                let value = arithmetic_expression(&mut rest, 0, &mut |_| None)?;
                rest.trim().is_empty().then_some(value)
            };
            let value = arithmetic_expression(&mut rest, 0, &mut variable)?;
            rest.trim().is_empty().then_some(value)
        });
        match value {
            Some(value) => Word::literal(value.to_string()),
            None => Word::new(vec![WordPart::Unknown]),
        }
    }

    /// Analyze a recovered shell source as a nested subject. `eval` persists
    /// mutations in the current shell; command substitutions and traps do not.
    /// The value of an arithmetic expansion whose operands are literal
    /// integers or exact variables established by this shell.
    pub(super) fn literal_arithmetic(&self, env: &ShellEnv, span: Span) -> Option<i64> {
        let text = self.source.get(span.start as usize..span.end as usize)?;
        let text = text
            .strip_prefix("$((")
            .and_then(|text| text.strip_suffix("))"))
            .unwrap_or(text);
        let mut rest = text.trim();
        // A variable's contents are arithmetic too; names nested in them are
        // not followed.
        let mut variable = |name: &str| {
            let contents = self.parameter_literal(env, name, None)?;
            let mut rest = contents.trim();
            let value = arithmetic_expression(&mut rest, 0, &mut |_| None)?;
            rest.trim().is_empty().then_some(value)
        };
        let value = arithmetic_expression(&mut rest, 0, &mut variable)?;
        rest.trim().is_empty().then_some(value)
    }
}

/// Whether a `for (( INIT; COND; STEP ))` header runs its body at least once:
/// INIT assigns literal integers and COND holds for them. An empty COND is
/// always true.
pub(in crate::shell) fn arithmetic_for_enters(header: &str) -> bool {
    let [init, condition, _] = header.split(';').collect::<Vec<_>>()[..] else {
        return false;
    };
    let mut values = HashMap::new();
    for assignment in init.split(',').filter(|_| !init.trim().is_empty()) {
        let Some((name, value)) = assignment.split_once('=') else {
            return false;
        };
        let name = name.trim();
        let mut rest = value.trim();
        let Some(value) = arithmetic_expression(&mut rest, 0, &mut |_| None) else {
            return false;
        };
        if !rest.trim().is_empty()
            || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return false;
        }
        values.insert(name.to_string(), value);
    }
    let condition = condition.trim();
    if condition.is_empty() {
        return true;
    }
    let Some((index, operator)) = condition.char_indices().find_map(|(index, _)| {
        ["<=", ">=", "==", "!=", "<", ">"]
            .into_iter()
            .find(|operator| condition[index..].starts_with(operator))
            .map(|operator| (index, operator))
    }) else {
        return false;
    };
    let side = |text: &str| {
        let mut rest = text.trim();
        let value = arithmetic_expression(&mut rest, 0, &mut |name| values.get(name).copied())?;
        rest.trim().is_empty().then_some(value)
    };
    let (Some(left), Some(right)) = (
        side(&condition[..index]),
        side(&condition[index + operator.len()..]),
    ) else {
        return false;
    };
    match operator {
        "<=" => left <= right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        "<" => left < right,
        _ => left > right,
    }
}

/// Record a shell assignment. An unconditional write replaces the binding;
/// a conditional write is not definite, but its literal is unioned into the
/// set of values the name may hold so a later `$cmd` can still be resolved.
/// `producers` are the pending flow values the assignment carries; a
/// conditional write has no single unambiguous producer, and any rebinding
/// drops the previous producers.
/// Sum and product of literal integer terms, recursion bounded by the
/// nesting of parentheses.
fn arithmetic_expression(
    rest: &mut &str,
    depth: u32,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<i64> {
    if depth > 16 {
        return None;
    }
    let mut value = arithmetic_term(rest, depth, variable)?;
    loop {
        *rest = rest.trim_start();
        let operator = match rest.chars().next() {
            Some(operator @ ('+' | '-')) => operator,
            _ => return Some(value),
        };
        *rest = &rest[1..];
        let term = arithmetic_term(rest, depth, variable)?;
        value = if operator == '+' {
            value.checked_add(term)?
        } else {
            value.checked_sub(term)?
        };
    }
}

fn arithmetic_term(
    rest: &mut &str,
    depth: u32,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<i64> {
    let mut value = arithmetic_factor(rest, depth, variable)?;
    loop {
        *rest = rest.trim_start();
        let operator = match rest.chars().next() {
            Some(operator @ ('*' | '/' | '%')) => operator,
            _ => return Some(value),
        };
        *rest = &rest[1..];
        let factor = arithmetic_factor(rest, depth, variable)?;
        value = match operator {
            '*' => value.checked_mul(factor)?,
            '/' => value.checked_div(factor)?,
            _ => value.checked_rem(factor)?,
        };
    }
}

fn arithmetic_factor(
    rest: &mut &str,
    depth: u32,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<i64> {
    *rest = rest.trim_start();
    if let Some(tail) = rest.strip_prefix('-') {
        *rest = tail;
        return arithmetic_factor(rest, depth, variable)?.checked_neg();
    }
    if let Some(tail) = rest.strip_prefix('+') {
        *rest = tail;
        return arithmetic_factor(rest, depth, variable);
    }
    if let Some(tail) = rest.strip_prefix('(') {
        *rest = tail;
        let value = arithmetic_expression(rest, depth + 1, variable)?;
        *rest = rest.trim_start().strip_prefix(')')?;
        return Some(value);
    }
    let name_len = rest
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .count();
    if name_len > 0
        && rest
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
    {
        let (name, tail) = rest.split_at(name_len);
        *rest = tail;
        return variable(name);
    }
    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let length = rest.len()
        - rest
            .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || matches!(c, '#' | '@' | '_'))
            .len();
    let (number, tail) = rest.split_at(length);
    *rest = tail;
    arithmetic_constant(number)
}

/// A shell arithmetic integer constant: `0x`/`0X` hexadecimal, a leading `0`
/// octal, `BASE#DIGITS` in bases 2 to 64, and decimal otherwise. A digit
/// outside its base is an error, and a value beyond 64 bits is left unknown.
fn arithmetic_constant(number: &str) -> Option<i64> {
    let (base, digits) = if let Some((base, digits)) = number.split_once('#') {
        (
            base.parse::<u32>()
                .ok()
                .filter(|base| (2..=64).contains(base))?,
            digits,
        )
    } else if let Some(digits) = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = number.strip_prefix('0').filter(|digits| !digits.is_empty()) {
        (8, digits)
    } else {
        (10, number)
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for digit in digits.chars() {
        // Up to base 36 either case of a letter is the same digit; above it
        // lowercase letters come first, then uppercase, `@` and `_`.
        let digit = match digit {
            '0'..='9' => digit as u32 - '0' as u32,
            'a'..='z' => digit as u32 - 'a' as u32 + 10,
            'A'..='Z' if base <= 36 => digit as u32 - 'A' as u32 + 10,
            'A'..='Z' => digit as u32 - 'A' as u32 + 36,
            '@' => 62,
            '_' => 63,
            _ => return None,
        };
        if digit >= base {
            return None;
        }
        value = value
            .checked_mul(i64::from(base))?
            .checked_add(i64::from(digit))?;
    }
    Some(value)
}
