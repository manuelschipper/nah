//! Shell arithmetic: literal evaluation of `$((...))`, integer-declared
//! variables and the arithmetic `for` header.

use std::collections::HashMap;

use crate::shell::Shell;
use crate::shell::lex::ShellSpan;
use crate::shell::shell_env::{ArrayValue, ShellEnv};
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

    /// The value of an arithmetic expansion whose operands are literal
    /// integers or exact variables established by this shell.
    pub(super) fn literal_arithmetic(&self, env: &ShellEnv, span: ShellSpan) -> Option<i64> {
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
    condition.is_empty()
        || arithmetic_truth(condition, &mut |name| values.get(name).copied()).unwrap_or(false)
}

/// Whether an arithmetic condition holds: one comparison of two
/// expressions, or one expression, which holds when it is not zero. `None`
/// when `condition` is neither or an operand is not known.
fn arithmetic_truth(
    condition: &str,
    variable: &mut dyn FnMut(&str) -> Option<i64>,
) -> Option<bool> {
    let mut value = |text: &str| {
        let mut rest = text.trim();
        let value = arithmetic_expression(&mut rest, 0, variable)?;
        rest.trim().is_empty().then_some(value)
    };
    let Some((index, operator)) = condition.char_indices().find_map(|(index, _)| {
        ["<=", ">=", "==", "!=", "<", ">"]
            .into_iter()
            .find(|operator| condition[index..].starts_with(operator))
            .map(|operator| (index, operator))
    }) else {
        return Some(value(condition)? != 0);
    };
    let left = value(&condition[..index])?;
    let right = value(&condition[index + operator.len()..])?;
    Some(match operator {
        "<=" => left <= right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        "<" => left < right,
        _ => left > right,
    })
}

impl Shell<'_> {
    /// Arithmetic `text` as bash evaluates it, after expanding the
    /// parameters in it: `$NAME` and `${NAME}` become the text the variable
    /// holds, so with `n=3-1`, `2*$n` is `2*3-1`, while a bare `n` stands
    /// for the value of `n` on its own; `${#NAME[@]}` becomes the count of a
    /// known array. Bash expands a whole `for (( ))` section, or a whole
    /// subscript, before it evaluates any of it. `None` for any other
    /// expansion or a value this shell does not know.
    pub(in crate::shell) fn expand_arithmetic(&self, env: &ShellEnv, text: &str) -> Option<String> {
        let mut expanded = String::new();
        let mut rest = text;
        while let Some(start) = rest.find('$') {
            expanded.push_str(&rest[..start]);
            rest = &rest[start + 1..];
            let name = if let Some(braced) = rest.strip_prefix('{') {
                let (inner, tail) = braced.split_once('}')?;
                rest = tail;
                if let Some(array) = inner
                    .strip_prefix('#')
                    .and_then(|counted| {
                        counted
                            .strip_suffix("[@]")
                            .or_else(|| counted.strip_suffix("[*]"))
                    })
                    .filter(|name| is_name(name))
                {
                    let count = env.arrays.get(array).and_then(ArrayValue::definite)?.len();
                    expanded.push_str(&count.to_string());
                    continue;
                }
                inner
            } else {
                let length = rest
                    .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .unwrap_or(rest.len());
                let (name, tail) = rest.split_at(length);
                rest = tail;
                name
            };
            if !is_name(name) {
                return None;
            }
            expanded.push_str(&self.parameter_literal(env, name, None)?);
        }
        expanded.push_str(rest);
        Some(expanded)
    }

    /// The value of expanded arithmetic `text` (`expand_arithmetic`) whose
    /// operands are integer constants and variables this shell knows. A
    /// variable's contents are arithmetic too; names nested in them are not
    /// followed. An increment or decrement is refused: the evaluator would
    /// read it as two signs.
    pub(in crate::shell) fn evaluate_arithmetic(&self, env: &ShellEnv, text: &str) -> Option<i64> {
        if text.contains("++") || text.contains("--") {
            return None;
        }
        let mut rest = text.trim();
        let value = arithmetic_expression(&mut rest, 0, &mut |name| {
            self.variable_arithmetic(env, name)
        })?;
        rest.trim().is_empty().then_some(value)
    }

    /// The value of arithmetic `text`, expanded and then evaluated: an
    /// array subscript.
    pub(in crate::shell) fn known_arithmetic(&self, env: &ShellEnv, text: &str) -> Option<i64> {
        self.evaluate_arithmetic(env, &self.expand_arithmetic(env, text)?)
    }

    /// Whether the `for (( ))` condition `text` holds, expanded and then
    /// evaluated; `None` when unknown.
    pub(in crate::shell) fn known_condition(&self, env: &ShellEnv, text: &str) -> Option<bool> {
        let text = self.expand_arithmetic(env, text)?;
        if text.contains("++") || text.contains("--") {
            return None;
        }
        arithmetic_truth(text.trim(), &mut |name| self.variable_arithmetic(env, name))
    }

    fn variable_arithmetic(&self, env: &ShellEnv, name: &str) -> Option<i64> {
        let contents = self.parameter_literal(env, name, None)?;
        let mut rest = contents.trim();
        let value = arithmetic_expression(&mut rest, 0, &mut |_| None)?;
        rest.trim().is_empty().then_some(value)
    }
}

/// The assignments of a `for (( ))` INIT or STEP section, in order, each
/// as the name and the expression whose value it stores: `i=0`, `i+=2`,
/// `i++` and `--i` among them. `None` when a part is no assignment.
pub(in crate::shell) fn arithmetic_assignments(section: &str) -> Option<Vec<(String, String)>> {
    let mut assignments = Vec::new();
    for part in section.split(',').filter(|_| !section.trim().is_empty()) {
        let part = part.trim();
        let stepped = |name: &str, operator| (name.trim().to_owned(), format!("{name}{operator}1"));
        let (name, expression) = if let Some(name) = part.strip_suffix("++") {
            stepped(name, '+')
        } else if let Some(name) = part.strip_suffix("--") {
            stepped(name, '-')
        } else if let Some(name) = part.strip_prefix("++") {
            stepped(name, '+')
        } else if let Some(name) = part.strip_prefix("--") {
            stepped(name, '-')
        } else if let Some((name, operator, value)) = ["+=", "-=", "*=", "/=", "%="]
            .into_iter()
            .find_map(|operator| {
                let (name, value) = part.split_once(operator)?;
                Some((name, &operator[..1], value))
            })
        {
            (name.trim().to_owned(), format!("{name}{operator}({value})"))
        } else {
            let (name, value) = part.split_once('=')?;
            if value.starts_with('=') {
                return None;
            }
            (name.trim().to_owned(), value.to_owned())
        };
        if !is_name(&name) {
            return None;
        }
        assignments.push((name, expression));
    }
    Some(assignments)
}

/// The names a `for (( ))` header's INIT and STEP sections may assign: the
/// names their assignments store, or every name in a section that is not
/// a list of assignments.
pub(in crate::shell) fn arithmetic_counters(header: &str) -> Vec<String> {
    let sections = header.split(';').collect::<Vec<_>>();
    let mut names = Vec::new();
    for section in [sections.first(), sections.get(2)].into_iter().flatten() {
        match arithmetic_assignments(section) {
            Some(assignments) => names.extend(assignments.into_iter().map(|(name, _)| name)),
            None => names.extend(
                section
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .filter(|word| is_name(word))
                    .map(str::to_owned),
            ),
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Whether arithmetic `text` may assign a variable: it holds an increment,
/// a decrement or an assignment operator, as opposed to a comparison.
pub(in crate::shell) fn may_assign(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.contains("++")
        || text.contains("--")
        || bytes.iter().enumerate().any(|(at, byte)| {
            *byte == b'='
                && bytes.get(at + 1) != Some(&b'=')
                && !(at > 0 && matches!(bytes[at - 1], b'=' | b'!' | b'<' | b'>'))
        })
}

fn is_name(text: &str) -> bool {
    text.starts_with(|character: char| character.is_ascii_alphabetic() || character == '_')
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
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
