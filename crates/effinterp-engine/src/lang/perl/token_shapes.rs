//! Shapes of a Perl token slice the compiler asks about: literal data,
//! constant operands, balanced arguments, the end of a call, list items and
//! the lowest-precedence operator split.

use std::collections::BTreeMap;

use super::tokenize::{PerlToken, SPECIAL_VARIABLE_UNMODELED};
use super::{PerlFailure, PerlImports};

/// Split a list at its top-level commas, dropping the empty item a trailing
/// comma leaves.
pub(super) fn split_list_items(tokens: &[PerlToken]) -> Vec<&[PerlToken]> {
    let mut depth = 0i64;
    let mut items: Vec<_> = tokens
        .split(|token| {
            match token {
                PerlToken::Punct('(' | '[' | '{') => depth += 1,
                PerlToken::Punct(')' | ']' | '}') => depth -= 1,
                _ => {}
            }
            depth == 0 && *token == PerlToken::Punct(',')
        })
        .collect();
    if items.last().is_some_and(|item| item.is_empty()) {
        items.pop();
    }
    items
}

/// Whether `tokens` is literal data: strings, numbers, hash keys and the
/// punctuation of nested hash and array literals, with nothing evaluated.
pub(super) fn is_literal_data(tokens: &[PerlToken]) -> bool {
    tokens.iter().enumerate().all(|(index, token)| match token {
        PerlToken::Text(_) | PerlToken::Number(_) => true,
        PerlToken::Punct(c) => matches!(c, '{' | '}' | '[' | ']' | ',' | '=' | '>'),
        // A bareword is data only as a hash key.
        PerlToken::Name(_) => {
            tokens.get(index + 1) == Some(&PerlToken::Punct('='))
                && tokens.get(index + 2) == Some(&PerlToken::Punct('>'))
        }
        _ => false,
    })
}

/// `decode_base64(...)` as imported from MIME::Base64, with one argument.
pub(super) fn decodes_base64(tokens: &[PerlToken], imports: &PerlImports) -> bool {
    matches!(
        tokens,
        [PerlToken::Name(name), PerlToken::Punct('('), argument @ .., PerlToken::Punct(')')]
            if name == "decode_base64" && imports.owns(name) && brackets_balance(argument)
                && !argument.contains(&PerlToken::Punct(','))
    )
}

/// The literal text of an expression: strings and literally bound variables
/// joined by `.`. Anything else is a runtime-selected value and is refused.
/// The text is charged to the analysis byte budget.
pub(super) fn perl_literal_text(
    tokens: &[PerlToken],
    variables: &BTreeMap<String, String>,
    budget: &crate::nest::Budget,
) -> Result<String, PerlFailure> {
    // A `.` concatenation of literal operands is itself literal.
    let mut value = String::new();
    for operand in tokens.split(|token| *token == PerlToken::Punct('.')) {
        value.push_str(match operand {
            [PerlToken::Text(value)] => value,
            [PerlToken::Variable(name)] => variables
                .get(name)
                .ok_or_else(|| format!("Perl variable ${name} has no literal binding"))?,
            [PerlToken::Unknown(detail)] => return Err(detail.clone().into()),
            [PerlToken::Special(_)] => return Err(SPECIAL_VARIABLE_UNMODELED.into()),
            _ => return Err("Perl path or value is a runtime-selected expression".into()),
        });
    }
    // A move can retain this path in three pending effects plus the binding.
    if !budget.try_charge_bytes((value.len() as u64).saturating_mul(4)) {
        return Err(PerlFailure::AnalysisBytes);
    }
    Ok(value)
}

/// Whether an argument's parentheses, brackets and braces balance. Arguments
/// are split at every comma, so an unbalanced one spans a nested list.
pub(super) fn brackets_balance(tokens: &[PerlToken]) -> bool {
    let mut depth = 0_i32;
    for token in tokens {
        match token {
            PerlToken::Punct('(' | '[' | '{') => depth += 1,
            PerlToken::Punct(')' | ']' | '}') => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0 && !tokens.is_empty()
}

/// The value of a numeric literal token: octal when it has a leading zero.
pub(super) fn perl_number(value: &str) -> Result<u32, PerlFailure> {
    let radix = if value.starts_with('0') { 8 } else { 10 };
    u32::from_str_radix(value, radix).map_err(|_| "Perl numeric literal is out of range".into())
}

/// Whether `tokens` is one numeric literal `perl_number` reads: decimal, or
/// octal digits after a leading zero.
pub(super) fn numeric_tokens(tokens: &[PerlToken]) -> bool {
    matches!(tokens, [PerlToken::Number(value)] if !value.starts_with('0') || value.bytes().all(|c| matches!(c, b'0'..=b'7')))
}

/// A lexical, scalar or bareword filehandle.
pub(super) fn is_filehandle(tokens: &[PerlToken]) -> bool {
    matches!(tokens, [PerlToken::Variable(_) | PerlToken::Name(_)])
        || matches!(tokens, [PerlToken::Name(my), PerlToken::Variable(_)] if my == "my")
}

/// Whether a refused statement leaves every later fact intact: output or
/// closing a handle, or a `die`/`exit` that may not run, whose arguments are
/// only literals and plain variables. An unconditional `die` or `exit` ends
/// the program, unless an enclosing `eval` catches it.
pub(super) fn refused_statement_is_inert(statement: &[PerlToken], conditional: bool) -> bool {
    let [PerlToken::Name(name), args @ ..] = statement else {
        return false;
    };
    let output = matches!(name.as_str(), "print" | "say" | "warn" | "close");
    (output || (conditional && matches!(name.as_str(), "die" | "exit")))
        && args.iter().all(|token| {
            matches!(
                token,
                PerlToken::Text(_)
                    | PerlToken::Number(_)
                    | PerlToken::Variable(_)
                    | PerlToken::Punct(',' | '(' | ')' | '.')
            )
        })
}

/// The end of the `name(...)` call that opens `tokens`.
pub(super) fn call_end(tokens: &[PerlToken]) -> Option<usize> {
    let [PerlToken::Name(_), PerlToken::Punct('('), ..] = tokens else {
        return None;
    };
    let mut depth = 0u32;
    for (index, token) in tokens.iter().enumerate().skip(1) {
        match token {
            PerlToken::Punct('(') => depth += 1,
            PerlToken::Punct(')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Constant expressions longer than this are not folded.
const MAX_CONSTANT_TOKENS: usize = 256;

/// A constant operand's definedness and truth: a literal, an `xor` of
/// constants, or a short-circuit chain that stops at a constant. The right operand is read only when it runs,
/// so `1 or unlink(...)` is the constant `1`.
pub(super) fn constant_operand(tokens: &[PerlToken]) -> Option<(bool, bool)> {
    match tokens {
        [PerlToken::Number(value)] => Some((true, value.bytes().any(|byte| byte != b'0'))),
        [PerlToken::Text(value)] => Some((true, !value.is_empty() && value != "0")),
        [PerlToken::Name(undef)] if undef == "undef" => Some((false, false)),
        _ if tokens.len() > MAX_CONSTANT_TOKENS => None,
        _ => {
            let (left, operator, right) = split_at_lowest_operator(tokens)?;
            let value = constant_operand(left)?;
            if operator == "xor" {
                // Both operands run; the result is defined.
                return Some((true, value.1 != constant_operand(right)?.1));
            }
            let stops = match operator {
                "or" | "||" => value.1,
                "and" | "&&" => !value.1,
                "//" => value.0,
                _ => return None,
            };
            if stops {
                Some(value)
            } else {
                constant_operand(right)
            }
        }
    }
}

/// Split at the lowest-precedence operator outside parentheses and braces:
/// an `if` or `unless` modifier, then `or` or `xor`, `and`, `||` or `//`, and
/// `&&`.
/// The split is structural: a symbolic operator binds tighter than a list
/// operator or assignment, so a caller accepts it only after a whole call or a
/// constant.
pub(super) fn split_at_lowest_operator(
    statement: &[PerlToken],
) -> Option<(&[PerlToken], &'static str, &[PerlToken])> {
    let mut last: [Option<(usize, &'static str)>; 5] = [None; 5];
    let mut depth = 0i64;
    for (index, token) in statement.iter().enumerate() {
        let found = match token {
            PerlToken::Punct('(' | '{') => {
                depth += 1;
                None
            }
            PerlToken::Punct(')' | '}') => {
                depth -= 1;
                None
            }
            _ if depth != 0 || index == 0 => None,
            PerlToken::Name(name) => match name.as_str() {
                "if" => Some((0, "if")),
                "unless" => Some((0, "unless")),
                "or" => Some((1, "or")),
                "xor" => Some((1, "xor")),
                "and" => Some((2, "and")),
                _ => None,
            },
            PerlToken::Punct(c @ ('|' | '/' | '&'))
                if statement.get(index + 1) == Some(&PerlToken::Punct(*c))
                    && statement.get(index - 1) != Some(&PerlToken::Punct(*c)) =>
            {
                match c {
                    '|' => Some((3, "||")),
                    '/' => Some((3, "//")),
                    _ => Some((4, "&&")),
                }
            }
            _ => None,
        };
        // The operators are left-associative, so the last one groups last.
        if let Some((class, operator)) = found {
            last[class] = Some((index, operator));
        }
    }
    let (index, operator) = last.into_iter().flatten().next()?;
    // A word operator is one token; a symbolic one is two.
    let symbolic = !operator.starts_with(char::is_alphabetic);
    let (left, right) = (
        &statement[..index],
        &statement[index + 1 + usize::from(symbolic)..],
    );
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left, operator, right))
}
