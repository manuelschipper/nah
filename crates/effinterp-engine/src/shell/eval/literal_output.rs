//! Exact output for shell producers whose arguments are all literal.

pub(super) fn render(
    name: Option<&str>,
    arguments: &[&str],
    stdin: Option<&str>,
    max_bytes: u64,
) -> Option<String> {
    let output = match (name, arguments) {
        (Some("echo"), arguments) => render_echo(arguments),
        (Some("printf"), arguments) => render_printf_arguments(arguments, max_bytes, false),
        (Some("cat"), []) => stdin.map(str::to_owned),
        // Reversing characters beyond ASCII depends on the locale.
        (Some("rev"), []) => stdin.filter(|text| text.is_ascii()).map(|text| {
            text.split_inclusive('\n')
                .map(|line| match line.strip_suffix('\n') {
                    Some(line) => line.chars().rev().chain(['\n']).collect::<String>(),
                    None => line.chars().rev().collect(),
                })
                .collect()
        }),
        (Some("tr"), [from, to]) => stdin.and_then(|text| translate(from, to, text)),
        (Some(path), arguments) => render_system_twin(path, arguments, stdin, max_bytes),
        _ => None,
    }?;
    // NUL bytes stay: a pipe carries them to consumers like `xargs -0`.
    // Callers that turn the output into shell words or source text refuse it.
    ((output.len() as u64) <= max_bytes).then_some(output)
}

/// `tr SET1 SET2` over ASCII text, for sets GNU and BSD read alike: plain
/// characters and ascending `a-z` ranges, no escapes, classes or options,
/// each character of SET1 once, and SET2 no shorter than SET1.
fn translate(from: &str, to: &str, text: &str) -> Option<String> {
    let from = tr_set(from)?;
    let to = tr_set(to)?;
    if to.len() < from.len()
        || from
            .iter()
            .enumerate()
            .any(|(index, ch)| from[..index].contains(ch))
        || !text.is_ascii()
    {
        return None;
    }
    Some(
        text.chars()
            .map(|ch| {
                from.iter()
                    .position(|&c| c == ch)
                    .map_or(ch, |index| to[index])
            })
            .collect(),
    )
}

fn tr_set(set: &str) -> Option<Vec<char>> {
    if set.is_empty() || set.starts_with('-') || !set.is_ascii() || set.contains(['\\', '[', ']']) {
        return None;
    }
    let chars = set.chars().collect::<Vec<_>>();
    let mut expanded = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars.get(index + 1) == Some(&'-') && index + 2 < chars.len() {
            let (start, end) = (chars[index], chars[index + 2]);
            if start > end {
                return None;
            }
            expanded.extend(start..=end);
            index += 3;
        } else {
            expanded.push(chars[index]);
            index += 1;
        }
    }
    Some(expanded)
}

/// The program a standard system directory spelling of `echo`, `printf`, or
/// `cat` names: `/usr/bin/printf` is the external twin of the builtin.
pub(super) fn system_twin(path: &str) -> Option<&str> {
    ["/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"]
        .iter()
        .find_map(|dir| path.strip_prefix(dir))
        .filter(|program| matches!(*program, "echo" | "printf" | "cat"))
}

/// Output of an external twin with literal arguments, where GNU and BSD agree
/// with the builtin. GNU prints usage for a lone `--help` or `--version`. BSD
/// `echo` takes only one leading `-n`, prints a later option word such as `-e`
/// literally, and stops output at `\c`; GNU reads those as options and plain
/// text, so such spellings stay unknown.
fn render_system_twin(
    path: &str,
    arguments: &[&str],
    stdin: Option<&str>,
    max_bytes: u64,
) -> Option<String> {
    if matches!(arguments, ["--help" | "--version"]) {
        return None;
    }
    match system_twin(path)? {
        "printf" => render_printf_arguments(arguments, max_bytes, true),
        "cat" if arguments.is_empty() => stdin.map(str::to_owned),
        "echo" => {
            let (newline, words) = match arguments {
                ["-n", words @ ..] => (false, words),
                words => (true, words),
            };
            let gnu_option = |word: &&str| {
                word.len() > 1
                    && word.starts_with('-')
                    && word[1..]
                        .chars()
                        .all(|option| matches!(option, 'n' | 'e' | 'E'))
            };
            if words.first().is_some_and(gnu_option) || words.iter().any(|word| word.contains('\\'))
            {
                return None;
            }
            let mut output = words.join(" ");
            if newline {
                output.push('\n');
            }
            Some(output)
        }
        _ => None,
    }
}

/// Whether every escape in a printf format or `%b` argument is one GNU and BSD
/// printf decode alike: BSD has no `\x`, `\u`, or `\U`, and after `\0` one
/// reads three more octal digits where the other reads two. `%s` copies its
/// argument verbatim in both, so it needs no check.
fn shared_printf_escapes(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            continue;
        }
        match chars.next() {
            Some('a' | 'b' | 'f' | 'n' | 'r' | 't' | 'v' | '\\' | '1'..='7') => {}
            Some('0') => {
                let mut digits = 0;
                while chars.next_if(|digit| digit.is_digit(8)).is_some() {
                    digits += 1;
                }
                if digits > 2 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn render_echo(arguments: &[&str]) -> Option<String> {
    let mut newline = true;
    let mut escapes = false;
    let mut offset = 0;
    while let Some(argument) = arguments.get(offset)
        && argument.len() > 1
        && argument.starts_with('-')
        && argument[1..]
            .chars()
            .all(|option| matches!(option, 'n' | 'e' | 'E'))
    {
        for option in argument[1..].chars() {
            match option {
                'n' => newline = false,
                'e' => escapes = true,
                'E' => escapes = false,
                _ => unreachable!(),
            }
        }
        offset += 1;
    }
    let text = arguments[offset..].join(" ");
    let mut output = String::new();
    if escapes {
        decode_escaped_text(&text, &mut output)?;
    } else {
        output.push_str(&text);
    }
    if newline {
        output.push('\n');
    }
    Some(output)
}

/// `shared` limits the interpreted escapes to those GNU and BSD printf share,
/// for the external twin; the builtin decodes Bash's full set.
fn render_printf_arguments(arguments: &[&str], max_bytes: u64, shared: bool) -> Option<String> {
    let arguments = match arguments {
        ["--", arguments @ ..] => arguments,
        arguments => arguments,
    };
    let [format, arguments @ ..] = arguments else {
        return None;
    };
    if format.starts_with('-') || shared && !shared_printf_escapes(format) {
        return None;
    }
    render_printf(format, arguments, max_bytes, shared)
}

fn render_printf(format: &str, arguments: &[&str], max_bytes: u64, shared: bool) -> Option<String> {
    let mut output = String::new();
    let mut offset = 0;
    loop {
        let consumed = render_printf_once(format, &arguments[offset..], &mut output, shared)?;
        if output.len() as u64 > max_bytes {
            return None;
        }
        if consumed == 0 || offset + consumed >= arguments.len() {
            return Some(output);
        }
        offset += consumed;
    }
}

fn render_printf_once(
    format: &str,
    arguments: &[&str],
    output: &mut String,
    shared: bool,
) -> Option<usize> {
    let mut chars = format.chars().peekable();
    let mut consumed = 0;
    while let Some(character) = chars.next() {
        match character {
            '%' => match chars.next()? {
                '%' => output.push('%'),
                's' => {
                    output.push_str(arguments.get(consumed).copied().unwrap_or(""));
                    consumed += 1;
                }
                // The first character, verbatim. Bash writes a whole multibyte
                // character where other printfs write one byte, so only ASCII is exact.
                // An empty or missing argument writes a NUL byte in Bash 5 and
                // nothing in Bash 3.2, so its output is unknown.
                'c' => {
                    let first = arguments.get(consumed)?.chars().next()?;
                    if !first.is_ascii() {
                        return None;
                    }
                    output.push(first);
                    consumed += 1;
                }
                'b' => {
                    let argument = arguments.get(consumed).copied().unwrap_or("");
                    if shared && !shared_printf_escapes(argument) {
                        return None;
                    }
                    decode_escaped_text(argument, output)?;
                    consumed += 1;
                }
                _ => return None,
            },
            '\\' => output.push(decode_escape(&mut chars, PrintfEscapeContext::Format)?),
            character => output.push(character),
        }
    }
    Some(consumed)
}

fn decode_escaped_text(input: &str, output: &mut String) -> Option<()> {
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\\' => output.push(decode_escape(&mut chars, PrintfEscapeContext::PercentB)?),
            character => output.push(character),
        }
    }
    Some(())
}

#[derive(Clone, Copy)]
enum PrintfEscapeContext {
    Format,
    PercentB,
}

fn decode_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    context: PrintfEscapeContext,
) -> Option<char> {
    let escape = chars.next()?;
    Some(match escape {
        'a' => '\u{7}',
        'b' => '\u{8}',
        'e' | 'E' => '\u{1b}',
        'f' => '\u{c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\u{b}',
        '0' => {
            if matches!(context, PrintfEscapeContext::Format) {
                decode_octal_byte(chars, 0, 2)?
            } else {
                decode_octal_byte(chars, 0, 3)?
            }
        }
        '1'..='7' => decode_octal_byte(chars, escape.to_digit(8)?, 2)?,
        'x' => decode_ascii_byte(decode_digits(chars, 16, 1, 2)?)?,
        'u' => char::from_u32(decode_ascii_digits(chars, 4)?)?,
        'U' => char::from_u32(decode_ascii_digits(chars, 8)?)?,
        '\\' => '\\',
        '\'' | '"' if matches!(context, PrintfEscapeContext::Format) => escape,
        _ => return None,
    })
}

fn decode_octal_byte(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    mut value: u32,
    remaining: usize,
) -> Option<char> {
    for _ in 0..remaining {
        let Some(digit) = chars.peek().and_then(|character| character.to_digit(8)) else {
            break;
        };
        chars.next();
        value = value * 8 + digit;
    }
    decode_ascii_byte(value)
}

fn decode_ascii_byte(value: u32) -> Option<char> {
    let byte = (value & 0xff) as u8;
    byte.is_ascii().then(|| char::from(byte))
}

fn decode_digits(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    minimum: usize,
    maximum: usize,
) -> Option<u32> {
    let mut value = 0;
    let mut consumed = 0;
    while consumed < maximum {
        let Some(digit) = chars.peek().and_then(|character| character.to_digit(radix)) else {
            break;
        };
        chars.next();
        value = value * radix + digit;
        consumed += 1;
    }
    (consumed >= minimum).then_some(value)
}

fn decode_ascii_digits(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    width: usize,
) -> Option<u32> {
    let value = decode_digits(chars, 16, width, width)?;
    (value <= 0x7f).then_some(value)
}
