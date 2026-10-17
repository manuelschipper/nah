//! The jq filter grammar that decides what a filter prints of the process
//! environment (`env`, `$ENV`), for the declarative `jq_environment_read`
//! condition.

use effinterp_model_schema::JqEnvironmentRead;

/// What a jq filter prints of the process environment: `None` when it never
/// reads `env` or `$ENV`.
///
/// The filter is read as a pipeline of values. The environment stays whole
/// through the constructs that keep every value (`[env]`, `{e: env}`,
/// `env, .`, `. + $ENV`, `env | tojson`, `"\(env)"`, `env | to_entries[] |
/// "\(.key)=\(.value)"`), and stops being whole at one that picks or
/// computes (`env.PATH`, `env | keys`, `env | length`). A construct outside
/// this grammar (destructuring `as` patterns, `reduce`, `def`, comparisons)
/// leaves a filter that names the environment unresolved rather than
/// guessed. A plain `as $name` binding, `if`, and the arguments of `first`,
/// `last` and `limit` are followed.
pub(super) fn jq_environment_read(filter: &str) -> Option<JqEnvironmentRead> {
    let tokens = jq_tokens(filter);
    let mut reader = JqReader {
        tokens: &tokens,
        index: 0,
        depth: 0,
        bindings: Vec::new(),
    };
    let value = reader
        .pipe(JqValue::Clean)
        .filter(|_| reader.index == tokens.len());
    match value {
        Some(JqValue::Clean) => None,
        Some(JqValue::Environment | JqValue::Entries | JqValue::Whole) => {
            Some(JqEnvironmentRead::Whole)
        }
        Some(JqValue::Touched) => Some(JqEnvironmentRead::Unresolved),
        None => tokens
            .iter()
            .any(|token| matches!(token, JqToken::Identifier("env") | JqToken::Variable("ENV")))
            .then_some(JqEnvironmentRead::Unresolved),
    }
}

/// One lexical token of a jq filter, borrowing its text from the filter.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JqToken<'a> {
    /// `.name`, the field access jq lexes as one token.
    Field(&'a str),
    Identifier(&'a str),
    Variable(&'a str),
    /// `@name`.
    Format(&'a str),
    Number(&'a str),
    StringOpen,
    StringClose,
    /// `\(` inside a string, and the `)` that closes it.
    InterpolationOpen,
    InterpolationClose,
    Punctuation(&'a str),
}

/// Lex a jq filter into tokens. Any character that starts no other token
/// is a `Punctuation` of its own, which the reader accepts only where its
/// grammar names it.
fn jq_tokens(filter: &str) -> Vec<JqToken<'_>> {
    const OPERATORS: [&str; 17] = [
        "?//", "//=", "|=", "+=", "-=", "*=", "/=", "%=", "==", "!=", "<=", ">=", "//", "..", "<",
        ">", "=",
    ];
    let bytes = filter.as_bytes();
    let word_end = |start: usize| {
        start
            + bytes[start..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                .count()
    };
    let word_starts = |index: usize| {
        bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    };
    let mut tokens = Vec::new();
    // One entry per open string: the parentheses open inside its current
    // interpolation, or `None` while reading its text.
    let mut strings: Vec<Option<usize>> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(None) = strings.last() {
            match byte {
                b'"' => {
                    strings.pop();
                    tokens.push(JqToken::StringClose);
                }
                b'\\' if bytes.get(index + 1) == Some(&b'(') => {
                    *strings.last_mut().unwrap() = Some(0);
                    tokens.push(JqToken::InterpolationOpen);
                    index += 1;
                }
                b'\\' => index += 1,
                _ => {}
            }
            index += 1;
            continue;
        }
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' => index += 1,
            b'#' => {
                index += bytes[index..]
                    .iter()
                    .take_while(|byte| **byte != b'\n')
                    .count();
            }
            b'"' => {
                strings.push(None);
                tokens.push(JqToken::StringOpen);
                index += 1;
            }
            b'(' | b')' => {
                let open = strings.last_mut().and_then(Option::as_mut);
                match (byte, open) {
                    (b')', Some(0)) => {
                        *strings.last_mut().unwrap() = None;
                        tokens.push(JqToken::InterpolationClose);
                    }
                    (_, open) => {
                        if let Some(open) = open {
                            *open = if byte == b'(' { *open + 1 } else { *open - 1 };
                        }
                        tokens.push(JqToken::Punctuation(&filter[index..index + 1]));
                    }
                }
                index += 1;
            }
            b'.' if word_starts(index + 1) => {
                let end = word_end(index + 1);
                tokens.push(JqToken::Field(&filter[index + 1..end]));
                index = end;
            }
            b'$' | b'@' if word_starts(index + 1) => {
                let end = word_end(index + 1);
                let name = &filter[index + 1..end];
                tokens.push(if byte == b'$' {
                    JqToken::Variable(name)
                } else {
                    JqToken::Format(name)
                });
                index = end;
            }
            b'0'..=b'9' => {
                // A number's exact extent does not matter: only that its
                // digits and exponent are not read as names.
                let end = index
                    + bytes[index..]
                        .iter()
                        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'.')
                        .count();
                tokens.push(JqToken::Number(&filter[index..end]));
                index = end;
            }
            b'.' if bytes.get(index + 1).is_some_and(u8::is_ascii_digit) => {
                index += 1;
            }
            _ if word_starts(index) => {
                let mut end = word_end(index);
                // `module::name` is one identifier.
                while bytes[end..].starts_with(b"::") && word_starts(end + 2) {
                    end = word_end(end + 2);
                }
                tokens.push(JqToken::Identifier(&filter[index..end]));
                index = end;
            }
            _ => {
                let length = OPERATORS
                    .iter()
                    .find(|operator| filter[index..].starts_with(**operator))
                    .map_or_else(
                        || filter[index..].chars().next().map_or(1, char::len_utf8),
                        |operator| operator.len(),
                    );
                tokens.push(JqToken::Punctuation(&filter[index..index + length]));
                index += length;
            }
        }
    }
    tokens
}

/// What a jq value holds of the process environment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JqValue {
    /// Nothing read from the environment.
    Clean,
    /// Part of the environment, or something computed from it.
    Touched,
    /// The environment object, alone or inside a constructed value.
    Environment,
    /// Its `{key, value}` entries, as `to_entries` produces them.
    Entries,
    /// Every variable's value in some other form, such as serialized text.
    Whole,
}

impl JqValue {
    /// Whether printing this value prints every environment variable's value.
    fn discloses(self) -> bool {
        matches!(self, Self::Environment | Self::Entries | Self::Whole)
    }

    /// A value that carries both operands, as `a, b` or `a + b` does.
    fn with(self, other: Self) -> Self {
        match (self, other) {
            (left, right) if left == right => left,
            (kept, Self::Clean | Self::Touched) if kept.discloses() => kept,
            (Self::Clean | Self::Touched, kept) if kept.discloses() => kept,
            (Self::Clean | Self::Touched, Self::Clean | Self::Touched) => Self::Touched,
            _ => Self::Whole,
        }
    }

    /// The result of an operation that computes from this value rather than
    /// keeping it.
    fn computed(self) -> Self {
        if self == Self::Clean {
            Self::Clean
        } else {
            Self::Touched
        }
    }

    /// `.name`: one field of this value. Only an entry's `value` keeps the
    /// environment whole.
    fn field(self, name: &str) -> Self {
        match self {
            Self::Entries if name == "value" => Self::Whole,
            other => other.computed(),
        }
    }

    /// `.[]`: every value of an object or array.
    fn iterated(self) -> Self {
        match self {
            Self::Environment => Self::Whole,
            other => other,
        }
    }
}

/// A recursive-descent reader over a jq filter's tokens. Each grammar method
/// takes the value the construct runs on and returns the value it produces,
/// or `None` where the filter leaves the grammar.
struct JqReader<'a> {
    tokens: &'a [JqToken<'a>],
    index: usize,
    depth: usize,
    /// What each `as $name` in scope bound, innermost last.
    bindings: Vec<(&'a str, JqValue)>,
}

impl<'a> JqReader<'a> {
    fn peek(&self) -> Option<JqToken<'a>> {
        self.tokens.get(self.index).copied()
    }

    /// Consume `punctuation` when it is the next token.
    fn eat(&mut self, punctuation: &str) -> bool {
        let found = self.peek() == Some(JqToken::Punctuation(punctuation));
        self.index += usize::from(found);
        found
    }

    /// `a | b`: `b` runs on what `a` produces. `None` wherever the filter
    /// leaves the grammar this reader resolves.
    fn pipe(&mut self, input: JqValue) -> Option<JqValue> {
        // Nesting is bounded so a generated filter cannot exhaust the stack.
        self.depth += 1;
        if self.depth > 64 {
            return None;
        }
        let mut value = self.operation(input)?;
        // `term as $name | body`: the body runs on the same input with the
        // name bound to what the term produced.
        if self.peek() == Some(JqToken::Identifier("as")) {
            self.index += 1;
            let Some(JqToken::Variable(name)) = self.peek() else {
                return None;
            };
            self.index += 1;
            if !self.eat("|") {
                return None;
            }
            self.bindings.push((name, value));
            let body = self.pipe(input);
            self.bindings.pop();
            self.depth -= 1;
            return body;
        }
        while self.eat(",") {
            value = value.with(self.operation(input)?);
        }
        if self.eat("|") {
            value = self.pipe(value)?;
        }
        self.depth -= 1;
        Some(value)
    }

    /// Consume the keyword `name` when it is the next token.
    fn keyword(&mut self, name: &str) -> bool {
        let found = self.peek() == Some(JqToken::Identifier(name));
        self.index += usize::from(found);
        found
    }

    /// What a literal condition before `then` always is: `false` and `null`
    /// are false, and every number and `true` is true.
    fn literal_condition(&self) -> Option<bool> {
        if self.tokens.get(self.index + 1) != Some(&JqToken::Identifier("then")) {
            return None;
        }
        match self.peek()? {
            JqToken::Identifier("false" | "null") => Some(false),
            JqToken::Identifier("true") | JqToken::Number(_) => Some(true),
            _ => None,
        }
    }

    /// The rest of `if c then a elif c then a else b end` after its `if`:
    /// any arm a literal condition does not rule out may be the one that
    /// prints, and a condition only computes from what it reads.
    fn conditional(&mut self, input: JqValue) -> Option<JqValue> {
        let mut value: Option<JqValue> = None;
        let mut join = |arm: JqValue| value = Some(value.map_or(arm, |value| value.with(arm)));
        // Whether control can still reach the next condition or the `else`.
        let mut reachable = true;
        loop {
            let literal = self.literal_condition();
            let tested = self.pipe(input)?.computed();
            if !self.keyword("then") {
                return None;
            }
            let arm = self.pipe(input)?;
            if reachable {
                join(tested);
                if literal != Some(false) {
                    join(arm);
                }
                reachable = literal != Some(true);
            }
            if self.keyword("elif") {
                continue;
            }
            // Without an `else` the false arm passes the input on.
            let last = if self.keyword("else") {
                self.pipe(input)?
            } else {
                input
            };
            if reachable {
                join(last);
            }
            break;
        }
        self.keyword("end").then_some(value?)
    }

    /// The comma operands of a filter argument, each with whether it always
    /// emits a value: a number, a constant, a variable, `env` or a plain
    /// string does. An argument that pipes or binds is one operand that may
    /// emit nothing.
    fn stream(&mut self, input: JqValue) -> Option<Vec<(JqValue, bool)>> {
        let start = self.index;
        let mut operands = Vec::new();
        loop {
            let first = self.index;
            let value = self.operation(input)?;
            let emits = matches!(
                &self.tokens[first..self.index],
                [JqToken::Number(_) | JqToken::Variable(_)]
                    | [JqToken::Identifier("env" | "true" | "false" | "null")]
                    | [JqToken::StringOpen, JqToken::StringClose]
            );
            operands.push((value, emits));
            if !self.eat(",") {
                break;
            }
        }
        if matches!(self.peek(), Some(JqToken::Punctuation(";" | ")"))) {
            return Some(operands);
        }
        self.index = start;
        Some(vec![(self.pipe(input)?, false)])
    }

    /// `first(f)`, `last(f)` or `limit(n; f)` after its `(`: the outputs of
    /// `f` it can print. The first output comes from the operands up to the
    /// first that always emits, the last from the final such operand on,
    /// and `limit(0; f)` never runs `f`.
    fn selection(&mut self, name: &str, input: JqValue) -> Option<JqValue> {
        let mut count = JqValue::Clean;
        let mut take_first = name == "first";
        if name == "limit" {
            let literal = match (self.peek()?, self.tokens.get(self.index + 1)) {
                (JqToken::Number(digits), Some(JqToken::Punctuation(";"))) => Some(digits),
                _ => None,
            };
            count = self.pipe(input)?.computed();
            if !self.eat(";") {
                return None;
            }
            match literal {
                Some("0") => {
                    self.stream(input)?;
                    return self.eat(")").then_some(JqValue::Clean);
                }
                Some("1") => take_first = true,
                _ => {}
            }
        }
        let operands = self.stream(input)?;
        if !self.eat(")") {
            return None;
        }
        let emits = |(_, emits): &(JqValue, bool)| *emits;
        let reached = if take_first {
            let end = operands
                .iter()
                .position(emits)
                .map_or(operands.len(), |at| at + 1);
            &operands[..end]
        } else if name == "last" {
            &operands[operands.iter().rposition(emits).unwrap_or(0)..]
        } else {
            &operands[..]
        };
        Some(
            reached
                .iter()
                .fold(count, |value, (operand, _)| value.with(*operand)),
        )
    }

    /// Operands joined by the arithmetic and alternative operators. `+` and
    /// `//` keep an operand whole; the others compute from it.
    fn operation(&mut self, input: JqValue) -> Option<JqValue> {
        let mut value = self.operand(input)?;
        loop {
            let keeps = if self.eat("+") || self.eat("//") {
                true
            } else if self.eat("-") || self.eat("*") || self.eat("/") || self.eat("%") {
                false
            } else {
                return Some(value);
            };
            let right = self.operand(input)?;
            value = if keeps {
                value.with(right)
            } else {
                value.with(right).computed()
            };
        }
    }

    /// A term with its postfix accesses (`.name`, `?`, `.[...]`), or the
    /// negation of one.
    fn operand(&mut self, input: JqValue) -> Option<JqValue> {
        if self.eat("-") {
            return Some(self.operand(input)?.computed());
        }
        let mut value = self.term(input)?;
        loop {
            match self.peek() {
                Some(JqToken::Field(name)) => {
                    self.index += 1;
                    value = value.field(name);
                }
                Some(JqToken::Punctuation("?")) => self.index += 1,
                Some(JqToken::Punctuation(".")) => {
                    // `."name"` and `.[...]` after a term.
                    self.index += 1;
                    if self.peek() == Some(JqToken::StringOpen) {
                        value = value.with(self.string(input)?).computed();
                    } else if self.peek() != Some(JqToken::Punctuation("[")) {
                        return None;
                    }
                }
                Some(JqToken::Punctuation("[")) => {
                    self.index += 1;
                    value = self.subscript(value, input)?;
                }
                _ => return Some(value),
            }
        }
    }

    /// The rest of `[...]` after a term: `[]` iterates, anything else picks
    /// an element or a slice.
    fn subscript(&mut self, value: JqValue, input: JqValue) -> Option<JqValue> {
        if self.eat("]") {
            return Some(value.iterated());
        }
        let mut picked = value;
        if self.peek() != Some(JqToken::Punctuation(":")) {
            picked = picked.with(self.pipe(input)?);
        }
        if self.eat(":") && self.peek() != Some(JqToken::Punctuation("]")) {
            picked = picked.with(self.pipe(input)?);
        }
        self.eat("]").then_some(picked.computed())
    }

    /// A string after its opening quote token: it carries what its
    /// interpolations print.
    fn string(&mut self, input: JqValue) -> Option<JqValue> {
        self.index += 1;
        let mut value = JqValue::Clean;
        loop {
            match self.peek()? {
                JqToken::StringClose => {
                    self.index += 1;
                    return Some(value);
                }
                JqToken::InterpolationOpen => {
                    self.index += 1;
                    let part = self.pipe(input)?;
                    if self.peek() != Some(JqToken::InterpolationClose) {
                        return None;
                    }
                    self.index += 1;
                    // Interpolation serializes the value.
                    let part = if part.discloses() {
                        JqValue::Whole
                    } else {
                        part
                    };
                    value = value.with(part);
                }
                _ => return None,
            }
        }
    }

    /// One primary: a string, `.`, `..`, field, number, variable, `@format`,
    /// bracketed or parenthesized filter, object, or a function call.
    fn term(&mut self, input: JqValue) -> Option<JqValue> {
        let token = self.peek()?;
        if token == JqToken::StringOpen {
            return self.string(input);
        }
        self.index += 1;
        match token {
            JqToken::Field(name) => Some(input.field(name)),
            JqToken::Number(_) => Some(JqValue::Clean),
            JqToken::Variable(name) => Some(
                match self.bindings.iter().rev().find(|(bound, _)| *bound == name) {
                    Some((_, value)) => *value,
                    None if name == "ENV" => JqValue::Environment,
                    None => JqValue::Clean,
                },
            ),
            JqToken::Format(name) => {
                if self.peek() == Some(JqToken::StringOpen) {
                    return self.string(input);
                }
                // These formats serialize an object. The others (`@csv`,
                // `@tsv`, `@sh`) refuse one and print an array's values.
                let serializes = matches!(name, "json" | "text" | "base64" | "html" | "uri");
                Some(
                    if input == JqValue::Whole || (input.discloses() && serializes) {
                        JqValue::Whole
                    } else {
                        input.computed()
                    },
                )
            }
            JqToken::Punctuation(".") => {
                if self.peek() == Some(JqToken::StringOpen) {
                    Some(input.with(self.string(input)?).computed())
                } else if self.eat("[") {
                    self.subscript(input, input)
                } else {
                    Some(input)
                }
            }
            // `..` produces its input first, then everything inside it.
            JqToken::Punctuation("..") => Some(input),
            JqToken::Punctuation("(") => {
                let value = self.pipe(input)?;
                self.eat(")").then_some(value)
            }
            JqToken::Punctuation("[") => {
                if self.eat("]") {
                    return Some(JqValue::Clean);
                }
                let value = self.pipe(input)?;
                self.eat("]").then_some(value)
            }
            JqToken::Punctuation("{") => self.object(input),
            JqToken::Identifier(name) => self.call(name, input),
            _ => None,
        }
    }

    /// An object after its `{`: it carries every entry's value.
    fn object(&mut self, input: JqValue) -> Option<JqValue> {
        let mut value = JqValue::Clean;
        if self.eat("}") {
            return Some(value);
        }
        loop {
            // The key, which without a `:` is also the entry's value:
            // `{name}` is `.name` and `{$name}` is the variable.
            let key = self.peek()?;
            let shorthand = match key {
                JqToken::StringOpen => {
                    let key = self.string(input)?;
                    value = value.with(key);
                    input.with(key).computed()
                }
                JqToken::Punctuation("(") => {
                    self.index += 1;
                    let key = self.pipe(input)?;
                    if !self.eat(")") {
                        return None;
                    }
                    value = value.with(key.computed());
                    JqValue::Clean
                }
                JqToken::Identifier(name) => {
                    self.index += 1;
                    input.field(name)
                }
                JqToken::Variable(name) => {
                    self.index += 1;
                    if name == "ENV" {
                        JqValue::Environment
                    } else {
                        JqValue::Clean
                    }
                }
                JqToken::Number(_) => {
                    self.index += 1;
                    JqValue::Clean
                }
                _ => return None,
            };
            if self.eat(":") {
                let mut entry = self.operation(input)?;
                while self.eat("|") {
                    entry = self.operation(entry)?;
                }
                value = value.with(entry);
            } else {
                value = value.with(shorthand);
            }
            if self.eat("}") {
                return Some(value);
            }
            if !self.eat(",") {
                return None;
            }
        }
    }

    /// A named filter after its name, with any arguments.
    fn call(&mut self, name: &str, input: JqValue) -> Option<JqValue> {
        const KEYWORDS: [&str; 17] = [
            "if", "then", "elif", "else", "end", "as", "def", "reduce", "foreach", "try", "catch",
            "label", "import", "include", "and", "or", "__loc__",
        ];
        if name == "if" {
            return self.conditional(input);
        }
        if KEYWORDS.contains(&name) {
            return None;
        }
        if !self.eat("(") {
            return Some(match (name, input) {
                ("env", _) => JqValue::Environment,
                ("to_entries", JqValue::Environment) => JqValue::Entries,
                ("from_entries", JqValue::Entries) => JqValue::Environment,
                ("add", JqValue::Environment | JqValue::Whole) => JqValue::Whole,
                ("tojson" | "tostring", input) if input.discloses() => JqValue::Whole,
                ("debug" | "stderr" | "values" | "objects", input) => input,
                (_, input) => input.computed(),
            });
        }
        if matches!(name, "first" | "last" | "limit") {
            return self.selection(name, input);
        }
        // `map(f)` is `[.[] | f]` and `with_entries(f)` is `to_entries |
        // map(f) | from_entries`; any other filter's arguments run on its
        // own input.
        let argument_input = match (name, input) {
            ("map", input) => input.iterated(),
            ("with_entries", JqValue::Environment) => JqValue::Entries,
            (_, input) => input,
        };
        let mut arguments = self.pipe(argument_input)?;
        let mut count = 1;
        while self.eat(";") {
            arguments = arguments.with(self.pipe(argument_input)?);
            count += 1;
        }
        if !self.eat(")") {
            return None;
        }
        Some(match name {
            "map" if count == 1 => arguments,
            // Entries passed through whole rebuild the object.
            "with_entries" if count == 1 && arguments == JqValue::Entries => input,
            // Deleting named paths keeps every other value.
            "del" if count == 1 && arguments == JqValue::Touched => input,
            // Joining an array of every value keeps every value.
            "join" if input == JqValue::Whole => JqValue::Whole,
            _ => input.with(arguments).computed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jq_filter_environment_reads_are_whole_only_when_every_value_is_printed() {
        for filter in [
            "env",
            "$ENV",
            "[env]",
            "{e: env}",
            "{$ENV}",
            "env,.",
            "env?",
            "env//{}",
            ". + $ENV",
            "env[]",
            "env\n| tojson",
            "\"\\(env)\"",
            "env|@base64",
            "env|to_entries[]|\"\\(.key)=\\(.value)\"",
            "env|to_entries|map(\"\\(.key)=\\(.value)\")|.[]",
            "[env[]]|join(\",\")",
            "env | to_entries[] | [.key, .value] | @tsv",
            "env | to_entries[] | [.key, .value] | @sh",
            "env | del(.PATH)",
            "env | with_entries(.)",
            "env as $e | $e",
            "$ENV as $e | [$e] | tojson",
            "if . then env else 1 end",
            "if .a then 1 elif .b then $ENV end",
            "if true then env else 1 end",
            "if .a then 1 elif 0 then env else 2 end",
            "first(env)",
            "first(empty, env)",
            "first(env, 1)",
            "last(1, env)",
            "last(env, empty)",
            "limit(1; env)",
            "limit(2; 1, env)",
            "limit(.n; env)",
        ] {
            assert_eq!(
                jq_environment_read(filter),
                Some(JqEnvironmentRead::Whole),
                "{filter}"
            );
        }
        for filter in [
            "env.PATH",
            "$ENV.PATH",
            "env[\"PATH\"]",
            "env|.PATH",
            "env\n| keys",
            "env|length",
            "[env][0].HOME",
            "env|to_entries[]|.key",
            "env | to_entries[] | [.key] | @csv",
            "env | del(.[])",
            "env | with_entries(select(.key == \"PATH\"))",
            "\"\\(env.HOME)\"",
            "env as $e | $e.PATH",
            "env as [$a] | $a",
            "if env.CI then 1 else 2 end",
            "env == 1",
            &format!("{}env{}", "(".repeat(200), ")".repeat(200)),
        ] {
            assert_eq!(
                jq_environment_read(filter),
                Some(JqEnvironmentRead::Unresolved),
                "{filter}"
            );
        }
        for filter in [
            ".env",
            ".a.env",
            ".[\"env\"]",
            "{env: 1}",
            "{env}",
            "\"env $ENV\"",
            ". # env",
            "$env",
            "environment",
            ".items[] | select(.a == 1) | .name",
            ".a as $ENV | $ENV",
            "if .a then .b else .c end",
            "if false then env else 1 end",
            "if true then 1 else env end",
            "if null then env elif 1 then 2 else env end",
            "first(1, env)",
            "last(env, 1)",
            "limit(0; env)",
            "limit(1; \"a\", env)",
        ] {
            assert_eq!(jq_environment_read(filter), None, "{filter}");
        }
    }
}
