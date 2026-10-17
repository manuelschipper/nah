//! What a `kubectl get` of Secrets prints of their data, read from its
//! output format: the whole object, or a JSONPath, custom-columns or Go
//! template. Only template actions select values; text around them and
//! quoted strings inside them are literal.
//!
//! kubectl's JSONPath and Go-template printers write the whole object after
//! an execution error, so a template is certified as names-only just when it
//! cannot fail: plain paths to fields every object has. Anything else that
//! does not provably print data is left unread. A failure is established
//! in two cases: a name that is not base64 through `base64decode`, and a
//! read of `items` from one object with missing keys an error.

use std::collections::BTreeMap;

use crate::word::Word;

use super::go_template_failure::fails_on_absent_items;

/// What a `get` of Secrets prints of their data.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum SecretOutput {
    /// The `data` or `stringData` values: the whole object, a template path
    /// into them, or a template that provably fails and so prints the object.
    Data,
    /// Names, types and other metadata only.
    Names,
    /// A format or template whose output Nah does not establish.
    Unread,
}

/// `names` are the Secrets the request names, and `missing_keys_fail` is
/// `--allow-missing-template-keys=false`, under which a path to an absent
/// field is an execution error. `one_object` says the request returns one
/// object, which kubectl prints as itself and not as a list.
pub(super) fn secret_output(
    output: Option<&Word>,
    template: Option<&Word>,
    names: &[Word],
    missing_keys_fail: bool,
    one_object: bool,
) -> SecretOutput {
    // One object has no `items`, so with missing keys failing a read of it
    // is an execution error.
    let items_absent = missing_keys_fail && one_object;
    let read = |text: &Word, format: Format| {
        let read = match format {
            Format::JsonPath => jsonpath(text.literal_prefix(), items_absent),
            Format::Columns => columns(text.literal_prefix()),
            // Whether a template parses is known only when all of it is read.
            Format::GoTemplate => match text.as_literal() {
                Some(text) if items_absent && fails_on_absent_items(text) => SecretOutput::Data,
                _ => go_template(text.literal_prefix(), names),
            },
        };
        match read {
            SecretOutput::Data => SecretOutput::Data,
            // An expansion leaves the rest of the template unread, and a
            // failed lookup prints the object.
            _ if text.as_literal().is_none() || missing_keys_fail => SecretOutput::Unread,
            read => read,
        }
    };
    let Some(output) = output else {
        // `--template` alone selects the go-template printer.
        return template.map_or(SecretOutput::Names, |template| {
            read(template, Format::GoTemplate)
        });
    };
    let text = output.literal_prefix();
    let (name, inline) = text
        .split_once('=')
        .map_or((text, None), |(name, inline)| (name, Some(inline)));
    let format = match name {
        "yaml" | "json" | "kyaml" if inline.is_none() && output.as_literal().is_some() => {
            return SecretOutput::Data;
        }
        "name" | "wide" if inline.is_none() && output.as_literal().is_some() => {
            return SecretOutput::Names;
        }
        "jsonpath" | "jsonpath-as-json" => Format::JsonPath,
        "custom-columns" => Format::Columns,
        "go-template" | "template" => Format::GoTemplate,
        _ => return SecretOutput::Unread,
    };
    match (inline, template) {
        (Some(_), _) => {
            let mut parts = output.parts.clone();
            if let Some(crate::word::WordPart::Literal(first)) = parts.first_mut() {
                *first = first[name.len() + 1..].to_string();
            }
            read(&Word::new(parts), format)
        }
        (None, Some(template)) if output.as_literal().is_some() => read(template, format),
        _ => SecretOutput::Unread,
    }
}

#[derive(Clone, Copy)]
enum Format {
    JsonPath,
    Columns,
    GoTemplate,
}

/// The verdict over a template's actions: any data read decides it, then any
/// unread action.
#[derive(Default)]
struct Reading {
    data: bool,
    unread: bool,
}

impl Reading {
    fn add(&mut self, read: SecretOutput) {
        match read {
            SecretOutput::Data => self.data = true,
            SecretOutput::Unread => self.unread = true,
            SecretOutput::Names => {}
        }
    }

    fn output(&self) -> SecretOutput {
        if self.data {
            SecretOutput::Data
        } else if self.unread {
            SecretOutput::Unread
        } else {
            SecretOutput::Names
        }
    }
}

/// The fields every object carries that are not Secret data.
const METADATA_FIELDS: [&str; 5] = ["metadata", "kind", "apiVersion", "type", "immutable"];

// ---- JSONPath ----

/// One step of a JSONPath expression.
#[derive(Debug, PartialEq)]
enum Step {
    /// `.name`, `['name']` or a union of names.
    Fields(Vec<String>),
    /// `.*` or `[*]`.
    Wildcard,
    /// An index, slice or filter: a selection that can fail or match nothing.
    Other,
    /// `..`: every value below, at any depth.
    Descent,
}

/// The steps of one expression, or `None` when it is not one Nah reads.
fn jsonpath_steps(path: &str) -> Option<Vec<Step>> {
    let chars: Vec<char> = path.trim().chars().collect();
    let field = |c: &char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-');
    let mut steps = Vec::new();
    let mut index = usize::from(matches!(chars.first(), Some('$' | '@')));
    while index < chars.len() {
        match chars[index] {
            '.' if chars.get(index + 1) == Some(&'.') => {
                steps.push(Step::Descent);
                index += 2;
                // The descent's field or wildcard, when one follows it directly.
                if chars.get(index).is_some_and(field) {
                    index -= 1;
                } else if chars.get(index) == Some(&'*') {
                    steps.push(Step::Wildcard);
                    index += 1;
                }
            }
            '.' if chars.get(index + 1) == Some(&'*') => {
                steps.push(Step::Wildcard);
                index += 2;
            }
            '.' => {
                let mut name = String::new();
                index += 1;
                // `\.` keeps a dot inside a field name.
                while index < chars.len() {
                    if chars[index] == '\\' && chars.get(index + 1) == Some(&'.') {
                        name.push('.');
                        index += 2;
                    } else if field(&chars[index]) {
                        name.push(chars[index]);
                        index += 1;
                    } else {
                        break;
                    }
                }
                // A lone `.` is the object itself.
                if !name.is_empty() {
                    steps.push(Step::Fields(vec![name]));
                } else if index < chars.len() {
                    return None;
                }
            }
            '[' => {
                let close = chars[index..].iter().position(|c| *c == ']')? + index;
                let inner: String = chars[index + 1..close].iter().collect();
                let inner = inner.trim();
                steps.push(if inner == "*" {
                    Step::Wildcard
                } else {
                    let names: Option<Vec<String>> = inner
                        .split(',')
                        .map(|name| {
                            let name = name.trim();
                            ['\'', '"']
                                .iter()
                                .find_map(|quote| name.strip_prefix(*quote)?.strip_suffix(*quote))
                                .filter(|name| !name.is_empty() && !name.contains(['\'', '"']))
                                .map(str::to_string)
                        })
                        .collect();
                    names.map_or(Step::Other, Step::Fields)
                });
                index = close + 1;
            }
            _ => return None,
        }
    }
    Some(steps)
}

/// What an expression over a Secret, or over a list of them, selects.
fn jsonpath_selection(steps: &[Step]) -> SecretOutput {
    // `indexed` is a listed object picked by an index, slice or filter. Such
    // a pick can fail and print the list, so it is never names only.
    let (object, indexed) = match steps {
        [Step::Fields(names), rest @ ..] if names[..] == ["items"] => match rest {
            [] => (rest, false),
            [Step::Wildcard, rest @ ..] => (rest, false),
            [Step::Other, rest @ ..] => (rest, true),
            [Step::Descent, ..] => return SecretOutput::Data,
            // A field of the list itself is none.
            [Step::Fields(_), ..] => return SecretOutput::Unread,
        },
        steps => (steps, false),
    };
    match object {
        // The whole object, every top-level value, or every value below it.
        [] | [Step::Wildcard | Step::Descent, ..] => SecretOutput::Data,
        [Step::Fields(names), rest @ ..] => {
            if names
                .iter()
                .any(|name| matches!(name.as_str(), "data" | "stringData"))
            {
                SecretOutput::Data
            } else if names
                .iter()
                .all(|name| METADATA_FIELDS.contains(&name.as_str()))
                && !indexed
                && rest
                    .iter()
                    .all(|step| matches!(step, Step::Fields(_) | Step::Wildcard))
            {
                SecretOutput::Names
            } else {
                SecretOutput::Unread
            }
        }
        [Step::Other, ..] => SecretOutput::Unread,
    }
}

/// The objects an open JSONPath `range` iterates.
#[derive(Clone, Copy, PartialEq)]
enum Ranged {
    /// Every listed object.
    Listed,
    /// The listed objects an index, slice or filter picks.
    Picked,
    /// Something Nah does not place.
    Unplaced,
}

/// A JSONPath template: text with `{…}` actions.
///
/// `items_absent` says a path into `items` fails, which prints the object.
fn jsonpath(text: &str, items_absent: bool) -> SecretOutput {
    let chars: Vec<char> = text.chars().collect();
    let mut reading = Reading::default();
    let mut ranges: Vec<Ranged> = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '{' {
            index += 1;
            continue;
        }
        // The action runs to its closing brace, past quoted strings.
        let mut end = index + 1;
        let mut quote = None;
        while let Some(&c) = chars.get(end) {
            match quote {
                Some(open) if c == '\\' => end += usize::from(open == '"'),
                Some(open) if c == open => quote = None,
                Some(_) => {}
                None if matches!(c, '"' | '\'') => quote = Some(c),
                None if c == '}' => break,
                None => {}
            }
            end += 1;
        }
        let action: String = chars[index + 1..end.min(chars.len())].iter().collect();
        let action = action.trim();
        index = end + 1;
        if action.starts_with(['"', '\'']) {
            continue;
        }
        if action == "end" {
            if ranges.pop().is_none() {
                reading.unread = true;
            }
            continue;
        }
        let (path, ranged) = match action.strip_prefix("range") {
            Some(path) if path.starts_with([' ', '\t']) => (path, true),
            _ => (action, false),
        };
        let read = match jsonpath_steps(path) {
            Some(steps)
                if items_absent
                    && ranges.is_empty()
                    && matches!(steps.first(), Some(Step::Fields(names)) if names[..] == ["items"]) =>
            {
                if ranged {
                    ranges.push(Ranged::Unplaced);
                }
                SecretOutput::Data
            }
            Some(steps) if !ranges.contains(&Ranged::Unplaced) => {
                if ranged {
                    let over = match &steps[..] {
                        [Step::Fields(names), rest @ ..] if names[..] == ["items"] => match rest {
                            [] | [Step::Wildcard] => Ranged::Listed,
                            [Step::Other] => Ranged::Picked,
                            _ => Ranged::Unplaced,
                        },
                        _ => Ranged::Unplaced,
                    };
                    ranges.push(over);
                    if over == Ranged::Listed {
                        SecretOutput::Names
                    } else {
                        SecretOutput::Unread
                    }
                } else {
                    match jsonpath_selection(&steps) {
                        // A pick can fail and print the list.
                        SecretOutput::Names if ranges.contains(&Ranged::Picked) => {
                            SecretOutput::Unread
                        }
                        read => read,
                    }
                }
            }
            _ => {
                if ranged {
                    ranges.push(Ranged::Unplaced);
                }
                SecretOutput::Unread
            }
        };
        reading.add(read);
    }
    reading.output()
}

/// A custom-columns spec: `HEADER:PATH` columns, each path a JSONPath
/// expression that may omit its braces and its leading dot.
fn columns(text: &str) -> SecretOutput {
    let mut reading = Reading::default();
    for column in text.split(',') {
        let Some((_, path)) = column.split_once(':') else {
            reading.unread = true;
            continue;
        };
        let path = path
            .strip_prefix('{')
            .and_then(|path| path.strip_suffix('}'))
            .unwrap_or(path);
        let path = if path.starts_with(['.', '[', '$', '@']) {
            path.to_string()
        } else {
            format!(".{path}")
        };
        reading.add(
            jsonpath_steps(&path).map_or(SecretOutput::Unread, |steps| jsonpath_selection(&steps)),
        );
    }
    reading.output()
}

// ---- Go templates ----

/// What a Go-template value is, as far as printing it goes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    /// A Secret, or the list the request returns.
    Object,
    /// The list's `items`.
    Items,
    /// The data map or a value in it.
    Data,
    /// A metadata field that is always present, so reading it cannot fail.
    Metadata,
    /// The object's `metadata.name`.
    Name,
    /// A literal, a count or a key name.
    Plain,
    /// Anything else: its value, or whether evaluating it fails, is not
    /// established.
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    /// `.a.b`; a lone `.` has no fields.
    Field(Vec<String>),
    /// `$name.a.b`; `$` alone is the root object.
    Variable(String, Vec<String>),
    Word(String),
    Literal,
    Pipe,
    Open,
    Close,
    Assign,
    Comma,
}

fn go_tokens(action: &str) -> Option<Vec<Token>> {
    let chars: Vec<char> = action.chars().collect();
    let word = |c: &char| c.is_ascii_alphanumeric() || *c == '_';
    let chain = |index: &mut usize| {
        let mut fields = Vec::new();
        while chars.get(*index) == Some(&'.') && chars.get(*index + 1).is_some_and(word) {
            let start = *index + 1;
            *index = start;
            while chars.get(*index).is_some_and(word) {
                *index += 1;
            }
            fields.push(chars[start..*index].iter().collect::<String>());
        }
        fields
    };
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        match c {
            c if c.is_whitespace() => index += 1,
            '"' | '`' | '\'' => {
                index += 1;
                loop {
                    match chars.get(index)? {
                        '\\' if c != '`' => index += 2,
                        close if *close == c => break,
                        _ => index += 1,
                    }
                }
                index += 1;
                tokens.push(Token::Literal);
            }
            '.' => {
                let fields = chain(&mut index);
                if fields.is_empty() {
                    index += 1;
                }
                tokens.push(Token::Field(fields));
            }
            '$' => {
                let start = index + 1;
                index = start;
                while chars.get(index).is_some_and(word) {
                    index += 1;
                }
                let name = chars[start..index].iter().collect();
                tokens.push(Token::Variable(name, chain(&mut index)));
            }
            '|' => {
                tokens.push(Token::Pipe);
                index += 1;
            }
            '(' => {
                tokens.push(Token::Open);
                index += 1;
            }
            ')' => {
                tokens.push(Token::Close);
                index += 1;
                // A field of a parenthesized value is not read.
                if chars.get(index) == Some(&'.') {
                    return None;
                }
            }
            ',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            ':' if chars.get(index + 1) == Some(&'=') => {
                tokens.push(Token::Assign);
                index += 2;
            }
            '=' => {
                tokens.push(Token::Assign);
                index += 1;
            }
            c if c.is_ascii_digit() || c == '-' || c == '+' => {
                while chars
                    .get(index)
                    .is_some_and(|c| word(c) || matches!(c, '.' | '-' | '+'))
                {
                    index += 1;
                }
                tokens.push(Token::Literal);
            }
            c if word(&c) => {
                let start = index;
                while chars.get(index).is_some_and(word) {
                    index += 1;
                }
                tokens.push(Token::Word(chars[start..index].iter().collect()));
            }
            _ => return None,
        }
    }
    Some(tokens)
}

/// A field chain read from a value of `base`.
fn go_field(base: Kind, fields: &[String]) -> Kind {
    let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
    match (base, &fields[..]) {
        (base, []) => base,
        (Kind::Data, _) => Kind::Data,
        (Kind::Object, ["items"]) => Kind::Items,
        (Kind::Object, ["data", ..]) => Kind::Data,
        (Kind::Object, ["metadata", "name"]) => Kind::Name,
        // A field of `metadata`, which every object has, prints `<no value>`
        // when absent; a field below an absent one is an execution error.
        (Kind::Object, ["metadata"] | ["metadata", _]) => Kind::Metadata,
        (Kind::Object, [field]) if METADATA_FIELDS.contains(field) => Kind::Metadata,
        _ => Kind::Unknown,
    }
}

struct GoTemplate<'a> {
    /// The Secrets the request names.
    names: &'a [Word],
    variables: BTreeMap<String, Kind>,
    /// What `.` is in each open `range`, `with` or `if`.
    dots: Vec<Kind>,
    reading: Reading,
}

impl GoTemplate<'_> {
    fn dot(&self) -> Kind {
        self.dots.last().copied().unwrap_or(Kind::Object)
    }

    /// Whether decoding every named Secret's name as base64 fails, which
    /// makes the printer write the whole object. A Kubernetes name is not
    /// padded, so one whose length is not a multiple of four, or that has a
    /// `-` or `.`, is not base64.
    fn names_fail_to_decode(&self) -> bool {
        !self.names.is_empty()
            && self.names.iter().all(|name| {
                name.as_literal().is_some_and(|name| {
                    !name.is_empty()
                        && (name.len() % 4 != 0
                            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric()))
                })
            })
    }

    fn operand(&self, tokens: &[Token], position: &mut usize) -> Kind {
        let token = tokens.get(*position);
        *position += 1;
        match token {
            Some(Token::Field(fields)) => go_field(self.dot(), fields),
            Some(Token::Variable(name, fields)) => {
                let base = if name.is_empty() {
                    Kind::Object
                } else {
                    self.variables.get(name).copied().unwrap_or(Kind::Unknown)
                };
                go_field(base, fields)
            }
            Some(Token::Literal) => Kind::Plain,
            Some(Token::Word(word)) if matches!(word.as_str(), "true" | "false") => Kind::Plain,
            Some(Token::Open) => {
                let kind = self.pipeline(tokens, position);
                if tokens.get(*position) == Some(&Token::Close) {
                    *position += 1;
                    kind
                } else {
                    Kind::Unknown
                }
            }
            _ => Kind::Unknown,
        }
    }

    /// One command of a pipeline: an operand, or a function applied to its
    /// arguments and the value piped into it.
    fn command(&self, tokens: &[Token], position: &mut usize, piped: Option<Kind>) -> Kind {
        let function = match tokens.get(*position) {
            Some(Token::Word(word)) if !matches!(word.as_str(), "true" | "false") => {
                *position += 1;
                Some(word.as_str())
            }
            _ => None,
        };
        let mut arguments = Vec::new();
        while !matches!(
            tokens.get(*position),
            None | Some(Token::Pipe | Token::Close)
        ) {
            arguments.push(self.operand(tokens, position));
        }
        arguments.extend(piped);
        let Some(function) = function else {
            return match arguments[..] {
                [kind] => kind,
                _ => Kind::Unknown,
            };
        };
        match (function, &arguments[..]) {
            // A count of the data map or of one value.
            ("len", [Kind::Data]) => Kind::Plain,
            ("index", [Kind::Data, ..]) => Kind::Data,
            ("base64decode", [Kind::Data]) => Kind::Data,
            // A failed decode is an execution error, which prints the object.
            ("base64decode", [Kind::Name]) if self.names_fail_to_decode() => Kind::Object,
            // These print their arguments and cannot fail.
            ("print" | "printf" | "println" | "html" | "js" | "urlquery", arguments) => {
                if arguments
                    .iter()
                    .any(|kind| matches!(kind, Kind::Data | Kind::Object | Kind::Items))
                {
                    Kind::Data
                } else if arguments.contains(&Kind::Unknown) {
                    Kind::Unknown
                } else {
                    Kind::Metadata
                }
            }
            _ => Kind::Unknown,
        }
    }

    fn pipeline(&self, tokens: &[Token], position: &mut usize) -> Kind {
        let mut kind = self.command(tokens, position, None);
        while tokens.get(*position) == Some(&Token::Pipe) {
            *position += 1;
            kind = self.command(tokens, position, Some(kind));
        }
        kind
    }

    /// A whole pipeline, or unknown when words are left over.
    fn value(&self, tokens: &[Token]) -> Kind {
        let mut position = 0;
        let kind = self.pipeline(tokens, &mut position);
        if position == tokens.len() && !tokens.is_empty() {
            kind
        } else {
            Kind::Unknown
        }
    }

    /// A control pipeline's value prints nothing, but evaluating it may fail.
    fn control(&mut self, tokens: &[Token]) -> Kind {
        let kind = self.value(tokens);
        if kind == Kind::Unknown {
            self.reading.unread = true;
        }
        kind
    }

    fn action(&mut self, action: &str) {
        let action = action.trim_start_matches('-').trim_end_matches('-').trim();
        if action.starts_with("/*") {
            return;
        }
        let Some(tokens) = go_tokens(action) else {
            self.reading.unread = true;
            return;
        };
        // `$a := …`, `$a, $b := …`: the variables a declaration binds.
        let declared = tokens
            .iter()
            .position(|token| *token == Token::Assign)
            .map(|assign| {
                let names: Vec<&String> = tokens[..assign]
                    .iter()
                    .filter_map(|token| match token {
                        Token::Variable(name, fields) if fields.is_empty() => Some(name),
                        _ => None,
                    })
                    .collect();
                (assign, names)
            });
        let keyword = match tokens.first() {
            Some(Token::Word(word)) => word.as_str(),
            _ => "",
        };
        match keyword {
            "end" => {
                if self.dots.pop().is_none() || tokens.len() != 1 {
                    self.reading.unread = true;
                }
            }
            "range" => {
                let start = declared.as_ref().map_or(1, |(assign, _)| assign + 1);
                let ranged = self.control(&tokens[start..]);
                // Ranging the listed objects visits each; ranging a map
                // gives its keys and values.
                let (key, element) = match ranged {
                    Kind::Items => (Kind::Plain, Kind::Object),
                    Kind::Data => (Kind::Plain, Kind::Data),
                    _ => (Kind::Unknown, Kind::Unknown),
                };
                match declared.as_ref().map(|(_, names)| &names[..]) {
                    Some([element_name]) => {
                        self.variables.insert((*element_name).clone(), element);
                    }
                    Some([key_name, element_name]) => {
                        self.variables.insert((*key_name).clone(), key);
                        self.variables.insert((*element_name).clone(), element);
                    }
                    Some(_) => self.reading.unread = true,
                    None => {}
                }
                self.dots.push(element);
            }
            "with" => {
                let start = declared.as_ref().map_or(1, |(assign, _)| assign + 1);
                let kind = self.control(&tokens[start..]);
                if let Some((_, names)) = &declared {
                    for name in names {
                        self.variables.insert((*name).clone(), kind);
                    }
                }
                self.dots.push(kind);
            }
            "if" => {
                self.control(&tokens[1..]);
                self.dots.push(self.dot());
            }
            "else" => match tokens.get(1) {
                None => {}
                Some(Token::Word(word)) if word == "if" => {
                    self.control(&tokens[2..]);
                }
                _ => self.reading.unread = true,
            },
            "define" | "template" | "block" | "break" | "continue" => self.reading.unread = true,
            _ => match declared {
                Some((assign, names)) => {
                    let kind = self.control(&tokens[assign + 1..]);
                    for name in names {
                        self.variables.insert(name.clone(), kind);
                    }
                }
                // A plain action prints its pipeline's value.
                None => match self.value(&tokens) {
                    Kind::Data | Kind::Object | Kind::Items => self.reading.data = true,
                    Kind::Unknown => self.reading.unread = true,
                    Kind::Metadata | Kind::Name | Kind::Plain => {}
                },
            },
        }
    }
}

/// A Go template: text with `{{…}}` actions.
fn go_template(text: &str, names: &[Word]) -> SecretOutput {
    let mut template = GoTemplate {
        names,
        variables: BTreeMap::new(),
        dots: Vec::new(),
        reading: Reading::default(),
    };
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let action = &rest[open + 2..];
        // The action ends at the first `}}` outside a quoted string.
        let mut quote = None;
        let mut close = None;
        let mut chars = action.char_indices();
        while let Some((index, c)) = chars.next() {
            match quote {
                Some('`') if c == '`' => quote = None,
                Some('`') => {}
                Some(_) if c == '\\' => {
                    chars.next();
                }
                Some(open) if c == open => quote = None,
                Some(_) => {}
                None if matches!(c, '"' | '`' | '\'') => quote = Some(c),
                None if action[index..].starts_with("}}") => {
                    close = Some(index);
                    break;
                }
                None => {}
            }
        }
        // An action cut short by an expansion is read as far as it goes.
        let close = close.unwrap_or(action.len());
        template.action(&action[..close]);
        rest = action.get(close + 2..).unwrap_or("");
    }
    template.reading.output()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One table for the three template languages: a path into data is a
    /// read however it is spelled, literal text and counts are not, and a
    /// template that can fail is never certified as names-only.
    #[test]
    fn templates_are_read_by_what_their_actions_print() {
        use SecretOutput::{Data, Names, Unread};
        let named = [Word::literal("app")];
        for (format, text, expected) in [
            ("jsonpath", "{.data}", Data),
            ("jsonpath", "{.data.password}", Data),
            ("jsonpath", r"{.data.tls\.crt}", Data),
            ("jsonpath", "{.data['password']}", Data),
            ("jsonpath", "{['data']['password']}", Data),
            ("jsonpath", r#"{["data"]}"#, Data),
            ("jsonpath", "{['metadata','data']}", Data),
            ("jsonpath", "{.items[*]['data']['password']}", Data),
            ("jsonpath", "{.items[*].data}", Data),
            ("jsonpath", "{range .items[*]}{.data.password}{end}", Data),
            ("jsonpath", "{@}", Data),
            ("jsonpath", "{.items[*]}", Data),
            ("jsonpath", "{.*}", Data),
            ("jsonpath", "{.metadata.name}", Names),
            ("jsonpath", "{['metadata']['name']}", Names),
            ("jsonpath", "{.items[*]['metadata']['name']}", Names),
            ("jsonpath", "{.items[*].metadata.name}", Names),
            (
                "jsonpath",
                r#"{range .items[*]}{.metadata.name}{"\n"}{end}"#,
                Names,
            ),
            ("jsonpath", "DATA:.data NAME:{.metadata.name}", Names),
            ("jsonpath", r#"{".data"}{.type}"#, Names),
            ("jsonpath", "{..password}", Data),
            ("jsonpath", "{..*}", Data),
            ("jsonpath", "{.items[*]..password}", Data),
            ("jsonpath", "{.items..data}", Data),
            ("jsonpath", "{.items[0].data}", Data),
            ("jsonpath", "{.items[0]}", Data),
            ("jsonpath", "{.items[0:2]['stringData']}", Data),
            ("jsonpath", r#"{.items[?(@.type=="Opaque")].data}"#, Data),
            ("jsonpath", "{range .items[0:2]}{.data.password}{end}", Data),
            (
                "jsonpath",
                "{range .items[0:2]}{.metadata.name}{end}",
                Unread,
            ),
            (
                "jsonpath",
                r#"{.items[?(@.type=="Opaque")].metadata.name}"#,
                Unread,
            ),
            ("jsonpath", "{.metadata..name}", Unread),
            ("jsonpath", "{.items.data}", Unread),
            ("jsonpath", "{[0].data}", Unread),
            ("jsonpath", "{.items[0].metadata.name}", Unread),
            ("jsonpath", "{.metadata.ownerReferences[0].name}", Unread),
            ("jsonpath", "{range .metadata.labels}{@}{end}", Unread),
            ("jsonpath", "{.spec}", Unread),
            ("custom-columns", "P:.data.password", Data),
            ("custom-columns", "P:data.password", Data),
            ("custom-columns", "NAME:.metadata.name,TYPE:.type", Names),
            ("custom-columns", "NAME:metadata.name", Names),
            ("go-template", "{{.data.password}}", Data),
            ("go-template", "{{.data.password | base64decode}}", Data),
            ("go-template", "{{ base64decode .data.password }}", Data),
            ("go-template", r#"{{index .data "password"}}"#, Data),
            ("go-template", r#"{{printf "%s" .data.password}}"#, Data),
            ("go-template", "{{.}}", Data),
            ("go-template", "{{range .items}}{{.data}}{{end}}", Data),
            (
                "go-template",
                "{{range $k, $v := .data}}{{$v}}{{end}}",
                Data,
            ),
            (
                "go-template",
                r#"{{range $k, $v := .data}}{{printf "%s=%s\n" $k ($v | base64decode)}}{{end}}"#,
                Data,
            ),
            ("go-template", "{{range .data}}{{.}}{{end}}", Data),
            // `app` is not base64, so the decode fails and the printer
            // writes the whole object.
            ("go-template", "{{.metadata.name | base64decode}}", Data),
            ("go-template", "{{base64decode .metadata.name}}", Data),
            ("go-template", "{{.metadata.name}}", Names),
            ("go-template", "{{.metadata.name}} {{.type}}", Names),
            (
                "go-template",
                r#"{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}"#,
                Names,
            ),
            (
                "go-template",
                r#"{{printf ".data"}}:{{.metadata.name}}"#,
                Names,
            ),
            ("go-template", "{{len .data}}", Names),
            (
                "go-template",
                r#"{{range $key, $value := .data}}{{$key}}{{"\n"}}{{end}}"#,
                Names,
            ),
            ("go-template", "text .data only", Names),
            ("go-template", "{{.metadata.labels.app}}", Unread),
            (
                "go-template",
                "{{.metadata.namespace | base64decode}}",
                Unread,
            ),
            ("go-template", "{{.metadata.name | upper}}", Unread),
            ("go-template", "{{len .items}}", Unread),
            ("go-template", "{{with .metadata}}{{.name}}{{end}}", Unread),
            ("go-template", r#"{{template "x" .}}"#, Unread),
        ] {
            let output = Word::literal(format!("{format}={text}"));
            assert_eq!(
                secret_output(Some(&output), None, &named, false, true),
                expected,
                "{format}={text}"
            );
        }
        // A name that is valid base64 decodes, and a list has no name.
        let decode = Word::literal("go-template={{.metadata.name | base64decode}}");
        assert_eq!(
            secret_output(Some(&decode), None, &[Word::literal("apps")], false, true),
            Unread
        );
        assert_eq!(
            secret_output(Some(&decode), None, &[], false, false),
            Unread
        );
        // With missing keys an error, no template is certified names-only.
        let name = Word::literal("jsonpath={.metadata.name}");
        assert_eq!(secret_output(Some(&name), None, &named, true, true), Unread);
        assert_eq!(secret_output(Some(&name), None, &named, false, true), Names);
        // One named Secret has no `items`: the path prints nothing, or fails
        // and prints the object when missing keys fail. A list has them.
        let listed = Word::literal("jsonpath={.items[0].metadata.name}");
        assert_eq!(
            secret_output(Some(&listed), None, &named, false, true),
            Unread
        );
        assert_eq!(secret_output(Some(&listed), None, &named, true, true), Data);
        assert_eq!(secret_output(Some(&listed), None, &[], true, false), Unread);
        // The Go-template twin: an action outside every block that reads
        // `items` fails, and the printer then writes the object. A template
        // kubectl rejects before running it, a read that may be skipped and
        // a lookup that returns no error establish nothing.
        for (text, expected) in [
            ("{{.items}}", Data),
            ("{{ $.items }}", Data),
            ("{{- len .items -}}", Data),
            (r#"{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}"#, Data),
            (
                "{{range $i, $s := .items}}{{$s.metadata.name}}{{end}}",
                Data,
            ),
            ("{{if .items}}list{{end}}", Data),
            ("{{.metadata.name}}{{with .items}}{{len .}}{{end}}", Data),
            // `and` and `or` always evaluate their first argument and the
            // value piped into them, and go on past one that decides nothing.
            ("{{and .items true}}", Data),
            ("{{if or .items false}}x{{end}}", Data),
            ("{{and true .items}}", Data),
            ("{{len .items | and false}}", Data),
            ("{{and false .items}}", Unread),
            ("{{or true .items}}", Unread),
            // Templates Go's parser rejects, after which nothing is printed.
            ("{{len .items}}{{else}}", Unread),
            ("{{len .items}}{{if}}{{end}}", Unread),
            ("{{len .items.}}", Unread),
            ("{{len(.items)}}", Unread),
            (
                r#"{{if true}}{{$v := "x"}}{{end}}{{len .items}}{{$v}}"#,
                Unread,
            ),
            ("{{len .items}}{{print 08}}", Unread),
            ("{{len .items}}{{nil}}", Unread),
            ("{{-  /* note */}}{{len .items}}", Unread),
            ("{{- /* note */ -}}{{len .items}}", Data),
            ("{{len .items | upper}}", Unread),
            ("{{len .items}}{{end}}", Unread),
            ("{{range .items}}{{.metadata.name}}", Unread),
            ("{{len .items}}{{$missing}}", Unread),
            ("{{-len .items}}", Unread),
            ("{{len .items", Unread),
            (r#"{{define "t"}}{{len .items}}{{end}}"#, Unread),
            ("{{if .metadata}}{{len .items}}{{end}}", Unread),
            ("{{or .metadata .items}}", Unread),
            (r#"{{index . "items"}}"#, Unread),
            (r#"{{"{{.items}}"}}"#, Unread),
            ("{{.metadata.items}}", Unread),
        ] {
            let output = Word::literal(format!("go-template={text}"));
            assert_eq!(
                secret_output(Some(&output), None, &named, true, true),
                expected,
                "{text}"
            );
        }
        // A list has `items`, and by default a missing key prints nothing.
        let counted = Word::literal("go-template={{if .items}}list{{end}}");
        for (missing_keys_fail, one_object) in [(true, false), (false, true)] {
            assert_ne!(
                secret_output(Some(&counted), None, &named, missing_keys_fail, one_object),
                Data
            );
        }
        // `--template` alone is a Go template; `-o jsonpath` reads it too.
        let template = Word::literal("{{.data.password}}");
        assert_eq!(
            secret_output(None, Some(&template), &named, false, true),
            Data
        );
        let bare = Word::literal("jsonpath");
        let path = Word::literal("{.data}");
        assert_eq!(
            secret_output(Some(&bare), Some(&path), &named, false, true),
            Data
        );
        for (format, expected) in [("yaml", Data), ("name", Names), ("jsonpath-file=t", Unread)] {
            assert_eq!(
                secret_output(Some(&Word::literal(format)), None, &named, false, true),
                expected
            );
        }
    }
}
