//! Whether a kubectl Go template provably fails on an object that has no
//! `items`, with missing keys an execution error.
//!
//! kubectl's Go-template printer writes the whole object after an execution
//! error, but rejects a template that does not parse and prints nothing. So
//! the failure counts only for a template this module proves Go's parser
//! accepts: it reads a subset of the action grammar in full and certifies
//! nothing outside it. Inside that subset it finds an `items` read that runs
//! whenever the template does: one outside every block, in an operand the
//! action always evaluates.

/// Go's builtin template functions and the two kubectl adds. Any other name
/// is a parse error.
const FUNCTIONS: [&str; 21] = [
    "and",
    "call",
    "html",
    "index",
    "slice",
    "js",
    "len",
    "not",
    "or",
    "print",
    "printf",
    "println",
    "urlquery",
    "eq",
    "ge",
    "gt",
    "le",
    "lt",
    "ne",
    "exists",
    "base64decode",
];

/// What an operand is, as far as `and` and `or` deciding to go on.
#[derive(Clone, Copy, PartialEq)]
enum Operand {
    True,
    False,
    Other,
}

#[derive(Clone, Copy, PartialEq)]
enum BlockKind {
    If,
    Range,
    With,
}

/// An open `if`, `range` or `with`.
struct Block {
    kind: BlockKind,
    /// The variables in scope before the block, restored at its `end`.
    outer: usize,
    /// The variables in scope after its header, restored at its `else`.
    header: usize,
    in_else: bool,
}

/// One action's text, read left to right. Every method returns `None` for
/// text outside the certified grammar.
struct Action<'a> {
    chars: Vec<char>,
    at: usize,
    /// The variables in scope, innermost last.
    variables: &'a [String],
    /// The action is outside every block, where `.` is the printed object
    /// and nothing skips it.
    top_level: bool,
    /// An operand that is always evaluated reads the object's `items`.
    reads_items: bool,
}

impl Action<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.at += 1;
        }
    }

    fn done(&mut self) -> bool {
        self.skip_space();
        self.at == self.chars.len()
    }

    /// Go ends an operand at white space, a pipe, a closing parenthesis or
    /// the action's end; anything else directly after it is a parse error.
    fn at_terminator(&self) -> bool {
        self.peek()
            .is_none_or(|c| c.is_whitespace() || matches!(c, '|' | ')'))
    }

    fn identifier(&mut self) -> Option<String> {
        let start = self.at;
        if !self
            .peek()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return None;
        }
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            self.at += 1;
        }
        Some(self.chars[start..self.at].iter().collect())
    }

    /// `.a.b` after a `.`, `$` or `$name`; empty when no field follows.
    fn fields(&mut self) -> Option<Vec<String>> {
        let mut fields = Vec::new();
        while self.peek() == Some('.') {
            self.at += 1;
            fields.push(self.identifier()?);
        }
        Some(fields)
    }

    fn operand(&mut self, evaluated: bool) -> Option<Operand> {
        let mut operand = Operand::Other;
        let reads_items = |fields: &[String]| fields.first().is_some_and(|field| field == "items");
        match self.peek()? {
            '(' => {
                self.at += 1;
                self.pipeline(evaluated)?;
                self.skip_space();
                if self.peek() != Some(')') {
                    return None;
                }
                self.at += 1;
            }
            '.' => {
                // A lone `.` is the value itself.
                if self
                    .chars
                    .get(self.at + 1)
                    .is_some_and(|c| !c.is_whitespace() && !matches!(c, '|' | ')'))
                {
                    let fields = self.fields()?;
                    self.reads_items |= evaluated && self.top_level && reads_items(&fields);
                } else {
                    self.at += 1;
                }
            }
            '$' => {
                self.at += 1;
                let name = self.identifier();
                let fields = self.fields()?;
                match name {
                    // `$` is the printed object everywhere.
                    None => self.reads_items |= evaluated && self.top_level && reads_items(&fields),
                    Some(name) if self.variables.contains(&name) => {}
                    Some(_) => return None,
                }
            }
            '"' => {
                self.at += 1;
                loop {
                    match self.peek()? {
                        '"' => break,
                        '\n' => return None,
                        '\\' => {
                            self.at += 1;
                            if !matches!(self.peek()?, 'n' | 't' | 'r' | '"' | '\\') {
                                return None;
                            }
                        }
                        _ => {}
                    }
                    self.at += 1;
                }
                self.at += 1;
            }
            '`' => {
                self.at += 1;
                while self.peek()? != '`' {
                    self.at += 1;
                }
                self.at += 1;
            }
            c if c.is_ascii_digit() || matches!(c, '-' | '+') => {
                if !c.is_ascii_digit() {
                    self.at += 1;
                }
                let start = self.at;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.at += 1;
                }
                // A leading zero starts an octal literal.
                if self.at == start || (self.chars[start] == '0' && self.at - start > 1) {
                    return None;
                }
            }
            _ => {
                operand = match self.identifier()?.as_str() {
                    "true" => Operand::True,
                    "false" => Operand::False,
                    "nil" => Operand::Other,
                    _ => return None,
                }
            }
        }
        self.at_terminator().then_some(operand)
    }

    /// One command: a function applied to its arguments, or a lone operand.
    /// `first` is the pipeline's first command; a later one receives the
    /// value piped into it and must be a function.
    fn command(&mut self, evaluated: bool, first: bool) -> Option<()> {
        self.skip_space();
        let start = self.at;
        let function = self
            .identifier()
            .filter(|name| FUNCTIONS.contains(&name.as_str()));
        let Some(function) = function else {
            self.at = start;
            // `nil` alone is not a command.
            if !first || self.chars[self.at..].starts_with(&['n', 'i', 'l']) {
                return None;
            }
            self.operand(evaluated)?;
            self.skip_space();
            return matches!(self.peek(), None | Some('|' | ')')).then_some(());
        };
        if !self.at_terminator() {
            return None;
        }
        // `and` and `or` evaluate their arguments in order and stop at the
        // first that decides the result; every other function takes them all.
        let mut evaluated = evaluated;
        loop {
            self.skip_space();
            if matches!(self.peek(), None | Some('|' | ')')) {
                return Some(());
            }
            let operand = self.operand(evaluated)?;
            evaluated &= match function.as_str() {
                "and" => operand == Operand::True,
                "or" => operand == Operand::False,
                _ => true,
            };
        }
    }

    /// Commands joined by `|`. Each runs before the next, which receives its
    /// value already evaluated.
    fn pipeline(&mut self, evaluated: bool) -> Option<()> {
        self.command(evaluated, true)?;
        while self.peek() == Some('|') {
            self.at += 1;
            self.command(evaluated, false)?;
        }
        Some(())
    }

    /// `$a :=`, or with `pair` also `$a, $b :=`, before a pipeline: the names
    /// declared. `Some(vec![])` when the action declares nothing.
    fn declaration(&mut self, pair: bool) -> Option<Vec<String>> {
        self.skip_space();
        let start = self.at;
        let mut names = Vec::new();
        loop {
            if self.peek() != Some('$') {
                break;
            }
            self.at += 1;
            let Some(name) = self.identifier() else {
                break;
            };
            names.push(name);
            self.skip_space();
            if self.chars[self.at..].starts_with(&[':', '=']) {
                self.at += 2;
                return Some(names);
            }
            if !(pair && names.len() == 1 && self.peek() == Some(',')) {
                break;
            }
            self.at += 1;
            self.skip_space();
        }
        // Two names are a declaration only.
        self.at = start;
        (names.len() < 2).then(Vec::new)
    }
}

/// Whether `text` is a template Go's parser accepts that, run over an object
/// without `items` with missing keys an error, always fails.
pub(super) fn fails_on_absent_items(text: &str) -> bool {
    certified_items_read(text).unwrap_or(false)
}

/// `None` when the template is outside the certified grammar.
fn certified_items_read(text: &str) -> Option<bool> {
    let mut variables: Vec<String> = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    let mut reads_items = false;
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let body = &rest[open + 2..];
        let (action, after) = action_text(body)?;
        rest = after;
        let Some(action) = action else {
            continue;
        };
        let mut action = Action {
            chars: action.chars().collect(),
            at: 0,
            variables: &variables,
            top_level: blocks.is_empty(),
            reads_items: false,
        };
        let start = action.at;
        let keyword = action.identifier();
        let keyword = keyword.filter(|_| action.at_terminator());
        let mut declared = Vec::new();
        let mut opened = None;
        match keyword.as_deref() {
            Some("end") => {
                let block = blocks.pop()?;
                if !action.done() {
                    return None;
                }
                variables.truncate(block.outer);
                continue;
            }
            Some("else") => {
                let block = blocks.last_mut()?;
                if block.in_else {
                    return None;
                }
                if action.done() {
                    block.in_else = true;
                    variables.truncate(block.header);
                    continue;
                }
                // `else if` chains another test on the same `end`.
                if block.kind != BlockKind::If
                    || action.identifier().as_deref() != Some("if")
                    || !action.at_terminator()
                {
                    return None;
                }
                action.variables = &variables[..block.header];
                action.pipeline(false)?;
            }
            Some(keyword @ ("if" | "range" | "with")) => {
                let kind = match keyword {
                    "if" => BlockKind::If,
                    "range" => BlockKind::Range,
                    _ => BlockKind::With,
                };
                declared = action.declaration(kind == BlockKind::Range)?;
                action.pipeline(true)?;
                opened = Some(kind);
            }
            Some("define" | "template" | "block" | "break" | "continue") => return None,
            _ => {
                action.at = start;
                declared = action.declaration(false)?;
                // `$a = …` assigns a variable already in scope.
                if declared.is_empty() && action.peek() == Some('$') {
                    action.at += 1;
                    let name = action.identifier();
                    action.skip_space();
                    if action.peek() == Some('=') {
                        if !name.is_some_and(|name| variables.contains(&name)) {
                            return None;
                        }
                        action.at += 1;
                    } else {
                        action.at = start;
                    }
                }
                action.pipeline(true)?;
            }
        }
        if !action.done() {
            return None;
        }
        reads_items |= action.reads_items;
        let outer = variables.len();
        variables.extend(declared);
        if let Some(kind) = opened {
            blocks.push(Block {
                kind,
                outer,
                header: variables.len(),
                in_else: false,
            });
        }
    }
    blocks.is_empty().then_some(reads_items)
}

/// Splits one action off the text after its `{{`: the action without its
/// trim markers, or `None` for a comment, and the text after its `}}`.
fn action_text(body: &str) -> Option<(Option<&str>, &str)> {
    // A trim marker is a `-` set off from the action by white space. A
    // comment starts right at the delimiter, or one character past the marker.
    let inner = match body.strip_prefix('-') {
        Some(inner) if inner.starts_with(char::is_whitespace) => {
            &inner[inner.chars().next().map_or(0, char::len_utf8)..]
        }
        _ => body,
    };
    if let Some(comment) = inner.strip_prefix("/*") {
        let after = &comment[comment.find("*/")? + 2..];
        let after = after.strip_prefix(" -").unwrap_or(after);
        return Some((None, after.strip_prefix("}}")?));
    }
    // The action ends at the first `}}` outside a quoted string.
    let mut quote = None;
    let mut chars = inner.char_indices();
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
            None if inner[index..].starts_with("}}") => {
                let action = &inner[..index];
                let action = match action.strip_suffix('-') {
                    Some(action) if action.ends_with(char::is_whitespace) => action,
                    _ => action,
                };
                return Some((Some(action), &inner[index + 2..]));
            }
            None => {}
        }
    }
    None
}
