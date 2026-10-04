//! Conservative pre-parse nesting guards for the frontends whose third-party
//! or hand-written parsers recurse once per nesting level.
//!
//! oxc (JS/TS) and lib-ruby-parser build their ASTs by recursive descent, and
//! the PowerShell script-block reader recurses once per grouping parenthesis.
//! A source nested past the native stack overflows and aborts the whole hook,
//! which skips every guard — worse than any boundary. These scans bound an
//! upper estimate of parse-recursion depth from the raw bytes before the
//! parser runs. Above [`super::frontend::MAX_WALK_DEPTH`] the caller emits the
//! partial-analysis boundary the walkers already raise at that depth, so the
//! segment reads as partial coverage and the rest of the command is still
//! analyzed. The estimate only ever over-counts: unusually deep but legitimate
//! source may hit the boundary, but no crashing source slips through.

use super::frontend::MAX_WALK_DEPTH;

/// Whether JS/TS source nests deeper than the walk limit anywhere.
///
/// The scan bounds the depth of the tree the parser builds. Every open
/// bracket (`([{`, and a template literal's `${`) is a frame holding two
/// runs: chained infix, prefix and postfix operators along one expression
/// spine, and nested control-flow keywords along one statement spine. The
/// depth at any byte is the open brackets plus the runs of every open frame,
/// so a chain keeps counting across the brackets it closes (`c ? (1) : c ?
/// (1) : ...`, `f(1)(1)...`, `if (a) {} else if (b) {} ...`). A run ends only
/// where the spine does: at `;`, at `,`, at a line break or closing `}`
/// followed by the start of a new statement. A flat list (`[1, 2, ...]`) or a
/// sequence of short statements therefore stays shallow.
///
/// Comments, strings, template text and regular expressions are skipped so
/// their bytes cannot close a live bracket. A `/` is read as a regular
/// expression wherever an operand may start, which this scan can only tell
/// from the previous token.
pub(crate) fn js_nesting_exceeds(source: &str) -> bool {
    scan_nesting(source.as_bytes(), Syntax::JsTs)
}

/// Whether Ruby source nests deeper than the walk limit anywhere.
///
/// lib-ruby-parser descends recursively and even dropping its `Box<Node>`
/// recurses once per level, so a source nested past the native stack overflows
/// the hook. Its lexer cannot be driven standalone without the parser's own
/// setup, so this is the same conservative byte scan as JS, tuned for Ruby's
/// operators and block keywords. It never skips strings or comments — Ruby
/// interpolation (`#{...}`) is live code whose brackets must be counted — so it
/// over-counts brackets inside string and comment text, which only ever trips
/// the boundary early.
pub(crate) fn ruby_nesting_exceeds(source: &str) -> bool {
    scan_nesting(source.as_bytes(), Syntax::Ruby)
}

#[derive(Clone, Copy, PartialEq)]
enum Syntax {
    JsTs,
    Ruby,
}

/// What the previous token was, as far as the next one needs to know.
#[derive(Clone, Copy, PartialEq)]
enum Prev {
    /// A complete operand: a name, a literal, or a closed `)` or `]`.
    Operand,
    /// An operator, separator or open bracket: an operand comes next.
    Operator,
    /// `if`, `while`, `for` or `with`, whose `(...)` is a statement head.
    HeadKeyword,
    /// The `)` closing a statement head, or a `}`: a statement may start.
    StatementStart,
}

impl Prev {
    fn ends_expression(self) -> bool {
        matches!(self, Self::Operand | Self::StatementStart)
    }
}

/// The runs accumulated directly inside one open bracket.
#[derive(Default)]
struct Frame {
    op_run: u32,
    stmt_run: u32,
    /// The statement run the last `;` or `}` ended, which a following `else`,
    /// `catch` or `finally` continues.
    ended_stmt_run: u32,
    /// `<` not yet matched by `>` in the operator run. While one is open a
    /// `,` may separate TypeScript type arguments, which nest (`A<B, A<B,
    /// ...>>`), so it does not end the run.
    open_angles: u32,
    /// The bracket is the `(` of an `if`, `while`, `for` or `with` head.
    statement_head: bool,
    /// The bracket is a template literal's `${`.
    template: bool,
}

struct Nesting {
    /// The open frames, innermost last; the first is the source itself.
    frames: Vec<Frame>,
    /// Depth held by every frame but the innermost: its runs, plus one for
    /// the bracket it opened.
    enclosing: u32,
}

impl Nesting {
    fn top(&mut self) -> &mut Frame {
        self.frames.last_mut().expect("the source frame stays open")
    }

    fn exceeds(&self) -> bool {
        let top = self.frames.last().expect("the source frame stays open");
        self.enclosing + top.op_run + top.stmt_run > MAX_WALK_DEPTH
    }

    fn open(&mut self, frame: Frame) {
        let top = self.top();
        self.enclosing += top.op_run + top.stmt_run + 1;
        self.frames.push(frame);
    }

    /// Close the innermost bracket; an unmatched closer closes nothing.
    fn close(&mut self) -> Option<Frame> {
        if self.frames.len() == 1 {
            return None;
        }
        let closed = self.frames.pop();
        let top = self.top();
        self.enclosing -= top.op_run + top.stmt_run + 1;
        closed
    }

    fn end_op_run(&mut self) {
        let top = self.top();
        top.op_run = 0;
        top.open_angles = 0;
    }

    /// End the statement run, keeping it for an `else` that continues it.
    fn end_stmt_run(&mut self) {
        let top = self.top();
        if top.stmt_run > 0 {
            top.ended_stmt_run = top.stmt_run;
        }
        top.stmt_run = 0;
    }
}

/// The index just past a template literal's text that starts at `i`, and
/// whether the text stopped at a `${` rather than the closing backtick.
fn skip_template_text(bytes: &[u8], mut i: usize) -> (usize, bool) {
    while i < bytes.len() {
        match bytes[i] {
            b'`' => return (i + 1, false),
            b'$' if bytes.get(i + 1) == Some(&b'{') => return (i + 2, true),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    (i, false)
}

/// The index just past the regular expression literal whose `/` is at `i`,
/// or None when the line ends before the literal does.
fn skip_regex(bytes: &[u8], mut i: usize) -> Option<usize> {
    let mut in_class = false;
    i += 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' | b'\r' => return None,
            b'\\' => i += 1,
            b'[' => in_class = true,
            b']' => in_class = false,
            b'/' if !in_class => return Some(i + 1),
            _ => {}
        }
        i += 1;
    }
    None
}

fn scan_nesting(bytes: &[u8], syntax: Syntax) -> bool {
    let js = syntax == Syntax::JsTs;
    let mut nesting = Nesting {
        frames: vec![Frame::default()],
        enclosing: 0,
    };
    let mut i = 0;
    let mut prev = Prev::Operator;
    // A line break or `}` came after a complete expression. The run it may
    // have ended continues if the next token is an operator or bracket
    // (`a\n? b\n: c`, `x\n.y()`), and ends if that token starts an operand.
    let mut statement_break = false;

    macro_rules! bump_op {
        () => {{
            nesting.top().op_run += 1;
            if nesting.exceeds() {
                return true;
            }
        }};
    }
    macro_rules! start_operand {
        () => {{
            if statement_break {
                nesting.end_op_run();
            }
        }};
    }

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\n' || c == b'\r' {
            statement_break |= prev.ends_expression();
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'/' if js && bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if js && bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i += 2;
                continue;
            }
            // JS string literals cannot span brackets that matter, so skipping
            // them avoids counting bracket characters in string data. Ruby
            // strings are not skipped: `#{...}` interpolation nests live code.
            b'\'' | b'"' if js => {
                start_operand!();
                let quote = c;
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
                prev = Prev::Operand;
            }
            b'`' if js => {
                // A template after an operand is tagged, one more link of a
                // call chain.
                if prev == Prev::Operand {
                    bump_op!();
                }
                let (next, interpolates) = skip_template_text(bytes, i + 1);
                i = next;
                if interpolates {
                    nesting.open(Frame {
                        template: true,
                        ..Frame::default()
                    });
                    if nesting.exceeds() {
                        return true;
                    }
                    prev = Prev::Operator;
                } else {
                    prev = Prev::Operand;
                }
            }
            b'(' | b'[' | b'{' => {
                if c == b'{' {
                    start_operand!();
                } else if prev == Prev::Operand {
                    // A call or index applied to what precedes it: one more
                    // link of the chain `f(1)(2)[3]`.
                    bump_op!();
                }
                nesting.open(Frame {
                    statement_head: c == b'(' && prev == Prev::HeadKeyword,
                    ..Frame::default()
                });
                if nesting.exceeds() {
                    return true;
                }
                prev = Prev::Operator;
                i += 1;
            }
            b')' | b']' | b'}' => {
                let closed = nesting.close();
                i += 1;
                if closed.as_ref().is_some_and(|frame| frame.template) {
                    // The interpolation is over; the literal's text resumes.
                    let (next, interpolates) = skip_template_text(bytes, i);
                    i = next;
                    if interpolates {
                        nesting.open(Frame {
                            template: true,
                            ..Frame::default()
                        });
                        prev = Prev::Operator;
                    } else {
                        prev = Prev::Operand;
                    }
                    statement_break = false;
                    continue;
                }
                if c == b'}' && js {
                    nesting.end_stmt_run();
                    prev = Prev::StatementStart;
                    statement_break = true;
                    continue;
                }
                prev = if closed.is_some_and(|frame| frame.statement_head) {
                    Prev::StatementStart
                } else {
                    Prev::Operand
                };
            }
            b';' => {
                nesting.end_op_run();
                // In JS `;` terminates a statement; in Ruby it only separates
                // statements that may still sit inside an open `if`/`begin`
                // block closed by `end`, so it must not drop the block spine.
                if js {
                    nesting.end_stmt_run();
                }
                prev = Prev::Operator;
                i += 1;
            }
            b',' => {
                if nesting.top().open_angles == 0 {
                    nesting.end_op_run();
                }
                prev = Prev::Operator;
                i += 1;
            }
            b'/' if js && prev != Prev::Operand && skip_regex(bytes, i).is_some() => {
                start_operand!();
                i = skip_regex(bytes, i).unwrap_or(i + 1);
                prev = Prev::Operand;
            }
            b'!' | b'~' | b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'<' | b'>' | b'&' | b'|'
            | b'^' | b'?' | b':' | b'.' => {
                bump_op!();
                let next = bytes.get(i + 1).copied();
                let doubled = next == Some(c) || (i > 0 && bytes[i - 1] == c);
                let top = nesting.top();
                if c == b'<' && !doubled && next != Some(b'=') {
                    top.open_angles += 1;
                } else if c == b'>' {
                    top.open_angles = top.open_angles.saturating_sub(1);
                }
                // `x++`, `x--` and TypeScript's `x!` leave the operand
                // complete, so a `/` after them still divides.
                let postfix = match c {
                    b'+' | b'-' if next == Some(c) => {
                        bump_op!();
                        i += 1;
                        true
                    }
                    b'!' => next != Some(b'='),
                    _ => false,
                };
                if !(js && postfix && prev == Prev::Operand) {
                    prev = Prev::Operator;
                }
                i += 1;
            }
            _ if c == b'_' || c == b'$' || c == b'@' || c.is_ascii_alphabetic() || c >= 0x80 => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i] == b'_'
                        || bytes[i] == b'$'
                        || bytes[i] == b'@'
                        || bytes[i].is_ascii_alphanumeric()
                        || bytes[i] >= 0x80)
                {
                    i += 1;
                }
                let word = &bytes[start..i];
                let is_stmt_keyword = match syntax {
                    Syntax::JsTs => matches!(
                        word,
                        b"if" | b"for" | b"while" | b"do" | b"switch" | b"try" | b"with" | b"case"
                    ),
                    Syntax::Ruby => matches!(
                        word,
                        b"if"
                            | b"unless"
                            | b"while"
                            | b"until"
                            | b"for"
                            | b"begin"
                            | b"case"
                            | b"do"
                            | b"elsif"
                            | b"when"
                            | b"and"
                            | b"or"
                            | b"not"
                    ),
                };
                let is_op_keyword = match syntax {
                    Syntax::JsTs => matches!(
                        word,
                        b"new"
                            | b"typeof"
                            | b"void"
                            | b"delete"
                            | b"await"
                            | b"yield"
                            | b"instanceof"
                            | b"in"
                            | b"of"
                            | b"as"
                            | b"satisfies"
                            | b"keyof"
                            | b"class"
                            | b"extends"
                    ),
                    Syntax::Ruby => false,
                };
                if is_op_keyword {
                    bump_op!();
                    prev = Prev::Operator;
                } else {
                    start_operand!();
                    if is_stmt_keyword {
                        nesting.top().stmt_run += 1;
                        if nesting.exceeds() {
                            return true;
                        }
                        prev = if js && matches!(word, b"if" | b"for" | b"while" | b"with") {
                            Prev::HeadKeyword
                        } else {
                            Prev::Operator
                        };
                    } else if js && matches!(word, b"return" | b"throw") {
                        prev = Prev::Operator;
                    } else if js && matches!(word, b"else" | b"catch" | b"finally") {
                        // The clause belongs to the statement the last `;` or
                        // `}` ended, so what follows nests under that spine.
                        let top = nesting.top();
                        top.stmt_run = top.stmt_run.max(top.ended_stmt_run);
                        prev = Prev::Operator;
                    } else if !js && word == b"end" {
                        // `end` closes a block, so a following construct starts a
                        // fresh spine rather than nesting under this one.
                        nesting.top().stmt_run = 0;
                        prev = Prev::Operand;
                    } else {
                        prev = Prev::Operand;
                    }
                }
            }
            _ => {
                // A digit or any other expression byte ends a spine element.
                start_operand!();
                prev = Prev::Operand;
                i += 1;
            }
        }
        statement_break = false;
    }
    false
}
