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

use std::collections::HashSet;

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
/// where the spine does: at `;`, at `,` outside a type argument list, and at
/// a line break or a block's `}` unless an operator follows. A flat list
/// (`[1, 2, ...]`) or a sequence of short statements therefore stays shallow.
///
/// Comments, strings, template text and regular expressions are skipped so
/// their bytes cannot close a live bracket. A `/` is read as a regular
/// expression wherever an operand may start, which this scan can only tell
/// from the previous token and from whether the `}` before it closed a block
/// or an expression.
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
enum PrevToken {
    /// A complete operand: a name, a literal, or a closed `)` or `]`.
    Operand,
    /// An operator, separator or open bracket inside an expression: an
    /// operand comes next, and a `{` there opens an object literal.
    Operator,
    /// `=>`: an operand comes next, but a `{` there opens the arrow's body.
    Arrow,
    /// `if`, `while`, `for` or `with`, whose `(...)` is a statement head.
    HeadKeyword,
    /// A statement may start: the source begins, or a `;`, a block's `{` or
    /// `}`, a label's `:` or a statement head's `)` came last.
    StatementStart,
}

impl PrevToken {
    /// Whether a line break here may end the expression: nothing before it
    /// still waits for an operand.
    fn ends_expression(self) -> bool {
        matches!(self, Self::Operand | Self::StatementStart)
    }

    /// Whether a `function` or `class` here is an expression, not a
    /// declaration.
    fn expects_operand(self) -> bool {
        matches!(self, Self::Operator | Self::Arrow)
    }
}

/// The runs accumulated directly inside one open bracket.
#[derive(Default)]
struct BracketFrame {
    op_run: u32,
    stmt_run: u32,
    /// Links of the operator run that are left-associative operators starting
    /// a line (`a\n+ b\n+ c`, `x\n.y()\n.z()`). The parser loops over those,
    /// so only the walkers recurse on them and a link costs half a level:
    /// a chain written one operand per line may run to twice the walk limit.
    line_links: u32,
    /// The statement run the last `;` or `}` ended, which a following `else`,
    /// `catch` or `finally` continues.
    ended_stmt_run: u32,
    /// Open TypeScript type argument lists in the operator run. Inside one a
    /// `,` separates arguments that nest (`A<B, A<B, ...>>`), so it does not
    /// end the run.
    open_angles: u32,
    /// The `<` of this frame that a later `>` closes, found by looking ahead
    /// as far as `angles_scanned_to`. A comparison's `<` has no closer and so
    /// opens no list.
    closed_angles: HashSet<usize>,
    angles_scanned_to: usize,
    /// `?` of the operator run still waiting for their `:`. A `:` beyond them
    /// ends a label or a `case`, and a statement follows it.
    open_ternaries: u32,
    /// The frame holds statements: the source itself, or a block.
    block: bool,
    /// The bracket is the `{` of an object literal or of a function or class
    /// expression, so its `}` completes an operand.
    expression: bool,
    /// A `function` or `class` expression started here; its body is the next
    /// `{` this frame opens.
    expression_body_pending: bool,
    /// The bracket is the `(` of an `if`, `while`, `for` or `with` head.
    statement_head: bool,
    /// The bracket is a template literal's `${`.
    template: bool,
}

impl BracketFrame {
    /// The parse depth this frame's own runs add, not counting its bracket.
    fn depth(&self) -> u32 {
        self.op_run + self.stmt_run + self.line_links / 2
    }
}

/// The nesting depth estimate at the byte the scan has reached: the stack
/// of open bracket frames and the depth the outer ones hold.
struct Nesting {
    /// The open frames, innermost last; the first is the source itself.
    frames: Vec<BracketFrame>,
    /// Depth held by every frame but the innermost: its runs, plus one for
    /// the bracket it opened.
    enclosing: u32,
}

impl Nesting {
    /// The innermost open frame.
    fn top(&mut self) -> &mut BracketFrame {
        self.frames.last_mut().expect("the source frame stays open")
    }

    /// Whether the estimate here is past the walk limit, `MAX_WALK_DEPTH`.
    fn exceeds(&self) -> bool {
        let top = self.frames.last().expect("the source frame stays open");
        self.enclosing + top.depth() > MAX_WALK_DEPTH
    }

    /// Open a bracket: the frame it leaves keeps its runs in the estimate.
    fn open(&mut self, frame: BracketFrame) {
        let top = self.top();
        self.enclosing += top.depth() + 1;
        self.frames.push(frame);
    }

    /// Close the innermost bracket; an unmatched closer closes nothing.
    fn close(&mut self) -> Option<BracketFrame> {
        if self.frames.len() == 1 {
            return None;
        }
        let closed = self.frames.pop();
        let top = self.top();
        self.enclosing -= top.depth() + 1;
        closed
    }

    /// End the operator run where the expression spine ends.
    fn end_op_run(&mut self) {
        let top = self.top();
        top.op_run = 0;
        top.line_links = 0;
        top.open_angles = 0;
        top.open_ternaries = 0;
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

/// Record which `<` from `from` on, directly inside the current bracket and
/// before the statement ends, a later `>` closes.
fn scan_angles(bytes: &[u8], from: usize, frame: &mut BracketFrame) {
    let mut open = Vec::new();
    let mut depth = 0u32;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            quote @ (b'\'' | b'"') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => break,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => break,
            b'<' if depth == 0 => open.push(i),
            // The `>` of `=>` closes nothing.
            b'>' if depth == 0 && bytes[i - 1] != b'=' => {
                if let Some(opened) = open.pop() {
                    frame.closed_angles.insert(opened);
                }
            }
            _ => {}
        }
        i += 1;
    }
    frame.angles_scanned_to = i;
}

/// Whether the operator at `i`, first on its line, nests the lines before
/// it and after it under each other: a conditional, an arrow, `**` or an
/// assignment. Every other operator there is left-associative.
fn nests_across_line_break(bytes: &[u8], i: usize) -> bool {
    let at = |offset: usize| bytes.get(i + offset).copied();
    match bytes[i] {
        b':' => true,
        b'?' => match at(1) {
            Some(b'?') => at(2) == Some(b'='),
            Some(b'.') => at(2).is_some_and(|byte| byte.is_ascii_digit()),
            _ => true,
        },
        b'=' => at(1) != Some(b'='),
        b'*' => matches!(at(1), Some(b'*' | b'=')),
        c @ (b'&' | b'|') => at(1) == Some(b'=') || (at(1) == Some(c) && at(2) == Some(b'=')),
        b'+' | b'-' | b'/' | b'%' | b'^' => at(1) == Some(b'='),
        b'<' => at(1) == Some(b'<') && at(2) == Some(b'='),
        b'>' => {
            let run = bytes[i..].iter().take_while(|byte| **byte == b'>').count();
            run > 1 && at(run) == Some(b'=')
        }
        _ => false,
    }
}

fn scan_nesting(bytes: &[u8], syntax: Syntax) -> bool {
    let js = syntax == Syntax::JsTs;
    let mut nesting = Nesting {
        frames: vec![BracketFrame {
            block: true,
            ..BracketFrame::default()
        }],
        enclosing: 0,
    };
    let mut i = 0;
    let mut prev = PrevToken::StatementStart;
    // A line break or a block's `}` came after a complete expression in
    // JS. The run it may have ended continues only if the next token is an
    // operator that nests across the break (`a\n? b\n: c`).
    let mut statement_break = false;

    macro_rules! bump_op {
        () => {{
            nesting.top().op_run += 1;
            if nesting.exceeds() {
                return true;
            }
        }};
    }
    // One more link of the operator run. A left-associative link that starts
    // a line is the cheaper `line_links` kind.
    macro_rules! bump_link {
        ($nests:expr) => {{
            if statement_break && !$nests && prev == PrevToken::StatementStart {
                // A prefix operator opening a new statement.
                nesting.end_op_run();
                bump_op!();
            } else if statement_break && !$nests {
                nesting.top().line_links += 1;
                if nesting.exceeds() {
                    return true;
                }
            } else {
                bump_op!();
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
            if prev.ends_expression() {
                // A Ruby operator cannot start a line, so the break is final.
                if js {
                    statement_break = true;
                } else {
                    nesting.end_op_run();
                }
            }
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
                prev = PrevToken::Operand;
            }
            b'`' if js => {
                // A template after an operand is tagged, one more link of a
                // call chain.
                if prev == PrevToken::Operand {
                    bump_link!(false);
                } else {
                    start_operand!();
                }
                let (next, interpolates) = skip_template_text(bytes, i + 1);
                i = next;
                if interpolates {
                    nesting.open(BracketFrame {
                        template: true,
                        ..BracketFrame::default()
                    });
                    if nesting.exceeds() {
                        return true;
                    }
                    prev = PrevToken::Operator;
                } else {
                    prev = PrevToken::Operand;
                }
            }
            b'(' | b'[' | b'{' => {
                let mut frame = BracketFrame {
                    statement_head: c == b'(' && prev == PrevToken::HeadKeyword,
                    ..BracketFrame::default()
                };
                if c != b'{' && prev == PrevToken::Operand {
                    // A call or index applied to what precedes it: one more
                    // link of the chain `f(1)(2)[3]`.
                    bump_link!(false);
                } else {
                    start_operand!();
                }
                if c == b'{' && js {
                    let pending = std::mem::take(&mut nesting.top().expression_body_pending);
                    frame.expression = pending || prev == PrevToken::Operator;
                    frame.block = !frame.expression;
                }
                prev = if frame.block {
                    PrevToken::StatementStart
                } else {
                    PrevToken::Operator
                };
                nesting.open(frame);
                if nesting.exceeds() {
                    return true;
                }
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
                        nesting.open(BracketFrame {
                            template: true,
                            ..BracketFrame::default()
                        });
                        prev = PrevToken::Operator;
                    } else {
                        prev = PrevToken::Operand;
                    }
                    statement_break = false;
                    continue;
                }
                if c == b'}' && js && !closed.as_ref().is_some_and(|frame| frame.expression) {
                    nesting.end_stmt_run();
                    prev = PrevToken::StatementStart;
                    statement_break = true;
                    continue;
                }
                prev = if closed.is_some_and(|frame| frame.statement_head) {
                    PrevToken::StatementStart
                } else {
                    PrevToken::Operand
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
                prev = PrevToken::StatementStart;
                i += 1;
            }
            b',' => {
                if nesting.top().open_angles == 0 {
                    nesting.end_op_run();
                }
                prev = PrevToken::Operator;
                i += 1;
            }
            b'/' if js && prev != PrevToken::Operand && skip_regex(bytes, i).is_some() => {
                start_operand!();
                i = skip_regex(bytes, i).unwrap_or(i + 1);
                prev = PrevToken::Operand;
            }
            b'!' | b'~' | b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'<' | b'>' | b'&' | b'|'
            | b'^' | b'?' | b':' | b'.' => {
                bump_link!(nests_across_line_break(bytes, i));
                let next = bytes.get(i + 1).copied();
                let doubled = next == Some(c) || (i > 0 && bytes[i - 1] == c);
                let top = nesting.top();
                let mut ends_label = false;
                match c {
                    b'<' if js && !doubled && next != Some(b'=') => {
                        if i >= top.angles_scanned_to {
                            scan_angles(bytes, i, top);
                        }
                        if top.closed_angles.contains(&i) {
                            top.open_angles += 1;
                        }
                    }
                    b'>' => top.open_angles = top.open_angles.saturating_sub(1),
                    b'?' if !matches!(next, Some(b'?' | b'.' | b':')) && !doubled => {
                        top.open_ternaries += 1;
                    }
                    b':' if top.open_ternaries > 0 => top.open_ternaries -= 1,
                    b':' => ends_label = js && top.block,
                    _ => {}
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
                if ends_label {
                    prev = PrevToken::StatementStart;
                } else if c == b'>' && i > 0 && bytes[i - 1] == b'=' {
                    prev = PrevToken::Arrow;
                } else if !(js && postfix && prev == PrevToken::Operand) {
                    prev = PrevToken::Operator;
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
                    // `extends` continues the class it follows; every other
                    // keyword operator is left-associative or starts an
                    // operand, and a `class` that is not an operand declares.
                    let expression = prev.expects_operand();
                    if matches!(word, b"in" | b"instanceof" | b"of" | b"as" | b"satisfies") {
                        bump_link!(false);
                    } else {
                        if word != b"extends" && !(word == b"class" && expression) {
                            start_operand!();
                        }
                        bump_op!();
                    }
                    if word == b"class" && expression {
                        nesting.top().expression_body_pending = true;
                    }
                    // `for await (...)` is still a statement head.
                    if !(word == b"await" && prev == PrevToken::HeadKeyword) {
                        prev = PrevToken::Operator;
                    }
                } else if js && word == b"async" {
                    // `async` leaves what follows where it was: a function
                    // expression after `=`, a declaration after a statement.
                    start_operand!();
                } else if js && word == b"function" {
                    start_operand!();
                    if prev.expects_operand() {
                        nesting.top().expression_body_pending = true;
                    }
                    prev = PrevToken::Operand;
                } else {
                    start_operand!();
                    if is_stmt_keyword {
                        nesting.top().stmt_run += 1;
                        if nesting.exceeds() {
                            return true;
                        }
                        prev = if js && matches!(word, b"if" | b"for" | b"while" | b"with") {
                            PrevToken::HeadKeyword
                        } else if js && matches!(word, b"do" | b"try") {
                            PrevToken::StatementStart
                        } else {
                            PrevToken::Operator
                        };
                    } else if js && matches!(word, b"return" | b"throw") {
                        prev = PrevToken::Operator;
                    } else if js && matches!(word, b"else" | b"catch" | b"finally") {
                        // The clause belongs to the statement the last `;` or
                        // `}` ended, so what follows nests under that spine.
                        let top = nesting.top();
                        top.stmt_run = top.stmt_run.max(top.ended_stmt_run);
                        prev = PrevToken::StatementStart;
                    } else if !js && word == b"end" {
                        // `end` closes a block, so a following construct starts a
                        // fresh spine rather than nesting under this one.
                        nesting.top().stmt_run = 0;
                        prev = PrevToken::Operand;
                    } else {
                        prev = PrevToken::Operand;
                    }
                }
            }
            _ => {
                // A digit or any other expression byte ends a spine element.
                start_operand!();
                prev = PrevToken::Operand;
                i += 1;
            }
        }
        statement_break = false;
    }
    false
}
