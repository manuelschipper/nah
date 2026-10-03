//! Shell parser: token stream to a tree of pipelines, command groups, and
//! typed unsupported regions. Brace groups, subshells, and if/for/while/until
//! bodies are walked so the commands inside them contribute effects;
//! `case` arms are walked (every arm is a may-path). `[[ ]]` becomes a
//! `[[` command over the expression's words so their expansions are analyzed.
//! Function definitions (`name() { ... }` / `function name { ... }`) are
//! recorded; a later call to the name walks the body.

use std::cell::OnceCell;
use std::rc::Rc;

use crate::shell::lex::{self, Op, RedirKind, Seg, ShellDupTarget, ShellSpan, Tok, WordTok};

#[derive(Debug, Clone)]
pub(super) enum ShellItem {
    /// One pipeline; a single-command pipeline is the common case.
    /// `conditional` is true when the pipeline is the operand of a preceding
    /// `&&`/`||`, so it runs only on some paths. Assignments made by a
    /// conditional command are not statically certain and widen to unknown.
    Pipeline {
        cmds: Vec<Simple>,
        conditional: bool,
        short_circuit: Option<(ShellSpan, bool)>,
    },
    /// A command group whose inner items are walked in order.
    Group {
        kind: GroupKind,
        items: Vec<ShellItem>,
    },
    /// A recognized construct this frontend does not interpret.
    Unsupported {
        construct: &'static str,
        span: ShellSpan,
    },
    /// Marks the body of a loop that never ends and starts background jobs
    /// it never reaps, so the loop creates processes without bound. Carried
    /// as an item because only the parser still has the loop's header.
    /// `condition` names the header's command head, which a function defined
    /// before the loop can shadow.
    UnboundedSpawn {
        condition: Option<String>,
        span: ShellSpan,
    },
    /// A header expansion whose possible commands are not walked.
    UnwalkedExpansion { span: ShellSpan },
    /// Tokens that do not form a recognizable command.
    ParseError { message: String, span: ShellSpan },
    /// A function definition. The body is not executed here; a later call
    /// to `name` walks it at the call site.
    Function {
        name: String,
        body: Rc<Vec<ShellItem>>,
        redirs: Vec<Redir>,
        inputs: Rc<OnceCell<super::ReferencedInputs>>,
        saturated_inputs: Rc<OnceCell<super::ReferencedInputs>>,
        span: ShellSpan,
    },
    /// Mutually exclusive `if`/`case` alternatives. Arms stay separate so
    /// effects retain their branch conditions and budget allocation is fair.
    /// The arms cover every path: a construct that may match nothing carries
    /// an explicit empty arm for that path.
    Alternatives {
        group: u32,
        end: u32,
        arms: Vec<Vec<ShellItem>>,
    },
    /// A `for`/`select` body and the explicit `in` list, when `for` supplied
    /// one. The walker can preserve a bounded literal/glob list; all other
    /// loop variables remain unknown rather than environment reads.
    /// `arithmetic` spans the `INIT; COND; STEP` text of a `for (( ))` header.
    For {
        var: Option<(String, ShellSpan)>,
        values: Option<Vec<WordTok>>,
        arithmetic: Option<ShellSpan>,
        items: Vec<ShellItem>,
    },
}

/// How a group's inner items relate to the surrounding shell state.
#[derive(Debug, Clone)]
pub(super) enum GroupKind {
    Coprocess {
        name: Option<String>,
        span: ShellSpan,
    },
    /// `{ ...; }`: runs in the current shell; state changes persist.
    Brace,
    /// A compound command followed by its own redirections: `items` holds the
    /// redirections as a null command, then the compound command, then any
    /// pipeline stages the redirected command feeds. The redirections apply
    /// to the body only and are undone after it.
    Redirected,
    /// `( ... )`: runs in a subshell; state changes do not escape.
    Subshell,
    /// Runs concurrently with the following list.
    Background,
    /// Compound pipeline stages run concurrently in isolated shells.
    CompoundPipeline,
    /// if/for/while/until conditions and bodies: commands run only on some
    /// paths, so their assignments are not statically certain. `entry` is set
    /// when a constant condition runs a body that always reaches its end, so
    /// the first pass is certain; it holds the condition's command name, which
    /// a function can shadow, or None for `(( N ))`.
    Conditional {
        entry: Option<Option<String>>,
    },
    ShortCircuit(Option<(ShellSpan, bool)>),
    /// Commands no path reaches: the body of a loop whose constant condition
    /// never enters it, or what follows an unconditional `break` or
    /// `continue` in a loop body. `head` names the command that decided it,
    /// which a function, alias or disabled builtin of that name could change.
    Unreachable {
        head: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub(super) struct Simple {
    /// Prefix assignments (VAR=value). Persist only for a bare assignment
    /// statement; before a command word they scope to that command.
    pub assignments: Vec<Assign>,
    pub words: Vec<WordTok>,
    pub redirs: Vec<Redir>,
    /// Redirections trailing a compound command that runs in the current
    /// shell (`{ ...; }`, a loop, `if`, `case`). Assignments their expansions
    /// make persist, unlike a null command's here-document.
    pub compound_redirects: bool,
    pub span: ShellSpan,
}

#[derive(Debug, Clone)]
pub(super) struct Assign {
    pub name: String,
    pub value: WordTok,
    /// `NAME+=value`: the value extends what NAME already holds.
    pub append: bool,
    pub span: ShellSpan,
}

#[derive(Debug, Clone)]
pub(super) struct Redir {
    pub kind: RedirKind,
    /// The source descriptor being redirected (0 for input forms, 1 for output
    /// forms, or an explicit `n>`). Preserved so ordered fd wiring is correct.
    pub fd: Option<u32>,
    /// `{name}` allocates or closes a runtime-selected descriptor.
    pub named_fd: Option<String>,
    /// The duplication target for `Dup` (`2>&1` → Fd(1), `2>&-` → Close).
    pub dup: Option<ShellDupTarget>,
    /// `&>`/`>&file`: this redirect affects stdout and stderr together.
    pub both: bool,
    pub target: Option<WordTok>,
    pub heredoc: Option<lex::HereDoc>,
    pub span: ShellSpan,
}

/// Reserved words that open a construct we skip to its closer.
const OPENERS: [&str; 6] = ["if", "for", "while", "until", "case", "select"];
const CLOSERS: [&str; 3] = ["fi", "done", "esac"];
/// Keywords that only appear inside constructs; loose ones are misplaced.
const INNER_KEYWORDS: [&str; 8] = ["then", "else", "elif", "do", "done", "fi", "esac", "in"];

/// Bound on parser recursion into nested groups/constructs, so adversarial
/// deep nesting is skipped iteratively rather than overflowing the stack.
const MAX_NEST: u32 = 128;

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    src_end: u32,
    // Syntax errors must survive even when a malformed scan consumes a function call.
    errors: Vec<ShellItem>,
}

/// Why a command list stopped: end of input, a terminator keyword now under
/// the cursor (unconsumed), or a subshell-closing `)`.
enum Stop {
    Eof,
    Keyword(String),
    RParen,
    /// `;;` at the end of a `case` arm.
    DSemi,
}

pub(super) fn parse_shell_items(toks: &[Tok], src_end: u32) -> Vec<ShellItem> {
    let mut p = Parser {
        toks,
        pos: 0,
        src_end,
        errors: Vec::new(),
    };
    let (mut items, _) = p.list(&[], false, 0);
    items.append(&mut p.errors);
    items
}

// Compound pipeline wiring is still unsupported, but each parsed component
// runs in a child shell. Keep its parse boundaries and later stages reachable.
fn isolate_compound_pipeline(items: &mut Vec<ShellItem>, start: usize, piped: bool) {
    if piped {
        let stages = items.split_off(start);
        items.push(ShellItem::Group {
            kind: GroupKind::CompoundPipeline,
            items: stages
                .into_iter()
                .map(|item| ShellItem::Group {
                    kind: GroupKind::Subshell,
                    items: vec![item],
                })
                .collect(),
        });
    }
}

/// Move a compound command's trailing redirections, parsed as the null
/// command at `redirects`, into a `Redirected` group around the compound
/// command before it. When the redirections start a pipeline, the later
/// stages follow as the group's consumer and the whole pipeline runs in a
/// subshell. Returns whether a consumer was attached.
fn attach_compound_redirects(items: &mut Vec<ShellItem>, redirects: usize) -> bool {
    if redirects == 0
        || items.len() != redirects + 1
        || !matches!(&items[redirects], ShellItem::Pipeline { cmds, .. }
            if cmds.first().is_some_and(|cmd| cmd.compound_redirects))
    {
        return false;
    }
    let Some(ShellItem::Pipeline { mut cmds, .. }) = items.pop() else {
        unreachable!()
    };
    let consumer = cmds.split_off(1);
    let redirect = ShellItem::Pipeline {
        cmds,
        conditional: false,
        short_circuit: None,
    };
    let mut redirected = vec![redirect];
    let consumer = (!consumer.is_empty()).then_some(ShellItem::Pipeline {
        cmds: consumer,
        conditional: false,
        short_circuit: None,
    });
    let piped = consumer.is_some();
    // A short-circuit operand keeps its guard around the redirected command.
    let target = match items.last_mut() {
        Some(ShellItem::Group {
            kind: GroupKind::ShortCircuit(_),
            items: inner,
        }) if inner.len() == 1 => inner,
        _ => items,
    };
    let compound = target.pop().unwrap();
    target.push(match compound {
        // A subshell expands and applies its redirections in the child.
        ShellItem::Group {
            kind: GroupKind::Subshell,
            items,
        } => ShellItem::Group {
            kind: GroupKind::Subshell,
            items: vec![ShellItem::Group {
                kind: GroupKind::Redirected,
                items: {
                    redirected.push(ShellItem::Group {
                        kind: GroupKind::Brace,
                        items,
                    });
                    redirected.extend(consumer);
                    redirected
                },
            }],
        },
        compound => {
            redirected.push(compound);
            redirected.extend(consumer);
            let redirected = ShellItem::Group {
                kind: GroupKind::Redirected,
                items: redirected,
            };
            if piped {
                ShellItem::Group {
                    kind: GroupKind::Subshell,
                    items: vec![redirected],
                }
            } else {
                redirected
            }
        }
    });
    piped
}

impl<'a> Parser<'a> {
    /// `((NAME=EXPR))` under the cursor, a lone arithmetic assignment, as the
    /// assignment it makes in the current shell. Its value is EXPR evaluated
    /// as arithmetic, the way `$((EXPR))` evaluates it.
    fn arithmetic_assignment(&self) -> Option<Assign> {
        let [
            Tok::Op(Op::LParen, open),
            Tok::Op(Op::LParen, inner_open),
            Tok::Word(word),
            Tok::Op(Op::RParen, inner_close),
            Tok::Op(Op::RParen, close),
        ] = self.toks.get(self.pos..self.pos + 5)?
        else {
            return None;
        };
        if open.end != inner_open.start || inner_close.end != close.start {
            return None;
        }
        let [
            Seg::Literal {
                text,
                quoted: false,
            },
        ] = word.segs.as_slice()
        else {
            return None;
        };
        if text.len() as u32 != word.span.end - word.span.start {
            return None;
        }
        let mut assign = split_assignment(word).filter(|assign| !assign.append)?;
        let value = word.span.start + text.find('=')? as u32 + 1;
        if value == word.span.end {
            return None;
        }
        assign.value = WordTok {
            segs: vec![Seg::Arith {
                span: ShellSpan {
                    start: value,
                    end: word.span.end,
                },
            }],
            span: ShellSpan {
                start: value,
                end: word.span.end,
            },
        };
        assign.span = ShellSpan {
            start: open.start,
            end: close.end,
        };
        Some(assign)
    }

    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.pos)
    }

    /// Parse a command list until a terminator keyword in `terms`, a closing
    /// `)` (when `paren_terminates`), `;;` in a case arm (`esac` in `terms`),
    /// or end of input. The terminator token is left under the cursor for
    /// the caller to consume.
    fn list(
        &mut self,
        terms: &[&str],
        paren_terminates: bool,
        depth: u32,
    ) -> (Vec<ShellItem>, Stop) {
        let opener = self.pos.saturating_sub(1);
        let mut items = Vec::new();
        // Whether the next pipeline is guarded by a preceding `&&`/`||`.
        let mut conditional = false;
        let mut short_circuit = None;
        let mut chain_start = None;
        let mut job_start = 0;
        let mut pipeline_start = 0;
        let mut compound_pipeline = false;
        let stop = loop {
            let Some(tok) = self.peek() else {
                break Stop::Eof;
            };
            match tok {
                Tok::Op(op @ (Op::AndIf | Op::OrIf), _) => {
                    isolate_compound_pipeline(&mut items, pipeline_start, compound_pipeline);
                    pipeline_start = items.len();
                    compound_pipeline = false;
                    short_circuit = items
                        .last()
                        .and_then(|item| items_span(std::slice::from_ref(item)))
                        .map(|span| {
                            let start = *chain_start.get_or_insert(span.start);
                            (
                                ShellSpan {
                                    start,
                                    end: self.prev_end(),
                                },
                                *op == Op::AndIf,
                            )
                        });
                    conditional = true;
                    self.pos += 1;
                    while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
                        self.pos += 1;
                    }
                }
                Tok::Op(op @ (Op::Semi | Op::Amp | Op::Newline), _) => {
                    isolate_compound_pipeline(&mut items, pipeline_start, compound_pipeline);
                    if *op == Op::Amp && job_start < items.len() {
                        // The entire asynchronous AND/OR list runs in a child shell.
                        let job = items.split_off(job_start);
                        items.push(ShellItem::Group {
                            kind: GroupKind::Background,
                            items: job,
                        });
                    }
                    job_start = items.len();
                    pipeline_start = items.len();
                    compound_pipeline = false;
                    conditional = false;
                    short_circuit = None;
                    chain_start = None;
                    self.pos += 1;
                }
                Tok::Op(Op::DSemi | Op::SemiAmp | Op::DSemiAmp, _) if terms.contains(&"esac") => {
                    break Stop::DSemi;
                }
                Tok::Op(Op::LParen, _) if self.arithmetic_assignment().is_some() => {
                    let assign = self.arithmetic_assignment().unwrap();
                    self.pos += 5;
                    let span = assign.span;
                    items.push(ShellItem::Pipeline {
                        cmds: vec![Simple {
                            assignments: vec![assign],
                            words: Vec::new(),
                            redirs: Vec::new(),
                            compound_redirects: false,
                            span,
                        }],
                        conditional,
                        short_circuit,
                    });
                }
                Tok::Op(Op::LParen, span) => {
                    let start = span.start;
                    if depth >= MAX_NEST {
                        let end = self.skip_parens();
                        items.push(ShellItem::Unsupported {
                            construct: "subshell",
                            span: ShellSpan { start, end },
                        });
                    } else {
                        self.pos += 1;
                        let (inner, stop) = self.list(&[], true, depth + 1);
                        if matches!(stop, Stop::RParen) {
                            self.pos += 1;
                        }
                        let item = ShellItem::Group {
                            kind: GroupKind::Subshell,
                            items: inner,
                        };
                        items.push(if conditional {
                            ShellItem::Group {
                                kind: GroupKind::ShortCircuit(short_circuit),
                                items: vec![item],
                            }
                        } else {
                            item
                        });
                    }
                }
                Tok::Op(Op::RParen, span) => {
                    if paren_terminates {
                        break Stop::RParen;
                    }
                    let span = *span;
                    self.pos += 1;
                    items.push(ShellItem::ParseError {
                        message: "unexpected operator".into(),
                        span,
                    });
                }
                Tok::Op(
                    op @ (Op::DSemi | Op::SemiAmp | Op::DSemiAmp | Op::Pipe | Op::PipeBoth),
                    span,
                ) => {
                    let pipe = matches!(op, Op::Pipe | Op::PipeBoth);
                    let span = *span;
                    // `{ ...; } | consumer`: a compound command that starts
                    // the pipeline feeds its consumer the way a redirected
                    // one does, with no redirections of its own beyond the
                    // `2>&1` that `|&` adds.
                    if pipe
                        && !compound_pipeline
                        && items.len() == pipeline_start + 1
                        && self.follows_compound(&items)
                        && let Some(consumer) =
                            self.compound_consumer(conditional, short_circuit, depth)
                    {
                        let start = items.len();
                        items.push(consumer);
                        if let Some(ShellItem::Pipeline { cmds, .. }) = items.get_mut(start) {
                            cmds.insert(
                                0,
                                Simple {
                                    assignments: Vec::new(),
                                    words: Vec::new(),
                                    redirs: (*op == Op::PipeBoth)
                                        .then_some(Redir {
                                            kind: RedirKind::Dup,
                                            fd: Some(2),
                                            named_fd: None,
                                            dup: Some(ShellDupTarget::Fd(1)),
                                            both: false,
                                            target: None,
                                            heredoc: None,
                                            span,
                                        })
                                        .into_iter()
                                        .collect(),
                                    compound_redirects: true,
                                    span,
                                },
                            );
                        }
                        attach_compound_redirects(&mut items, start);
                        continue;
                    }
                    compound_pipeline |= pipe;
                    self.pos += 1;
                    if pipe {
                        while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
                            self.pos += 1;
                        }
                    }
                    items.push(ShellItem::ParseError {
                        message: "unexpected operator".into(),
                        span,
                    });
                }
                Tok::Word(w) => {
                    if let Some(text) = literal_text(w) {
                        if terms.contains(&text.as_str()) {
                            break Stop::Keyword(text);
                        }
                        let span = w.span;
                        if text == "coproc" && depth < MAX_NEST {
                            self.pos += 1;
                            let name = if matches!(self.toks.get(self.pos + 1), Some(Tok::Word(word)) if literal_text(word).as_deref() == Some("{"))
                            {
                                let name = match self.peek() {
                                    Some(Tok::Word(word)) => literal_text(word),
                                    _ => None,
                                };
                                self.pos += 1;
                                name
                            } else {
                                Some("COPROC".into())
                            };
                            let start = self
                                .peek()
                                .map(|token| match token {
                                    Tok::Word(word) => word.span.start,
                                    Tok::Op(_, span) | Tok::Redir { span, .. } => span.start,
                                })
                                .unwrap_or(span.end);
                            let body = self.parse_function_body(depth + 1);
                            let item = ShellItem::Group {
                                kind: GroupKind::Coprocess {
                                    name,
                                    span: ShellSpan {
                                        start,
                                        end: self.prev_end(),
                                    },
                                },
                                items: body,
                            };
                            items.push(if conditional {
                                ShellItem::Group {
                                    kind: GroupKind::ShortCircuit(short_circuit),
                                    items: vec![item],
                                }
                            } else {
                                item
                            });
                            continue;
                        }
                        if let Some(item) = self.try_open(&text, span, depth) {
                            items.push(if conditional {
                                ShellItem::Group {
                                    kind: GroupKind::ShortCircuit(short_circuit),
                                    items: vec![item],
                                }
                            } else {
                                item
                            });
                            continue;
                        }
                    }
                    compound_pipeline |=
                        self.pipeline(&mut items, conditional, short_circuit, depth)
                            && !matches!(&items[pipeline_start..],
                                [ShellItem::Pipeline { cmds, .. }] if cmds.len() > 1);
                }
                Tok::Redir { .. } => {
                    let compound = self.follows_compound(&items);
                    let start = items.len();
                    compound_pipeline |=
                        self.pipeline(&mut items, conditional, short_circuit, depth)
                            && !matches!(&items[pipeline_start..],
                                [ShellItem::Pipeline { cmds, .. }] if cmds.len() > 1);
                    if compound
                        && let Some(ShellItem::Pipeline { cmds, .. }) = items.get_mut(start)
                        && let Some(cmd) = cmds.first_mut()
                    {
                        cmd.compound_redirects = cmd.words.is_empty();
                    }
                    // A redirected compound command feeding its consumer is one
                    // wired pipeline, so the caller keeps its AND/OR selection.
                    if compound
                        && attach_compound_redirects(&mut items, start)
                        && items.len() == pipeline_start + 1
                    {
                        compound_pipeline = false;
                    }
                }
            }
        };
        isolate_compound_pipeline(&mut items, pipeline_start, compound_pipeline);
        if matches!(stop, Stop::Eof) && (!terms.is_empty() || paren_terminates) {
            self.retain_unterminated_construct(opener);
        }
        (items, stop)
    }

    /// Whether the token before the cursor closes the compound command that
    /// `items` ends with: a `}`, `done`, `fi` or `esac` keyword, or the `)` of
    /// a subshell group.
    fn follows_compound(&self, items: &[ShellItem]) -> bool {
        match self
            .pos
            .checked_sub(1)
            .and_then(|index| self.toks.get(index))
        {
            Some(Tok::Word(word)) => literal_text(word)
                .is_some_and(|text| matches!(text.as_str(), "}" | "done" | "fi" | "esac")),
            Some(Tok::Op(Op::RParen, _)) => matches!(
                items.last(),
                Some(ShellItem::Group {
                    kind: GroupKind::Subshell,
                    ..
                }) | Some(ShellItem::Group {
                    kind: GroupKind::ShortCircuit(_),
                    ..
                })
            ),
            _ => false,
        }
    }

    /// The simple-command stages after the `|` under the cursor, as one
    /// pipeline, consuming them. `None`, with nothing consumed, when a stage
    /// is a compound command: that chain stays an unwired compound pipeline.
    fn compound_consumer(
        &mut self,
        conditional: bool,
        short_circuit: Option<(ShellSpan, bool)>,
        depth: u32,
    ) -> Option<ShellItem> {
        let saved = (self.pos, self.errors.len());
        self.pos += 1;
        while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
            self.pos += 1;
        }
        let opens_compound = |parser: &Self| {
            matches!(parser.peek(), Some(Tok::Op(Op::LParen, _)))
                || matches!(parser.peek(), Some(Tok::Word(word)) if literal_text(word).is_some_and(|text|
                    matches!(text.as_str(), "{" | "if" | "for" | "select" | "while" | "until" | "case" | "coproc")))
        };
        let mut consumer = Vec::new();
        if !opens_compound(self) {
            self.pipeline(&mut consumer, conditional, short_circuit, depth);
        }
        // `pipeline` stops after a `|` (and its newlines) at a compound stage.
        let ends_in_compound = matches!(
            self.toks[..self.pos]
                .iter()
                .rev()
                .find(|token| !matches!(token, Tok::Op(Op::Newline, _))),
            Some(Tok::Op(Op::Pipe | Op::PipeBoth, _))
        );
        match consumer.as_slice() {
            [ShellItem::Pipeline { .. }] if !ends_in_compound => consumer.pop(),
            _ => {
                (self.pos, _) = saved;
                self.errors.truncate(saved.1);
                None
            }
        }
    }

    /// If `text` opens a construct we walk (`if`/`for`/`while`/`until`/`select`
    /// or a brace group), parse it into a group. Beyond the nesting bound the
    /// construct is skipped to its closer instead.
    fn try_open(&mut self, text: &str, span: ShellSpan, depth: u32) -> Option<ShellItem> {
        let opens = matches!(
            text,
            "if" | "for" | "while" | "until" | "select" | "case" | "{"
        );
        if !opens {
            return None;
        }
        if depth >= MAX_NEST {
            self.pos += 1;
            let (construct, end) = if text == "{" {
                ("brace group", self.skip_braces())
            } else {
                ("control-flow construct", self.skip_construct())
            };
            return Some(ShellItem::Unsupported {
                construct,
                span: ShellSpan {
                    start: span.start,
                    end,
                },
            });
        }
        Some(match text {
            "if" => self.parse_if(depth, span.start),
            "for" => self.parse_for(depth, true, span.start),
            "select" => self.parse_for(depth, false, span.start),
            "while" | "until" => self.parse_while(depth, text == "until", span.start),
            "case" => self.parse_case(depth, span.start),
            "{" => self.parse_brace(depth),
            _ => unreachable!(),
        })
    }

    fn parse_if(&mut self, depth: u32, group: u32) -> ShellItem {
        self.pos += 1; // `if`
        // The first condition list always runs, so it is not a may-path;
        // bodies, elif conditions, and else branches are.
        let (cond, stop) = self.list(&["then"], false, depth + 1);
        self.eat_keyword(&stop);
        // An `elif` test runs exactly when every earlier arm was skipped, so
        // it belongs to the alternative of the arms before it, not to the arm
        // it guards. Collect the chain first, then nest it from the inside
        // out so each test is exclusive with the preceding body only.
        let mut bodies = Vec::new();
        let mut elifs: Vec<(u32, Vec<ShellItem>)> = Vec::new();
        let mut otherwise = None;
        loop {
            let (body, stop) = self.list(&["elif", "else", "fi"], false, depth + 1);
            bodies.push(body);
            match &stop {
                Stop::Keyword(k) if k == "elif" => {
                    let elif_group = match self.peek() {
                        Some(Tok::Word(w)) => w.span.start,
                        _ => group,
                    };
                    self.pos += 1;
                    let (test, s) = self.list(&["then"], false, depth + 1);
                    self.eat_keyword(&s);
                    elifs.push((elif_group, test));
                }
                Stop::Keyword(k) if k == "else" => {
                    self.pos += 1;
                    let (body, stop) = self.list(&["fi"], false, depth + 1);
                    otherwise = Some(body);
                    self.eat_keyword(&stop);
                    break;
                }
                Stop::Keyword(_) => {
                    self.pos += 1; // `fi`
                    break;
                }
                _ => break,
            }
        }
        let mut nested: Option<ShellItem> = None;
        while let Some(body) = bodies.pop() {
            let mut arms = vec![body];
            match nested.take() {
                // An inner `elif` level: its test runs on the alternative
                // path, ahead of the nested alternatives it guards.
                Some(inner) => {
                    let (_, mut test) = elifs.pop().unwrap_or((group, Vec::new()));
                    test.push(inner);
                    arms.push(test);
                }
                // The innermost level. Without an `else`, the implicit empty
                // alternative is still an arm: it makes the arm set cover
                // every path, which consumers rely on to reason about state.
                None => arms.push(otherwise.take().unwrap_or_default()),
            }
            let level = elifs
                .last()
                .map(|(elif_group, _)| *elif_group)
                .unwrap_or(group);
            nested = Some(ShellItem::Alternatives {
                group: level,
                end: self.prev_end(),
                arms,
            });
        }
        let mut items = cond;
        if let Some(alternatives) = nested {
            items.push(alternatives);
        }
        ShellItem::Group {
            kind: GroupKind::Brace,
            items,
        }
    }

    fn parse_while(&mut self, depth: u32, until: bool, start: u32) -> ShellItem {
        self.pos += 1; // `while`/`until`
        let (cond, stop) = self.list(&["do"], false, depth + 1);
        self.eat_keyword(&stop);
        let (body, stop) = self.list(&["done"], false, depth + 1);
        self.eat_keyword(&stop);
        let body = if super::jobs::constant_status(&cond) == Some(until) {
            unreachable_body(super::jobs::condition_head(&cond), body)
        } else {
            loop_body(body)
        };
        let unbounded = super::jobs::unbounded_loop(&cond, &body, until)
            .then(|| super::jobs::condition_head(&cond));
        let entry = (super::jobs::constant_status(&cond) == Some(!until)
            && super::body_runs_every_iteration(&body))
        .then(|| super::jobs::condition_head(&cond));
        let mut items = cond;
        items.extend(body);
        if let Some(condition) = unbounded {
            items.push(ShellItem::UnboundedSpawn {
                condition,
                span: ShellSpan {
                    start,
                    end: self.prev_end(),
                },
            });
        }
        ShellItem::Group {
            kind: GroupKind::Conditional { entry },
            items,
        }
    }

    fn parse_for(&mut self, depth: u32, preserve_values: bool, start: u32) -> ShellItem {
        self.pos += 1; // `for`/`select`
        let var = match self.peek() {
            Some(Tok::Word(w)) => literal_text(w).map(|name| (name, w.span)),
            _ => None,
        };
        self.pos += usize::from(var.is_some());
        while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
            self.pos += 1;
        }
        let mut values = match self.peek() {
            Some(Tok::Word(w)) if literal_text(w).as_deref() == Some("in") => {
                self.pos += 1;
                Some(Vec::new())
            }
            _ => None,
        };
        let mut items = Vec::new();
        let mut found_do = false;
        let mut invalid_header = false;
        let mut header_ended = false;
        let mut parens = 0u32;
        let arithmetic = var.is_none()
            && matches!(self.peek(), Some(Tok::Op(Op::LParen, _)))
            && matches!(self.toks.get(self.pos + 1), Some(Tok::Op(Op::LParen, _)));
        // Token count per `;`-separated section of a `(( INIT; COND; POST ))`
        // header. An empty COND is the loop that never ends.
        let mut sections = vec![0usize];
        let mut header = ShellSpan { start: 0, end: 0 };
        // The `NAME in WORDS` header is not a command list; preserve its
        // words for bounded loop-variable binding, then skip it to `do`.
        while let Some(tok) = self.peek() {
            let is_do = parens == 0
                && matches!(tok, Tok::Word(w) if literal_text(w).as_deref() == Some("do"));
            retain_header_expansion(tok, &mut items);
            if !is_do {
                match tok {
                    Tok::Op(Op::LParen, span) if arithmetic && !header_ended => {
                        parens += 1;
                        if parens == 2 {
                            header.start = span.end;
                        }
                    }
                    Tok::Op(Op::RParen, span) if parens > 0 => {
                        if parens == 2 {
                            header.end = span.start;
                        }
                        parens -= 1;
                    }
                    // `;;` in `for ((;;))` lexes as one token but separates
                    // two empty header sections.
                    Tok::Op(Op::Semi | Op::DSemi, _) if arithmetic && parens == 2 => {
                        sections.push(0);
                        if matches!(tok, Tok::Op(Op::DSemi, _)) {
                            sections.push(0);
                        }
                    }
                    _ if parens > 0 => {
                        if arithmetic && parens == 2 {
                            *sections.last_mut().unwrap() += 1;
                        }
                    }
                    Tok::Op(Op::Semi | Op::Newline, _) => header_ended = true,
                    Tok::Word(word) if !header_ended && values.is_some() => {
                        values.as_mut().unwrap().push(word.clone());
                    }
                    _ => invalid_header = true,
                }
            }
            self.pos += 1;
            if is_do {
                found_do = true;
                break;
            }
        }
        if !found_do || invalid_header {
            items.push(ShellItem::ParseError {
                message: if found_do {
                    "unexpected tokens before loop do"
                } else {
                    "loop header is missing do"
                }
                .into(),
                span: ShellSpan {
                    start,
                    end: self.src_end,
                },
            });
        }
        let (body, stop) = self.list(&["done"], false, depth + 1);
        self.eat_keyword(&stop);
        // `for NAME in; do` has no value to run its body for.
        let mut body = if var.is_some() && values.as_ref().is_some_and(Vec::is_empty) {
            unreachable_body(None, body)
        } else {
            loop_body(body)
        };
        if items.is_empty()
            && matches!(sections.as_slice(), [_, 0, _])
            && super::jobs::unbounded_body(&body)
        {
            body.push(ShellItem::UnboundedSpawn {
                condition: None,
                span: ShellSpan {
                    start,
                    end: self.prev_end(),
                },
            });
        }
        // `for NAME; do` iterates the positional parameters, as `in "$@"`.
        let values = match (&var, values) {
            (Some((_, span)), None) if preserve_values => Some(vec![WordTok {
                segs: vec![Seg::AllArgs { quoted: true }],
                span: *span,
            }]),
            (_, values) => values,
        };
        let body = ShellItem::For {
            var,
            values: preserve_values.then_some(values).flatten(),
            arithmetic: (arithmetic && !invalid_header && header.end > header.start)
                .then_some(header),
            items: body,
        };
        if items.is_empty() {
            body
        } else {
            items.push(body);
            ShellItem::Group {
                kind: GroupKind::Brace,
                items,
            }
        }
    }

    fn parse_brace(&mut self, depth: u32) -> ShellItem {
        self.pos += 1; // `{`
        let (items, stop) = self.list(&["}"], false, depth + 1);
        self.eat_keyword(&stop);
        ShellItem::Group {
            kind: GroupKind::Brace,
            items,
        }
    }

    /// `case WORD in pat) list ;; ... esac`. Every arm is analyzed (may).
    fn parse_case(&mut self, depth: u32, group: u32) -> ShellItem {
        self.pos += 1; // `case`
        let mut items = Vec::new();
        let mut found_in = false;
        let mut invalid_header = false;
        let mut subject = None;
        // Only the subject word and newlines may precede `in`.
        if let Some(tok @ Tok::Word(word)) = self.peek() {
            subject = literal_word(word).map(|(text, _)| text);
            retain_header_expansion(tok, &mut items);
            self.pos += 1;
        }
        while let Some(tok) = self.peek() {
            retain_header_expansion(tok, &mut items);
            let is_in = matches!(tok, Tok::Word(w) if literal_text(w).as_deref() == Some("in"));
            invalid_header |= !is_in && !matches!(tok, Tok::Op(Op::Newline, _));
            self.pos += 1;
            if is_in {
                found_in = true;
                break;
            }
        }
        if !found_in || invalid_header {
            items.push(ShellItem::ParseError {
                message: if found_in {
                    "unexpected tokens before case in"
                } else {
                    "case header is missing in"
                }
                .into(),
                span: ShellSpan {
                    start: group,
                    end: self.src_end,
                },
            });
        }
        let mut arms = Vec::new();
        let mut patterns = Vec::new();
        let mut terminators = Vec::new();
        // Without a `*)` pattern the match may fall through; that no-match
        // path is an arm too, so the arm set covers every path.
        let mut matched_everything = false;
        loop {
            self.skip_separators();
            if matches!(self.peek(), Some(Tok::Word(w)) if literal_text(w).as_deref() == Some("esac"))
            {
                self.pos += 1;
                break;
            }
            if self.peek().is_none() {
                break;
            }
            let (catch_all, arm_patterns) = self.skip_case_pattern(&mut items);
            let (body, stop) = self.list(&["esac"], false, depth + 1);
            arms.push(body);
            patterns.push(arm_patterns);
            matched_everything |= catch_all;
            match stop {
                Stop::DSemi => {
                    terminators.push(match self.peek() {
                        Some(Tok::Op(Op::SemiAmp, _)) => Op::SemiAmp,
                        Some(Tok::Op(Op::DSemiAmp, _)) => Op::DSemiAmp,
                        _ => Op::DSemi,
                    });
                    self.pos += 1;
                }
                Stop::Keyword(_) => {
                    terminators.push(Op::DSemi);
                    self.pos += 1; // `esac`
                    break;
                }
                _ => {
                    terminators.push(Op::DSemi);
                    break;
                }
            }
        }
        // A literal subject matched against literal patterns selects its
        // arms before the script runs.
        if items.is_empty()
            && let Some(subject) = subject
            && let Some(selected) = select_case_arms(&subject, &patterns, &terminators)
        {
            return ShellItem::Group {
                kind: GroupKind::Brace,
                items: selected
                    .into_iter()
                    .flat_map(|arm| arms[arm].clone())
                    .collect(),
            };
        }
        // `;&` runs the next arm's body too, so that arm's path continues
        // into it.
        for arm in (0..arms.len().saturating_sub(1)).rev() {
            if terminators[arm] == Op::SemiAmp {
                let next = arms[arm + 1].clone();
                arms[arm].extend(next);
            }
        }
        if !matched_everything {
            arms.push(Vec::new());
        }
        let alternatives = ShellItem::Alternatives {
            group,
            end: self.prev_end(),
            arms,
        };
        if items.is_empty() {
            alternatives
        } else {
            items.push(alternatives);
            ShellItem::Group {
                kind: GroupKind::Brace,
                items,
            }
        }
    }

    fn skip_separators(&mut self) {
        while matches!(
            self.peek(),
            Some(Tok::Op(Op::Semi | Op::Amp | Op::Newline, _))
        ) {
            self.pos += 1;
        }
    }

    /// Consume a `case` pattern up to and including its closing `)`, and
    /// report whether that pattern is the `*` catch-all, and its
    /// alternatives when every one is literal text (`true` for a glob).
    fn skip_case_pattern(
        &mut self,
        items: &mut Vec<ShellItem>,
    ) -> (bool, Option<Vec<(String, bool)>>) {
        let start = self.pos;
        let mut depth = 0u32;
        let mut catch_all = false;
        let mut patterns = Some(Vec::new());
        let mut closed = false;
        let mut invalid_pattern = false;
        let mut previous_word_end = None;
        // The optional opening parenthesis belongs to the pattern terminator.
        if matches!(self.peek(), Some(Tok::Op(Op::LParen, _))) {
            self.pos += 1;
        }
        while let Some(tok) = self.peek() {
            if let Tok::Word(word) = tok {
                invalid_pattern |= previous_word_end.is_some_and(|end| end < word.span.start);
                previous_word_end = Some(word.span.end);
            } else {
                previous_word_end = None;
            }
            match tok {
                Tok::Word(w) if depth == 0 && literal_text(w).as_deref() == Some("esac") => {
                    break;
                }
                Tok::Op(Op::LParen, _) => {
                    depth += 1;
                    self.pos += 1;
                }
                Tok::Op(Op::RParen, _) => {
                    self.pos += 1;
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                    depth -= 1;
                }
                tok => {
                    invalid_pattern |= matches!(
                        tok,
                        Tok::Op(
                            Op::Semi
                                | Op::DSemi
                                | Op::SemiAmp
                                | Op::DSemiAmp
                                | Op::Amp
                                | Op::Newline,
                            _
                        )
                    );
                    retain_header_expansion(tok, items);
                    match tok {
                        Tok::Word(w) => {
                            catch_all |= literal_text(w).as_deref() == Some("*");
                            match (literal_word(w), &mut patterns) {
                                (Some(pattern), Some(patterns)) => patterns.push(pattern),
                                _ => patterns = None,
                            }
                        }
                        Tok::Op(Op::Pipe, _) => {}
                        _ => patterns = None,
                    }
                    self.pos += 1;
                }
            }
        }
        if !closed || invalid_pattern {
            let span = match &self.toks[start] {
                Tok::Word(word) => word.span,
                Tok::Op(_, span) | Tok::Redir { span, .. } => *span,
            };
            items.push(ShellItem::ParseError {
                message: "invalid or unterminated case pattern".into(),
                span: ShellSpan {
                    start: span.start,
                    end: self.src_end,
                },
            });
        }
        (catch_all, patterns.filter(|_| depth == 0))
    }

    /// Consume the terminator keyword a sub-list stopped on, if any.
    fn eat_keyword(&mut self, stop: &Stop) {
        if matches!(stop, Stop::Keyword(_)) {
            self.pos += 1;
        }
    }

    fn pipeline(
        &mut self,
        items: &mut Vec<ShellItem>,
        conditional: bool,
        short_circuit: Option<(ShellSpan, bool)>,
        depth: u32,
    ) -> bool {
        let mut cmds = Vec::new();
        let mut piped = false;
        loop {
            // Let the list parser retain a compound stage's body and group it
            // with the preceding stages instead of consuming it as command words.
            if piped
                && (matches!(self.peek(), Some(Tok::Op(Op::LParen, _)))
                    || matches!(self.peek(), Some(Tok::Word(word))
                        if literal_text(word).is_some_and(|text|
                            matches!(text.as_str(), "{" | "if" | "for" | "select" | "while" | "until" | "case"))))
            {
                break;
            }
            match self.simple(depth) {
                SimpleOut::Cmd(cmd) => cmds.push(cmd),
                SimpleOut::Empty => {}
                SimpleOut::Function { name, body, span } => {
                    if !cmds.is_empty() {
                        items.push(ShellItem::Pipeline {
                            cmds: std::mem::take(&mut cmds),
                            conditional,
                            short_circuit,
                        });
                    }
                    let redirs = if matches!(self.peek(), Some(Tok::Redir { .. })) {
                        match self.simple(depth) {
                            SimpleOut::Cmd(cmd) => cmd.redirs,
                            _ => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    };
                    let function = ShellItem::Function {
                        redirs,
                        name,
                        body: Rc::new(body),
                        inputs: Rc::new(OnceCell::new()),
                        saturated_inputs: Rc::new(OnceCell::new()),
                        span,
                    };
                    // `false && f(){ ...; }` never defines `f`: the definition
                    // is an AND/OR operand like any command.
                    items.push(if conditional {
                        ShellItem::Group {
                            kind: GroupKind::ShortCircuit(short_circuit),
                            items: vec![function],
                        }
                    } else {
                        function
                    });
                    return piped;
                }
                SimpleOut::Unsupported { construct, span } => {
                    if !cmds.is_empty() {
                        items.push(ShellItem::Pipeline {
                            cmds: std::mem::take(&mut cmds),
                            conditional,
                            short_circuit,
                        });
                    }
                    items.push(ShellItem::Unsupported { construct, span });
                }
            }
            match self.peek() {
                Some(Tok::Op(Op::Pipe, _)) => {
                    piped = true;
                    self.pos += 1;
                }
                Some(Tok::Op(Op::PipeBoth, _)) => {
                    piped = true;
                    self.pos += 1;
                    // `|&` routes the left command's stderr into the pipe too,
                    // as if `2>&1` were appended after its own redirects.
                    if let Some(cmd) = cmds.last_mut() {
                        cmd.redirs.push(Redir {
                            kind: RedirKind::Dup,
                            fd: Some(2),
                            named_fd: None,
                            dup: Some(ShellDupTarget::Fd(1)),
                            both: false,
                            target: None,
                            heredoc: None,
                            span: cmd.span,
                        });
                    }
                }
                _ => break,
            }
            while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
                self.pos += 1;
            }
        }
        if !cmds.is_empty() {
            items.push(ShellItem::Pipeline {
                cmds,
                conditional,
                short_circuit,
            });
        }
        piped
    }

    fn simple(&mut self, depth: u32) -> SimpleOut {
        let mut assignments = Vec::new();
        let mut words: Vec<WordTok> = Vec::new();
        let mut redirs = Vec::new();
        let mut named_fd = None;
        let mut start: Option<u32> = None;
        let mut end: u32 = 0;

        loop {
            match self.peek() {
                Some(Tok::Word(w)) => {
                    let w = w.clone();
                    start.get_or_insert(w.span.start);
                    end = w.span.end;
                    if let Some(text) = literal_text(&w)
                        && let Some(name) = text.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
                        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && matches!(self.toks.get(self.pos + 1), Some(Tok::Redir { span, .. }) if span.start == w.span.end)
                    {
                        named_fd = Some(name.to_string());
                        self.pos += 1;
                        continue;
                    }
                    if words.is_empty() {
                        if let Some(assign) = split_assignment(&w) {
                            self.pos += 1;
                            assignments.push(assign);
                            continue;
                        }
                        if let Some(text) = literal_text(&w) {
                            if let Some(out) = self.reserved(&text, w.span, depth) {
                                return out;
                            }
                            // `!` negates, `time` reports, and `coproc` runs the
                            // simple command that follows as a coprocess: none of
                            // them changes which command runs.
                            if text == "!" || text == "time" || text == "coproc" {
                                self.pos += 1;
                                continue;
                            }
                        }
                    }
                    self.pos += 1;
                    // name() function definition.
                    if words.is_empty()
                        && assignments.is_empty()
                        && matches!(self.peek(), Some(Tok::Op(Op::LParen, _)))
                        && matches!(self.toks.get(self.pos + 1), Some(Tok::Op(Op::RParen, _)))
                    {
                        self.pos += 2;
                        if let Some(name) = literal_text(&w) {
                            let body = self.parse_function_body(depth);
                            return SimpleOut::Function {
                                name,
                                body,
                                span: ShellSpan {
                                    start: w.span.start,
                                    end: self.prev_end(),
                                },
                            };
                        }
                        let fn_end = self.skip_function_body();
                        return SimpleOut::Unsupported {
                            construct: "function definition",
                            span: ShellSpan {
                                start: w.span.start,
                                end: fn_end,
                            },
                        };
                    }
                    words.push(w);
                }
                Some(Tok::Redir {
                    kind,
                    fd,
                    dup,
                    both,
                    heredoc,
                    span,
                }) => {
                    let (kind, fd, dup, both, heredoc, span) =
                        (*kind, *fd, *dup, *both, heredoc.clone(), *span);
                    start.get_or_insert(span.start);
                    end = span.end;
                    self.pos += 1;
                    let target = if needs_target(kind) || (kind == RedirKind::Dup && dup.is_none())
                    {
                        match self.peek() {
                            Some(Tok::Word(w)) => {
                                let w = w.clone();
                                end = w.span.end;
                                self.pos += 1;
                                Some(w)
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    redirs.push(Redir {
                        kind,
                        fd,
                        named_fd: named_fd.take(),
                        dup,
                        both,
                        target,
                        heredoc,
                        span,
                    });
                }
                _ => break,
            }
        }

        let Some(start) = start else {
            return SimpleOut::Empty;
        };
        SimpleOut::Cmd(Simple {
            assignments,
            words,
            redirs,
            compound_redirects: false,
            span: ShellSpan { start, end },
        })
    }

    /// Handle a reserved word in command position that the list layer did not
    /// intercept: constructs that reach here (as a later pipeline stage, or
    /// ones we do not walk) are skipped to their closer.
    fn reserved(&mut self, text: &str, span: ShellSpan, depth: u32) -> Option<SimpleOut> {
        if OPENERS.contains(&text) {
            self.pos += 1;
            let end = self.skip_construct();
            return Some(SimpleOut::Unsupported {
                construct: "control-flow construct",
                span: ShellSpan {
                    start: span.start,
                    end,
                },
            });
        }
        match text {
            "function" => {
                self.pos += 1;
                let name = match self.peek() {
                    Some(Tok::Word(w)) => {
                        let n = literal_text(w);
                        self.pos += 1;
                        n
                    }
                    _ => None,
                };
                if matches!(self.peek(), Some(Tok::Op(Op::LParen, _)))
                    && matches!(self.toks.get(self.pos + 1), Some(Tok::Op(Op::RParen, _)))
                {
                    self.pos += 2;
                }
                if let Some(name) = name {
                    let body = self.parse_function_body(depth);
                    Some(SimpleOut::Function {
                        name,
                        body,
                        span: ShellSpan {
                            start: span.start,
                            end: self.prev_end(),
                        },
                    })
                } else {
                    let end = self.skip_function_body();
                    Some(SimpleOut::Unsupported {
                        construct: "function definition",
                        span: ShellSpan {
                            start: span.start,
                            end,
                        },
                    })
                }
            }
            "{" => {
                self.pos += 1;
                let end = self.skip_braces();
                Some(SimpleOut::Unsupported {
                    construct: "brace group",
                    span: ShellSpan {
                        start: span.start,
                        end,
                    },
                })
            }
            // `[[ ... ]]` becomes a `[[` command over the expression's words:
            // the test itself has no effect, but its expansions (variable
            // reads, command substitutions) are analyzed like any argv.
            "[[" => {
                self.pos += 1;
                let mut words = vec![WordTok {
                    segs: vec![Seg::Literal {
                        text: "[[".into(),
                        quoted: false,
                    }],
                    span,
                }];
                let mut end = span.end;
                let mut terminated = false;
                let mut invalid_separator = false;
                let mut newline_allowed = true;
                let mut regex_next = false;
                let mut regex_end = None;
                while let Some(tok) = self.peek() {
                    if matches!(tok, Tok::Op(Op::Newline, _)) {
                        // Newlines continue an expression at its start or after a
                        // logical operator, or before a logical operator or closer.
                        while let Some(Tok::Op(Op::Newline, span)) = self.peek() {
                            end = span.end;
                            self.pos += 1;
                        }
                        invalid_separator |= !newline_allowed
                            && !matches!(
                                self.peek(),
                                Some(Tok::Op(Op::AndIf | Op::OrIf | Op::RParen, _))
                            )
                            && !matches!(self.peek(), Some(Tok::Word(w))
                                if literal_text(w).as_deref() == Some("]]"));
                        regex_next = false;
                        regex_end = None;
                        continue;
                    }
                    end = tok_end(tok);
                    let start = match tok {
                        Tok::Word(w) => w.span.start,
                        Tok::Op(_, span) | Tok::Redir { span, .. } => span.start,
                    };
                    // A pipe within the contiguous operand of `=~` is regex alternation.
                    let in_regex = regex_next || regex_end == Some(start);
                    regex_next = false;
                    regex_end = in_regex.then_some(end);
                    if let Tok::Word(w) = tok {
                        let text = literal_text(w);
                        if text.as_deref() == Some("]]") {
                            self.pos += 1;
                            terminated = true;
                            break;
                        }
                        regex_next = !in_regex && text.as_deref() == Some("=~");
                        newline_allowed &= text.as_deref() == Some("!");
                        words.push(w.clone());
                    } else {
                        newline_allowed = !in_regex
                            && matches!(tok, Tok::Op(Op::AndIf | Op::OrIf | Op::LParen, _));
                    }
                    invalid_separator |= matches!(
                        tok,
                        Tok::Op(
                            Op::Semi
                                | Op::DSemi
                                | Op::SemiAmp
                                | Op::DSemiAmp
                                | Op::Amp
                                | Op::PipeBoth,
                            _
                        )
                    ) || matches!(tok, Tok::Op(Op::Pipe, _)) && !in_regex;
                    self.pos += 1;
                }
                if !terminated || invalid_separator {
                    self.errors.push(ShellItem::ParseError {
                        message: "invalid or unterminated double-bracket condition".into(),
                        span: ShellSpan {
                            start: span.start,
                            end: if terminated { end } else { self.src_end },
                        },
                    });
                }
                Some(SimpleOut::Cmd(Simple {
                    assignments: Vec::new(),
                    words,
                    redirs: Vec::new(),
                    compound_redirects: false,
                    span: ShellSpan {
                        start: span.start,
                        end,
                    },
                }))
            }
            t if INNER_KEYWORDS.contains(&t) || t == "}" => {
                self.pos += 1;
                Some(SimpleOut::Unsupported {
                    construct: "misplaced keyword",
                    span,
                })
            }
            _ => None,
        }
    }

    // A missing terminator can swallow an enclosing function's call site.
    // Keep the error at source scope even if that function is never walked.
    fn retain_unterminated_construct(&mut self, opener: usize) {
        let start = match &self.toks[opener] {
            Tok::Word(word) => word.span.start,
            Tok::Op(_, span) | Tok::Redir { span, .. } => span.start,
        };
        self.errors.push(ShellItem::ParseError {
            message: "unterminated shell construct".into(),
            span: ShellSpan {
                start,
                end: self.src_end,
            },
        });
    }

    /// Skip to the closer matching an already-consumed opener, counting
    /// nested openers/closers by literal word text. This is approximate:
    /// a closer word used as a plain argument inside the construct ends the
    /// skip early, which can only over-report commands (safe direction for
    /// may-effects), never hide them.
    fn skip_construct(&mut self) -> u32 {
        let opener = self.pos - 1;
        let mut depth = 1u32;
        while let Some(tok) = self.peek() {
            let end = tok_end(tok);
            if let Tok::Word(w) = tok
                && let Some(text) = literal_text(w)
            {
                if OPENERS.contains(&text.as_str()) {
                    depth += 1;
                } else if CLOSERS.contains(&text.as_str()) {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return end;
                    }
                }
            }
            self.pos += 1;
        }
        self.retain_unterminated_construct(opener);
        self.src_end
    }

    fn skip_braces(&mut self) -> u32 {
        let opener = self.pos - 1;
        let mut depth = 1u32;
        while let Some(tok) = self.peek() {
            let end = tok_end(tok);
            if let Tok::Word(w) = tok
                && let Some(text) = literal_text(w)
            {
                if text == "{" {
                    depth += 1;
                } else if text == "}" {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return end;
                    }
                }
            }
            self.pos += 1;
        }
        self.retain_unterminated_construct(opener);
        self.src_end
    }

    fn skip_parens(&mut self) -> u32 {
        let opener = self.pos;
        let mut depth = 0u32;
        while let Some(tok) = self.peek() {
            let end = tok_end(tok);
            match tok {
                Tok::Op(Op::LParen, _) => depth += 1,
                Tok::Op(Op::RParen, _) => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return end;
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
        self.retain_unterminated_construct(opener);
        self.src_end
    }

    /// After `name()` / `function name`: parse a brace-group body, or one command.
    fn parse_function_body(&mut self, depth: u32) -> Vec<ShellItem> {
        while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
            self.pos += 1;
        }
        if depth >= MAX_NEST {
            let end = self.skip_function_body();
            return vec![ShellItem::Unsupported {
                construct: "function body",
                span: ShellSpan { start: end, end },
            }];
        }
        if let Some(Tok::Word(w)) = self.peek()
            && literal_text(w).as_deref() == Some("{")
        {
            self.pos += 1;
            let (items, stop) = self.list(&["}"], false, depth + 1);
            self.eat_keyword(&stop);
            return items;
        }
        let mut items = Vec::new();
        self.pipeline(&mut items, false, None, depth + 1);
        items
    }

    /// End of the last token consumed, for closing a construct's span.
    fn prev_end(&self) -> u32 {
        self.toks[..self.pos]
            .last()
            .map(tok_end)
            .unwrap_or(self.src_end)
    }

    /// After `name()`: skip an optional brace-group body, or one command.
    fn skip_function_body(&mut self) -> u32 {
        while matches!(self.peek(), Some(Tok::Op(Op::Newline, _))) {
            self.pos += 1;
        }
        if let Some(Tok::Word(w)) = self.peek()
            && literal_text(w).as_deref() == Some("{")
        {
            self.pos += 1;
            return self.skip_braces();
        }
        // Single-command body: skip to a separator.
        let mut end = self.src_end;
        while let Some(tok) = self.peek() {
            if matches!(tok, Tok::Op(Op::Semi | Op::Amp | Op::Newline, _)) {
                break;
            }
            end = tok_end(tok);
            self.pos += 1;
        }
        end
    }
}

enum SimpleOut {
    Cmd(Simple),
    Function {
        name: String,
        body: Vec<ShellItem>,
        span: ShellSpan,
    },
    Unsupported {
        construct: &'static str,
        span: ShellSpan,
    },
    Empty,
}

fn needs_target(kind: RedirKind) -> bool {
    !matches!(kind, RedirKind::Dup | RedirKind::HereDoc)
}

fn tok_end(tok: &Tok) -> u32 {
    match tok {
        Tok::Word(w) => w.span.end,
        Tok::Op(_, span) | Tok::Redir { span, .. } => span.end,
    }
}

/// Source span covering `items`, so a region the walker did not analyze can
/// be reported as an explicit boundary rather than silently dropped.
pub(crate) fn items_span(items: &[ShellItem]) -> Option<ShellSpan> {
    items
        .iter()
        .filter_map(|item| match item {
            ShellItem::Pipeline { cmds, .. } => match (cmds.first(), cmds.last()) {
                (Some(first), Some(last)) => Some(ShellSpan {
                    start: first.span.start,
                    end: last.span.end,
                }),
                _ => None,
            },
            ShellItem::Group { items, .. } | ShellItem::For { items, .. } => items_span(items),
            ShellItem::Alternatives { arms, .. } => arms
                .iter()
                .filter_map(|arm| items_span(arm))
                .reduce(merge_spans),
            ShellItem::UnwalkedExpansion { span }
            | ShellItem::Unsupported { span, .. }
            | ShellItem::UnboundedSpawn { span, .. }
            | ShellItem::ParseError { span, .. }
            | ShellItem::Function { span, .. } => Some(*span),
        })
        .reduce(merge_spans)
}

fn merge_spans(a: ShellSpan, b: ShellSpan) -> ShellSpan {
    ShellSpan {
        start: a.start.min(b.start),
        end: a.end.max(b.end),
    }
}

/// The word's full text if it is a single unquoted literal segment.
/// The text of a word made only of literal segments, and whether an
/// unquoted segment holds a glob character.
fn literal_word(w: &WordTok) -> Option<(String, bool)> {
    let mut text = String::new();
    let mut glob = false;
    for seg in &w.segs {
        let Seg::Literal { text: part, quoted } = seg else {
            return None;
        };
        glob |= !quoted && part.contains(['*', '?', '[']);
        text.push_str(part);
    }
    Some((text, glob))
}

/// The arms a literal `case` subject runs, in order, when every pattern
/// tested along the way is literal text or the `*` catch-all.
fn select_case_arms(
    subject: &str,
    patterns: &[Option<Vec<(String, bool)>>],
    terminators: &[Op],
) -> Option<Vec<usize>> {
    let mut selected = Vec::new();
    let mut arm = 0;
    let mut testing = true;
    while arm < patterns.len() {
        if testing {
            let mut matched = false;
            for (pattern, glob) in patterns[arm].as_ref()? {
                match (glob, pattern.as_str()) {
                    (false, pattern) => matched |= pattern == subject,
                    (true, "*") => matched = true,
                    (true, _) => return None,
                }
            }
            if !matched {
                arm += 1;
                continue;
            }
        }
        selected.push(arm);
        match terminators[arm] {
            Op::SemiAmp => testing = false,
            Op::DSemiAmp => testing = true,
            _ => break,
        }
        arm += 1;
    }
    Some(selected)
}

pub(crate) fn literal_text(w: &WordTok) -> Option<String> {
    match w.segs.as_slice() {
        [
            Seg::Literal {
                text,
                quoted: false,
            },
        ] => Some(text.clone()),
        _ => None,
    }
}

/// The command name a head word spelled only from literal text looks up after
/// quote removal: `'exec'`, `\exec`, and `e"xec"` all run the `exec` builtin.
/// Quoting such a word suppresses only alias expansion.
pub(crate) fn command_name_text(w: &WordTok) -> Option<String> {
    let mut name = String::new();
    for seg in &w.segs {
        let Seg::Literal { text, .. } = seg else {
            return None;
        };
        name.push_str(text);
    }
    (!name.is_empty()).then_some(name)
}

/// Split NAME=rest (or NAME+=rest) into an assignment when NAME is a valid
/// identifier in an unquoted literal head segment.
pub(crate) fn split_assignment(w: &WordTok) -> Option<Assign> {
    let Some(Seg::Literal {
        text,
        quoted: false,
    }) = w.segs.first()
    else {
        return None;
    };
    let eq = text.find('=')?;
    let (name, append) = match text[..eq].strip_suffix('+') {
        Some(name) => (name, true),
        None => (&text[..eq], false),
    };
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return None;
    }
    let mut value_segs = Vec::new();
    let rest = &text[eq + 1..];
    if !rest.is_empty() {
        value_segs.push(Seg::Literal {
            text: rest.to_string(),
            quoted: false,
        });
    }
    value_segs.extend(w.segs[1..].iter().cloned());
    Some(Assign {
        name: name.to_string(),
        value: WordTok {
            segs: value_segs,
            span: w.span,
        },
        append,
        span: w.span,
    })
}

// Header words bypass command-word evaluation, so retain evidence before discarding them.
fn retain_header_expansion(tok: &Tok, items: &mut Vec<ShellItem>) {
    if let Tok::Word(word) = tok
        && word.segs.iter().any(|seg| {
            matches!(
                seg,
                Seg::CommandSub { .. }
                    | Seg::Param {
                        unwalked_substitution: true,
                        ..
                    }
                    | Seg::UnwalkedParamSub
                    | Seg::Arith { .. }
                    | Seg::ProcSub { .. }
                    | Seg::ArrayLit { .. }
            )
        })
    {
        items.push(ShellItem::UnwalkedExpansion { span: word.span });
    }
}

/// `items` as a body nothing enters unless `head` is redefined.
fn unreachable_body(head: Option<String>, items: Vec<ShellItem>) -> Vec<ShellItem> {
    if items.is_empty() {
        return items;
    }
    vec![ShellItem::Group {
        kind: GroupKind::Unreachable { head },
        items,
    }]
}

/// A loop body whose commands after its first unconditional `break` or
/// `continue` never run. Only a bare stop or one with a single decimal loop
/// count of at least one qualifies: bash runs on past `--help`, zsh past
/// extra operands, and other operands mean different things per shell.
fn loop_body(mut items: Vec<ShellItem>) -> Vec<ShellItem> {
    let stop = items.iter().position(|item| {
        matches!(item, ShellItem::Pipeline { cmds, conditional: false, .. }
        if cmds.len() == 1
            && cmds[0].redirs.is_empty()
            && cmds[0].assignments.is_empty()
            && cmds[0].words.iter().map(literal_text).collect::<Option<Vec<_>>>()
                .is_some_and(|words| match words.as_slice() {
                    [stop] => stop == "break" || stop == "continue",
                    [stop, count] => {
                        (stop == "break" || stop == "continue")
                            && count.bytes().all(|byte| byte.is_ascii_digit())
                            && count.parse::<u32>().is_ok_and(|count| count >= 1)
                    }
                    _ => false,
                }))
    });
    let Some(stop) = stop else {
        return items;
    };
    let tail = items.split_off(stop + 1);
    let ShellItem::Pipeline { cmds, .. } = &items[stop] else {
        unreachable!()
    };
    let head = cmds[0].words.first().and_then(literal_text);
    items.extend(unreachable_body(head, tail));
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_source(source: &str) -> Vec<ShellItem> {
        let output = lex::lex(source);
        assert!(output.error.is_none(), "{:?}", output.error);
        parse_shell_items(&output.toks, source.len() as u32)
    }

    fn word_text(word: &WordTok) -> String {
        word.segs
            .iter()
            .map(|seg| match seg {
                Seg::Literal { text, .. } => text.as_str(),
                _ => panic!("expected literal word"),
            })
            .collect()
    }

    #[test]
    fn heredoc_and_same_line_file_redirect_are_ordered() {
        let items = parse_source("cat <<EOF > /etc/motd\nhi\nEOF");
        let ShellItem::Pipeline { cmds, .. } = &items[0] else {
            panic!("expected pipeline");
        };
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].redirs.len(), 2);
        assert_eq!(cmds[0].redirs[0].kind, RedirKind::HereDoc);
        let heredoc = cmds[0].redirs[0].heredoc.as_ref().unwrap();
        assert_eq!(heredoc.body, "hi\n");
        assert!(!heredoc.quoted);
        assert_eq!(cmds[0].redirs[1].kind, RedirKind::Out);
        assert_eq!(
            word_text(cmds[0].redirs[1].target.as_ref().unwrap()),
            "/etc/motd"
        );
    }

    #[test]
    fn heredoc_before_pipe_keeps_both_stages() {
        let items = parse_source("cat <<EOF | sh\nx\nEOF");
        let ShellItem::Pipeline { cmds, .. } = &items[0] else {
            panic!("expected pipeline");
        };
        assert_eq!(cmds.len(), 2);
        assert_eq!(word_text(&cmds[0].words[0]), "cat");
        assert_eq!(word_text(&cmds[1].words[0]), "sh");
        assert_eq!(cmds[0].redirs[0].kind, RedirKind::HereDoc);
    }

    #[test]
    fn heredoc_body_does_not_change_function_structure() {
        let items = parse_source("f(){ cat <<EOF\n'\nEOF\n}; f");
        assert_eq!(items.len(), 2);
        let ShellItem::Function { body, .. } = &items[0] else {
            panic!("expected function");
        };
        assert!(matches!(body.as_slice(), [ShellItem::Pipeline { .. }]));
        assert!(
            matches!(&items[1], ShellItem::Pipeline { cmds, .. } if word_text(&cmds[0].words[0]) == "f")
        );
    }
}
