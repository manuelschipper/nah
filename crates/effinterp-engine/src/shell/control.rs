//! A shell callable's effect-directed control flow.
//!
//! Every path carries the status of the last command it ran, because a
//! script completes successfully exactly when that status is zero, and
//! `&&`, `||`, and `if` select paths by it. A command's attempt is reached on
//! both of its outcomes; only its successful outcome continues on the `ok`
//! frontier.

use crate::control_flow::{ControlExit, Frontier, Graph, Jump};

use super::lex::Span;
use super::parse::{self, GroupKind, ShellItem, Simple};

/// The live paths after a construct, split by the status they carry.
#[derive(Clone, Copy, Default)]
struct Status {
    ok: Frontier,
    fail: Frontier,
}

/// What the graph describes: a script completes the invocation, a function
/// returns to its caller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Callable {
    Script,
    Function,
}

struct Builder<'a, 'g> {
    graph: &'g mut Graph,
    source: &'a str,
    callable: Callable,
    is_function: &'a dyn Fn(&str) -> bool,
    /// Enclosing loops visible from here; a subshell hides its parent's.
    loops: Vec<String>,
    /// `exit` inside a subshell only completes the subshell.
    subshells: Vec<(Vec<Frontier>, Vec<Frontier>)>,
}

/// Build the graph for `items`, parsed from `source`.
pub(super) fn build(
    graph: &mut Graph,
    source: &str,
    items: &[ShellItem],
    callable: Callable,
    is_function: &dyn Fn(&str) -> bool,
) {
    if items.iter().any(rewrites_control) {
        // Sourcing, eval, traps, and computed command names can define or run
        // code this graph cannot see at any later command.
        graph.widen();
        return;
    }
    let entry = graph.entry();
    let mut builder = Builder {
        graph,
        source,
        callable,
        is_function,
        loops: Vec::new(),
        subshells: Vec::new(),
    };
    let end = builder.items(
        Status {
            ok: entry,
            fail: None,
        },
        items,
    );
    builder.graph.exit(end.ok, ControlExit::Success);
    builder.graph.exit(end.fail, ControlExit::Failure);
}

fn head(cmd: &Simple) -> Option<(usize, Option<String>)> {
    let mut index = 0;
    while let Some(word) = cmd.words.get(index) {
        match parse::literal_text(word).as_deref() {
            Some("command" | "builtin" | "time" | "!") => index += 1,
            Some("-p" | "--") if index > 0 => index += 1,
            text => return Some((index, text.map(str::to_string))),
        }
    }
    None
}

fn rewrites_control(item: &ShellItem) -> bool {
    match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().any(|cmd| match head(cmd) {
            Some((_, Some(name))) => matches!(
                name.as_str(),
                "source" | "." | "eval" | "trap" | "command_not_found_handle"
            ),
            Some((_, None)) => true,
            None => false,
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            items.iter().any(rewrites_control)
        }
        ShellItem::Alternatives { arms, .. } => arms.iter().flatten().any(rewrites_control),
        ShellItem::Function { name, .. } => name == "command_not_found_handle",
        ShellItem::Unsupported { .. }
        | ShellItem::UnboundedSpawn { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    }
}

impl Builder<'_, '_> {
    fn join(&mut self, frontiers: &[Frontier]) -> Frontier {
        self.graph.join(frontiers)
    }

    fn items(&mut self, mut status: Status, items: &[ShellItem]) -> Status {
        if !self.graph.enter() {
            return Status::default();
        }
        let mut index = 0;
        while index < items.len() {
            // A trailing `&` backgrounds the whole `&&`/`||` list before it.
            let mut end = index;
            while items.get(end + 1).is_some_and(continues_list) {
                end += 1;
            }
            let background = parse::items_span(&items[index..=end])
                .is_some_and(|span| self.background(span.end))
                && !matches!(items[end], ShellItem::Function { .. });
            if background {
                // A job's interactions may happen after the script completes.
                status = Status {
                    ok: self.join(&[status.ok, status.fail]),
                    fail: None,
                };
            } else {
                for item in &items[index..=end] {
                    status = self.item(status, item);
                }
            }
            index = end + 1;
        }
        self.graph.leave();
        status
    }

    /// Whether the construct ending at `end` runs as a background job. Only
    /// separators and closing words may sit between it and the `&`; a false
    /// positive only makes a job optional.
    fn background(&self, end: u32) -> bool {
        let mut rest = self.source.get(end as usize..).unwrap_or_default();
        loop {
            let trimmed = rest.trim_start_matches([' ', '\t', '\n', ';', ')', '}']);
            let word = ["fi", "done", "esac"].into_iter().find(|word| {
                trimmed.starts_with(word)
                    && !trimmed[word.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
            });
            match word {
                Some(word) => rest = &trimmed[word.len()..],
                None => {
                    return trimmed.starts_with('&') && !trimmed[1..].starts_with(['&', '>']);
                }
            }
        }
    }

    fn item(&mut self, status: Status, item: &ShellItem) -> Status {
        let everything = self.join(&[status.ok, status.fail]);
        match item {
            ShellItem::Pipeline {
                cmds,
                conditional,
                short_circuit,
            } => {
                let (run, bypass) = select(status, *conditional, *short_circuit);
                let ran = self.pipeline(run, cmds);
                merge(self, ran, bypass)
            }
            ShellItem::Group { kind, items } => match kind {
                GroupKind::Brace | GroupKind::Redirected => self.items(status, items),
                GroupKind::Subshell => {
                    let loops = std::mem::take(&mut self.loops);
                    self.subshells.push((Vec::new(), Vec::new()));
                    let inner = self.items(status, items);
                    let (ok, fail) = self.subshells.pop().unwrap();
                    self.loops = loops;
                    let ok = self.join(&[&[inner.ok][..], &ok].concat());
                    let fail = self.join(&[&[inner.fail][..], &fail].concat());
                    Status { ok, fail }
                }
                // Background and compound-pipeline stages run concurrently in
                // their own shells: nothing inside them is ordered before what
                // follows, and their status does not gate it.
                GroupKind::Background
                | GroupKind::CompoundPipeline
                | GroupKind::Coprocess { .. } => status,
                GroupKind::Conditional { .. } | GroupKind::Unreachable { .. } => {
                    self.repeat(everything, items)
                }
                GroupKind::ShortCircuit(selection) => {
                    let (run, bypass) = select(status, true, *selection);
                    let ran = self.items(run, items);
                    merge(self, ran, bypass)
                }
            },
            ShellItem::For { items, .. } => self.repeat(everything, items),
            ShellItem::Alternatives { group, arms, .. } => {
                let selects_status = arms.len() == 2
                    && self
                        .source
                        .get(*group as usize..)
                        .is_some_and(|text| text.starts_with("if") || text.starts_with("elif"));
                let mut ok = Vec::new();
                let mut fail = Vec::new();
                for (index, arm) in arms.iter().enumerate() {
                    let entry = match (selects_status, index) {
                        (true, 0) => status.ok,
                        (true, _) => status.fail,
                        (false, _) => everything,
                    };
                    let arm_status = if arm.is_empty() {
                        // No command ran in the arm: the construct's status is zero.
                        Status {
                            ok: entry,
                            fail: None,
                        }
                    } else {
                        self.items(
                            Status {
                                ok: entry,
                                fail: None,
                            },
                            arm,
                        )
                    };
                    ok.push(arm_status.ok);
                    fail.push(arm_status.fail);
                }
                Status {
                    ok: self.join(&ok),
                    fail: self.join(&fail),
                }
            }
            // The loop's own repetition; it runs no command of its own.
            ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => status,
            ShellItem::Unsupported { .. }
            | ShellItem::UnwalkedExpansion { .. }
            | ShellItem::ParseError { .. } => {
                self.graph.unknown(everything);
                Status {
                    ok: everything,
                    fail: everything,
                }
            }
        }
    }

    /// A loop body runs zero or more times.
    fn repeat(&mut self, entry: Frontier, items: &[ShellItem]) -> Status {
        let header = self.graph.header(entry);
        let label = format!("{}", self.loops.len());
        self.loops.push(label.clone());
        self.graph.push_loop(Some(label), true);
        let body = self.items(
            Status {
                ok: header,
                fail: header,
            },
            items,
        );
        let (breaks, continues) = self.graph.pop_loop();
        self.loops.pop();
        let back = self.join(
            &[body.ok, body.fail]
                .into_iter()
                .chain(continues.into_iter().map(Some))
                .collect::<Vec<_>>(),
        );
        self.graph.backedge(back, header);
        let exit = self.join(
            &std::iter::once(header)
                .chain(breaks.into_iter().map(Some))
                .collect::<Vec<_>>(),
        );
        Status {
            ok: exit,
            fail: exit,
        }
    }

    fn pipeline(&mut self, status: Status, cmds: &[Simple]) -> Status {
        match cmds {
            [cmd] => self.command(status, cmd),
            _ => {
                // Each element runs in its own subshell; the last one's
                // status is the pipeline's.
                let mut at = self.join(&[status.ok, status.fail]);
                for cmd in &cmds[..cmds.len() - 1] {
                    at = self.graph.site(at, span(cmd.span), false);
                }
                let last = cmds.last().unwrap();
                let attempt = self.graph.site(at, span(last.span), false);
                Status {
                    ok: self.graph.success(attempt, span(last.span)),
                    fail: attempt,
                }
            }
        }
    }

    fn argument(&self, cmd: &Simple, index: usize) -> Option<Option<String>> {
        cmd.words.get(index).map(parse::literal_text)
    }

    fn complete(&mut self, status: Status, argument: Option<Option<String>>, returning: bool) {
        // `exit`/`return` without an operand keep the last status.
        let (ok, fail) = match argument {
            None => (status.ok, status.fail),
            Some(Some(code)) if code == "0" => (self.join(&[status.ok, status.fail]), None),
            Some(Some(code)) if code.parse::<u8>().is_ok() => {
                (None, self.join(&[status.ok, status.fail]))
            }
            Some(_) => {
                let everything = self.join(&[status.ok, status.fail]);
                (everything, everything)
            }
        };
        if let Some((subshell_ok, subshell_fail)) = self.subshells.last_mut()
            && !returning
        {
            subshell_ok.push(ok);
            subshell_fail.push(fail);
            return;
        }
        match (self.callable, returning) {
            (Callable::Function, true) => {
                self.graph.jump(ok, Jump::Return);
                self.graph.exit(fail, ControlExit::Failure);
            }
            (Callable::Script, false) => {
                self.graph.exit(ok, ControlExit::Success);
                self.graph.exit(fail, ControlExit::Failure);
            }
            // The whole shell completes from inside a function; its caller
            // does not continue on a failing exit.
            (Callable::Function, false) => self.graph.unknown(ok),
            // `return` outside a function is an error that continues.
            (Callable::Script, true) => unreachable!("handled by the caller"),
        }
    }

    fn command(&mut self, status: Status, cmd: &Simple) -> Status {
        let everything = self.join(&[status.ok, status.fail]);
        let Some((index, name)) = head(cmd) else {
            let attempt = self.graph.site(everything, span(cmd.span), false);
            return Status {
                ok: self.graph.success(attempt, span(cmd.span)),
                fail: attempt,
            };
        };
        let name = name.unwrap_or_default();
        match name.as_str() {
            "exit" => {
                self.complete(status, self.argument(cmd, index + 1), false);
                Status::default()
            }
            "return" if self.callable == Callable::Function || !self.subshells.is_empty() => {
                if self.subshells.is_empty() {
                    self.complete(status, self.argument(cmd, index + 1), true);
                } else {
                    // `return` in a function's subshell completes the subshell.
                    self.complete(status, self.argument(cmd, index + 1), false);
                }
                Status::default()
            }
            "return" => {
                self.graph.unknown(everything);
                Status {
                    ok: None,
                    fail: everything,
                }
            }
            "break" | "continue" => {
                let levels = match self.argument(cmd, index + 1) {
                    None => Some(1),
                    Some(Some(text)) => text.parse::<usize>().ok().filter(|levels| *levels > 0),
                    Some(None) => None,
                };
                match levels {
                    Some(levels) if !self.loops.is_empty() => {
                        let target = self.loops[self.loops.len().saturating_sub(levels)].clone();
                        let jump = if name == "break" {
                            Jump::Break(Some(target))
                        } else {
                            Jump::Continue(Some(target))
                        };
                        self.graph.jump(everything, jump);
                        Status::default()
                    }
                    Some(_) => Status {
                        ok: everything,
                        fail: None,
                    },
                    None => {
                        self.graph.unknown(everything);
                        Status::default()
                    }
                }
            }
            "exec" if cmd.words.len() > index + 1 => {
                // The replacement's completion is the shell's completion.
                let attempt = self.graph.site(everything, span(cmd.span), false);
                let ok = self.graph.success(attempt, span(cmd.span));
                if self.subshells.is_empty() {
                    match self.callable {
                        Callable::Script => {
                            self.graph.exit(ok, ControlExit::Success);
                            self.graph.exit(attempt, ControlExit::Failure);
                        }
                        Callable::Function => self.graph.unknown(ok),
                    }
                } else {
                    let (subshell_ok, subshell_fail) = self.subshells.last_mut().unwrap();
                    subshell_ok.push(ok);
                    subshell_fail.push(attempt);
                }
                Status::default()
            }
            _ => {
                let attempt =
                    self.graph
                        .site(everything, span(cmd.span), (self.is_function)(&name));
                let ok = self.graph.success(attempt, span(cmd.span));
                match name.as_str() {
                    ":" | "true" if index == 0 => Status {
                        ok: attempt,
                        fail: None,
                    },
                    "false" if index == 0 => Status {
                        ok: None,
                        fail: attempt,
                    },
                    _ if index > 0 => Status {
                        // Negation and wrappers may change the status.
                        ok: self.join(&[ok, attempt]),
                        fail: attempt,
                    },
                    _ => Status { ok, fail: attempt },
                }
            }
        }
    }
}

fn continues_list(item: &ShellItem) -> bool {
    matches!(
        item,
        ShellItem::Pipeline {
            conditional: true,
            ..
        } | ShellItem::Group {
            kind: GroupKind::ShortCircuit(_),
            ..
        }
    )
}

fn span(span: Span) -> (u32, u32) {
    (span.start, span.end)
}

/// Where a `&&`/`||` operand runs from, and the paths that skip it.
fn select(status: Status, conditional: bool, selection: Option<(Span, bool)>) -> (Status, Status) {
    match (conditional, selection) {
        (false, _) => (status, Status::default()),
        (true, Some((_, true))) => (
            Status {
                ok: status.ok,
                fail: None,
            },
            Status {
                ok: None,
                fail: status.fail,
            },
        ),
        (true, Some((_, false))) => (
            Status {
                ok: None,
                fail: status.fail,
            },
            Status {
                ok: status.ok,
                fail: None,
            },
        ),
        (true, None) => (status, status),
    }
}

fn merge(builder: &mut Builder<'_, '_>, left: Status, right: Status) -> Status {
    Status {
        ok: builder.join(&[left.ok, right.ok]),
        fail: builder.join(&[left.fail, right.fail]),
    }
}
