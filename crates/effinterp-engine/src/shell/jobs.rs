//! Fork-bomb shape: a loop that provably repeats forever and starts
//! background jobs the shell never reaps, so the number of live processes
//! grows without bound.
//!
//! Every rule keys on the parsed construct, never on a command name a script
//! chose: a constant loop condition, `&`, and the job-control builtins
//! (`wait`, `disown`) that decide whether a started job is reaped. A shape
//! this module cannot read off the tree is inconclusive, not a fork bomb.

use super::parse::{self, GroupKind, ShellItem, Simple};

/// Bound on recursion into nested groups while reading a loop body.
const MAX_DEPTH: u32 = 32;

/// Whether `while`/`until` with this condition and body spawns without bound.
/// `until` inverts the condition's polarity.
pub(crate) fn unbounded_loop(cond: &[ShellItem], body: &[ShellItem], until: bool) -> bool {
    constant_status(cond) == Some(!until) && unbounded_body(body)
}

/// The condition's command head, when the condition is one command. A script
/// can define a function of that name, and then the condition is that body
/// rather than the builtin this module read.
pub(crate) fn condition_head(cond: &[ShellItem]) -> Option<String> {
    let [ShellItem::Pipeline { cmds, .. }] = cond else {
        return None;
    };
    let [cmd] = cmds.as_slice() else {
        return None;
    };
    cmd.words.first().and_then(parse::literal_text)
}

/// Whether a loop body that always repeats spawns background jobs without
/// bound. The caller establishes that the loop itself never terminates.
pub(crate) fn unbounded_body(body: &[ShellItem]) -> bool {
    let mut jobs = Jobs::default();
    scan(body, &mut jobs, 0);
    jobs.unbounded()
}

/// What one pass over a loop body does to this shell's job table.
#[derive(Default)]
struct Jobs {
    /// Job starts and reaps in the order the body performs them.
    events: Vec<Event>,
    /// A started job that no `wait` in this shell can ever reap.
    escaped: bool,
    /// The body leaves the loop, so it runs a bounded number of times.
    leaves: bool,
    /// A construct whose jobs or reaping cannot be read off the shape.
    unknown: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Event {
    Start,
    ReapAll,
    ReapOne,
}

impl Jobs {
    fn unbounded(&self) -> bool {
        // An unread construct may hold the `break` or the `wait` that bounds
        // the loop, so it decides nothing either way.
        if self.leaves || self.unknown {
            return false;
        }
        if self.escaped {
            return true;
        }
        // A no-operand wait empties this shell's running-job table. Otherwise
        // each selective wait can discharge at most one launch per pass.
        !self.events.contains(&Event::ReapAll)
            && self
                .events
                .iter()
                .filter(|event| **event == Event::Start)
                .count()
                > self
                    .events
                    .iter()
                    .filter(|event| **event == Event::ReapOne)
                    .count()
    }

    /// Whether a job this list started is still running when it completes.
    fn leftover(&self) -> bool {
        let mut running = 0usize;
        for event in &self.events {
            match event {
                Event::Start => running += 1,
                Event::ReapAll => running = 0,
                Event::ReapOne => running = running.saturating_sub(1),
            }
        }
        running != 0
    }

    /// Whether this list has anything to say about the job table at all.
    fn relevant(&self) -> bool {
        !self.events.is_empty() || self.escaped || self.leaves || self.unknown
    }
}

fn scan(items: &[ShellItem], jobs: &mut Jobs, depth: u32) {
    if depth >= MAX_DEPTH {
        jobs.unknown = true;
        return;
    }
    for item in items {
        match item {
            ShellItem::Group {
                kind: GroupKind::Background,
                ..
            } => jobs.events.push(Event::Start),
            // A subshell owns the jobs it starts. Ones it leaves running
            // outlive it, and no `wait` in this shell can reach them.
            ShellItem::Group {
                kind: GroupKind::Subshell,
                items,
            } => {
                let mut inner = Jobs::default();
                scan(items, &mut inner, depth + 1);
                jobs.unknown |= inner.unknown;
                jobs.escaped |= inner.escaped || inner.leftover();
            }
            // A brace group runs in this shell; `if` and `case` reach the
            // parser as their condition followed by the arms inside one.
            ShellItem::Group {
                kind: GroupKind::Brace | GroupKind::Redirected,
                items,
            } => scan_alternatives(items, jobs, depth + 1),
            // Loop bodies, short-circuit operands, and pipeline stages run on
            // some paths only, or in shells of their own.
            ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
                jobs.unknown |= probe(items, depth + 1);
            }
            ShellItem::Alternatives { arms, .. } => {
                jobs.unknown |= arms.iter().any(|arm| probe(arm, depth + 1));
            }
            ShellItem::Pipeline {
                cmds, conditional, ..
            } => {
                let Some(builtin) = job_builtin(cmds) else {
                    continue;
                };
                if *conditional {
                    jobs.unknown = true;
                    continue;
                }
                match builtin {
                    JobBuiltin::WaitAll => jobs.events.push(Event::ReapAll),
                    JobBuiltin::WaitOne => jobs.events.push(Event::ReapOne),
                    // The job leaves the table, so no later `wait` reaps it.
                    JobBuiltin::Disown => jobs.escaped |= jobs.leftover(),
                    JobBuiltin::Leave => jobs.leaves = true,
                }
            }
            // A definition starts nothing until it is called.
            ShellItem::Function { .. } => {}
            ShellItem::UnboundedSpawn { .. } => {}
            ShellItem::Unsupported { .. }
            | ShellItem::UnwalkedExpansion { .. }
            | ShellItem::ParseError { .. } => jobs.unknown = true,
        }
    }
}

/// Scan a brace group, resolving a constant `if` condition to the one arm it
/// selects. `if false; then wait; fi` reaps nothing.
fn scan_alternatives(items: &[ShellItem], jobs: &mut Jobs, depth: u32) {
    let Some((ShellItem::Alternatives { arms, .. }, cond)) = items.split_last() else {
        scan(items, jobs, depth);
        return;
    };
    scan(cond, jobs, depth);
    // Two arms are `if COND; then ...; else ...`, in that order.
    let taken = match (constant_status(cond), arms.len()) {
        (Some(true), 2) => Some(0),
        (Some(false), 2) => Some(1),
        _ => None,
    };
    match taken {
        Some(index) => scan(&arms[index], jobs, depth + 1),
        None => jobs.unknown |= arms.iter().any(|arm| probe(arm, depth + 1)),
    }
}

/// Whether a region that runs only on some paths touches the job table.
fn probe(items: &[ShellItem], depth: u32) -> bool {
    let mut jobs = Jobs::default();
    scan(items, &mut jobs, depth);
    jobs.relevant()
}

enum JobBuiltin {
    WaitAll,
    WaitOne,
    Disown,
    Leave,
}

/// The job-control builtin a foreground pipeline runs, if any. Only a single
/// command carries the builtin's effect on this shell's job table.
fn job_builtin(cmds: &[Simple]) -> Option<JobBuiltin> {
    let [cmd] = cmds else {
        return None;
    };
    let head = cmd.words.first().and_then(parse::literal_text)?;
    match head.as_str() {
        "wait" => Some(
            if cmd.words[1..]
                .iter()
                .all(|word| matches!(parse::literal_text(word).as_deref(), Some("-f" | "--")))
            {
                JobBuiltin::WaitAll
            } else {
                JobBuiltin::WaitOne
            },
        ),
        "disown" => Some(JobBuiltin::Disown),
        "break" | "exit" | "return" => Some(JobBuiltin::Leave),
        _ => None,
    }
}

/// The exit status a condition list always produces, when its shape fixes it.
pub(super) fn constant_status(items: &[ShellItem]) -> Option<bool> {
    let [item] = items else {
        return None;
    };
    match item {
        ShellItem::Pipeline {
            cmds,
            conditional: false,
            ..
        } => match cmds.as_slice() {
            [cmd] => command_status(cmd),
            _ => None,
        },
        // `(( EXPR ))` reaches the parser as a doubled subshell around the
        // expression's words.
        ShellItem::Group {
            kind: GroupKind::Subshell,
            items,
        } => match items.as_slice() {
            [
                ShellItem::Group {
                    kind: GroupKind::Subshell,
                    items,
                },
            ] => arithmetic_status(items),
            _ => None,
        },
        _ => None,
    }
}

fn command_status(cmd: &Simple) -> Option<bool> {
    if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
        return None;
    }
    let words = cmd
        .words
        .iter()
        .map(parse::literal_text)
        .collect::<Option<Vec<_>>>()?;
    let (head, rest) = words.split_first()?;
    match head.as_str() {
        "true" | ":" | "/bin/true" | "/usr/bin/true" if rest.is_empty() => Some(true),
        "false" | "/bin/false" | "/usr/bin/false" if rest.is_empty() => Some(false),
        // A one-operand test is a string test: true when the string is not
        // empty. The parser drops `[[`'s closing word.
        "[" => match rest {
            [operand, closer] if closer == "]" => Some(!operand.is_empty()),
            _ => None,
        },
        "[[" => match rest {
            [operand] => Some(!operand.is_empty()),
            _ => None,
        },
        _ => None,
    }
}

/// The status of `(( EXPR ))` when EXPR is a literal integer.
fn arithmetic_status(items: &[ShellItem]) -> Option<bool> {
    let [
        ShellItem::Pipeline {
            cmds,
            conditional: false,
            ..
        },
    ] = items
    else {
        return None;
    };
    let [cmd] = cmds.as_slice() else {
        return None;
    };
    if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
        return None;
    }
    let [word] = cmd.words.as_slice() else {
        return None;
    };
    Some(parse::literal_text(word)?.parse::<i64>().ok()? != 0)
}

/// A cycle through these bodies cannot terminate by changing a predicate or
/// redefining a function. A dynamic branch keeps only the ordinary cycle boundary.
pub(super) fn invariant_recursion(items: &[ShellItem], in_cycle: &dyn Fn(&str) -> bool) -> bool {
    fn scan(items: &[ShellItem], depth: u32, in_cycle: &dyn Fn(&str) -> bool) -> bool {
        depth < MAX_DEPTH
            && items.iter().enumerate().all(|(index, item)| {
                // A synchronous recursive call may never return to launch a
                // later job. Only background lists can precede another item.
                (index + 1 == items.len()
                    || matches!(
                        item,
                        ShellItem::Group {
                            kind: GroupKind::Background,
                            ..
                        }
                    ))
                    && match item {
                        ShellItem::Pipeline {
                            cmds,
                            conditional: false,
                            ..
                        } => cmds.iter().all(|cmd| {
                            cmd.assignments.is_empty()
                                && cmd.redirs.is_empty()
                                && cmd
                                    .words
                                    .iter()
                                    .all(|word| parse::literal_text(word).is_some())
                                && cmd
                                    .words
                                    .first()
                                    .and_then(parse::literal_text)
                                    .is_some_and(|name| in_cycle(&name))
                        }),
                        ShellItem::Group {
                            kind:
                                GroupKind::Brace
                                | GroupKind::Redirected
                                | GroupKind::Background
                                | GroupKind::Coprocess { .. },
                            items,
                        } => scan(items, depth + 1, in_cycle),
                        _ => false,
                    }
            })
    }
    scan(items, 0, in_cycle)
}
