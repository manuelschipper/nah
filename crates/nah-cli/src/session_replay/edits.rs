//! What a call's writes change, for the facts export's `edits`. A write
//! whose resulting bytes the plan states (a Write, an Edit or patch whose
//! old text the engine matched, an append, a literal `sed -i`
//! substitution) is compared line by line with what the file held before
//! it; an in-place sed edit by line number, whose result the engine does
//! not compute, states the lines its addresses reach and the lines around
//! them.

use std::collections::{BTreeMap, BTreeSet};

use nah_proto::effinterp_proto::{
    AttrValue, OsDialect, Plan, ResourceExpr, ResourceIdentity, Subject,
};
use serde::Serialize;

/// The most lines two versions may differ by for their changes to be
/// stated; past it the edit says its changes are unresolved.
const MAX_DIFF_DISTANCE: usize = 1000;
/// Lines an address reaches that are stated, of a longer range.
const MAX_LANDED_LINES: usize = 16;
/// A stated line's text past this is cut.
const MAX_LINE_BYTES: usize = 256;

/// What a file held before a write, as the supplied state declares it.
pub(super) enum Prior {
    Known(String),
    Absent,
    Unobserved,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum PriorState {
    Known,
    Absent,
    Unobserved,
    /// An earlier write of this call leaves content the plan does not state.
    Unstated,
}

#[derive(Serialize)]
pub(super) struct Edit {
    effect: usize,
    path: String,
    prior: PriorState,
    /// Each run of changed lines, where the content before the write is
    /// known or absent and the plan states the content it leaves.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<Hunk>>,
    /// `beyond_bound` where the versions differ by more than
    /// [`MAX_DIFF_DISTANCE`] lines, so no run is stated.
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved: Option<&'static str>,
    /// For a sed edit by line number over known content, each command's
    /// address.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addressed: Vec<Addressed>,
}

/// One run of changed lines: `added`, `removed` or `replaced`.
#[derive(Serialize)]
struct Hunk {
    change: &'static str,
    old: Span,
    new: Span,
}

/// Where a run sits in one version: its first line, from 1, and how many
/// lines it has there. An empty run's line is the one that follows it.
#[derive(Serialize)]
struct Span {
    line: usize,
    count: usize,
}

/// One sed command's address over the file before the edit.
#[derive(Serialize)]
struct Addressed {
    command: char,
    /// The first and last line it addresses as written, `$` taken as the
    /// file's last.
    first: u64,
    last: u64,
    /// How many lines the command runs on: those of its range in the file,
    /// less those an earlier `d` or `c` of the script already ended.
    reached: usize,
    /// The first of those lines, at most [`MAX_LANDED_LINES`].
    lands_on: Vec<Line>,
    /// The line before the range and the line after it, which enclose it.
    before: Option<Line>,
    after: Option<Line>,
}

#[derive(Serialize)]
struct Line {
    line: usize,
    text: String,
}

/// The edits of `plan`, with `prior` answering what a path held before
/// the call, and the text each write would put in its file, by path, for
/// the session record once the file shows it: a write's stated bytes, an
/// Edit's new text, or the lines an in-place edit changed.
pub(super) fn edits(
    plan: &Plan,
    prior: &dyn Fn(&str) -> Prior,
) -> (Vec<Edit>, Vec<(String, String)>) {
    // What each path holds after this call's earlier writes; `None` where a
    // write left it unstated.
    let mut held: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut edits = Vec::new();
    let mut written = Vec::new();
    for (index, effect) in plan.effects.iter().enumerate() {
        if !matches!(
            effect.operation.as_str(),
            "filesystem.write" | "filesystem.create"
        ) {
            continue;
        }
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &effect.resource
        else {
            continue;
        };
        let text = |name: &str| match effect.attributes.get(name) {
            Some(AttrValue::String(value)) => Some(value.as_str()),
            _ => None,
        };
        let flag = |name: &str| matches!(effect.attributes.get(name), Some(AttrValue::Bool(true)));
        let (before, state) = match held.get(path) {
            Some(Some(content)) => (Prior::Known(content.clone()), PriorState::Known),
            Some(None) => (Prior::Unobserved, PriorState::Unstated),
            None => {
                let before = prior(path);
                let state = match before {
                    Prior::Known(_) => PriorState::Known,
                    Prior::Absent => PriorState::Absent,
                    Prior::Unobserved => PriorState::Unobserved,
                };
                (before, state)
            }
        };
        let old = match &before {
            Prior::Known(content) => Some(content.as_str()),
            Prior::Absent => Some(""),
            Prior::Unobserved => None,
        };
        // An in-place write's `written_content` is only its new fragment,
        // whose place the engine found only where it states the result.
        let content = match (text("resulting_content"), text("written_content")) {
            (Some(content), _) => Some(content.to_owned()),
            (None, Some(_)) if flag("in_place") => None,
            (None, Some(added)) if flag("append") => old.map(|old| format!("{old}{added}")),
            (None, Some(content)) => Some(content.to_owned()),
            (None, None) => None,
        };
        let mut edit = Edit {
            effect: index,
            path: path.clone(),
            prior: state,
            changes: None,
            unresolved: None,
            addressed: Vec::new(),
        };
        if let Some(added) = text("written_content") {
            written.push((path.clone(), added.to_owned()));
        }
        if let Some(content) = &content {
            if let Some(old) = old {
                match hunks(old, content) {
                    Some(changes) => {
                        if text("written_content").is_none() {
                            written.extend(
                                new_lines(&changes, content).map(|line| (path.clone(), line)),
                            );
                        }
                        edit.changes = Some(changes);
                    }
                    None => edit.unresolved = Some("beyond_bound"),
                }
            }
            edits.push(edit);
        } else if flag("in_place")
            && let Some(lines) = sed_edits(plan, effect.execution.0 as usize)
        {
            if let Prior::Known(old) = &before {
                edit.addressed = addressed(&lines, old);
            }
            edits.push(edit);
        }
        held.insert(path.clone(), content);
    }
    (edits, written)
}

/// The line edits of the sed that runs at `node`, when its whole argv is
/// literal and every way the plan's host can read it agrees.
fn sed_edits(plan: &Plan, node: usize) -> Option<Vec<nah_effinterp::SedLineEdit>> {
    let argv = plan
        .execution_graph
        .nodes
        .get(node)?
        .argv
        .iter()
        .map(|word| match word {
            ResourceExpr::Literal { value } => Some(value.as_str()),
            _ => None,
        })
        .collect::<Option<Vec<&str>>>()?;
    let program = argv.first()?.rsplit('/').next()?;
    // The host the plan was made for, which chooses how sed reads its argv.
    let dialect = match &plan.subject {
        Subject::Exec { context, .. }
        | Subject::Shell { context, .. }
        | Subject::Source { context, .. }
        | Subject::ToolCall { context, .. } => context.os_dialect,
        Subject::Sql { .. } => OsDialect::Unknown,
    };
    (program == "sed")
        .then(|| nah_effinterp::sed_line_edits(&argv, dialect))
        .flatten()
}

/// Each command's address over `old`. A `d` or `c` ends the cycle of the
/// lines it covers, so later commands of the script never run on them.
fn addressed(edits: &[nah_effinterp::SedLineEdit], old: &str) -> Vec<Addressed> {
    let lines: Vec<&str> = old.split_inclusive('\n').collect();
    let count = lines.len() as u64;
    let line = |number: u64| {
        let text = lines.get(usize::try_from(number.checked_sub(1)?).ok()?)?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        let mut end = text.len().min(MAX_LINE_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Some(Line {
            line: number as usize,
            text: text[..end].to_owned(),
        })
    };
    let mut ended: BTreeSet<u64> = BTreeSet::new();
    edits
        .iter()
        .map(|edit| {
            let first = edit.first.unwrap_or(count);
            // A range ending before it starts addresses its first line alone.
            let last = edit.last.unwrap_or(count).max(first);
            let reached: Vec<u64> = (first..=last.min(count))
                .filter(|number| !ended.contains(number))
                .collect();
            if matches!(edit.command, 'd' | 'c') {
                ended.extend(&reached);
            }
            Addressed {
                command: edit.command,
                first,
                last,
                reached: reached.len(),
                lands_on: reached
                    .iter()
                    .take(MAX_LANDED_LINES)
                    .filter_map(|number| line(*number))
                    .collect(),
                before: line(first.saturating_sub(1)),
                after: last.checked_add(1).and_then(line),
            }
        })
        .collect()
}

/// The runs of lines that differ between `old` and `new`; `None` where they
/// differ by more than [`MAX_DIFF_DISTANCE`] lines.
fn hunks(old: &str, new: &str) -> Option<Vec<Hunk>> {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let mut hunks = Vec::new();
    let (mut i, mut j) = (0, 0);
    for (x, y) in matched(&a, &b)?.into_iter().chain([(a.len(), b.len())]) {
        if x > i || y > j {
            hunks.push(Hunk {
                change: match (x - i, y - j) {
                    (0, _) => "added",
                    (_, 0) => "removed",
                    _ => "replaced",
                },
                old: Span {
                    line: i + 1,
                    count: x - i,
                },
                new: Span {
                    line: j + 1,
                    count: y - j,
                },
            });
        }
        (i, j) = (x + 1, y + 1);
    }
    Some(hunks)
}

/// The pairs of lines a shortest edit script between `a` and `b` keeps, in
/// order (Myers' greedy algorithm); `None` when the script needs more than
/// [`MAX_DIFF_DISTANCE`] inserted and removed lines.
fn matched(a: &[&str], b: &[&str]) -> Option<Vec<(usize, usize)>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let limit = MAX_DIFF_DISTANCE.min(a.len() + b.len()) as isize;
    let offset = limit + 1;
    // `furthest[k + offset]`: how far along `a` the furthest path on
    // diagonal `k` reaches; one copy per distance, to walk back.
    let mut furthest = vec![0isize; 2 * offset as usize + 1];
    let mut trace = Vec::new();
    for distance in 0..=limit {
        trace.push(furthest.clone());
        for diagonal in (-distance..=distance).step_by(2) {
            let at = (diagonal + offset) as usize;
            let mut x = if diagonal == -distance
                || diagonal != distance && furthest[at - 1] < furthest[at + 1]
            {
                furthest[at + 1]
            } else {
                furthest[at - 1] + 1
            };
            let mut y = x - diagonal;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            furthest[at] = x;
            if x >= n && y >= m {
                return Some(walk_back(&trace, distance, offset, (n, m)));
            }
        }
    }
    None
}

/// The kept pairs of the path that reached `end` at `distance`, walking
/// back each distance's step and the diagonal run after it.
fn walk_back(
    trace: &[Vec<isize>],
    distance: isize,
    offset: isize,
    end: (isize, isize),
) -> Vec<(usize, usize)> {
    let (mut x, mut y) = end;
    let mut pairs = Vec::new();
    for distance in (0..=distance).rev() {
        let at = |diagonal: isize| trace[distance as usize][(diagonal + offset) as usize];
        let diagonal = x - y;
        let previous = if diagonal == -distance
            || diagonal != distance && at(diagonal - 1) < at(diagonal + 1)
        {
            diagonal + 1
        } else {
            diagonal - 1
        };
        let start_x = at(previous);
        let start_y = start_x - previous;
        while x > start_x && y > start_y {
            x -= 1;
            y -= 1;
            pairs.push((x as usize, y as usize));
        }
        (x, y) = (start_x, start_y);
    }
    pairs.reverse();
    pairs
}

/// The lines `changes` put in `content`.
fn new_lines<'c>(changes: &'c [Hunk], content: &'c str) -> impl Iterator<Item = String> + 'c {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    changes.iter().flat_map(move |hunk| {
        lines[hunk.new.line - 1..hunk.new.line - 1 + hunk.new.count]
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
    })
}
