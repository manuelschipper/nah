//! git ref updates and deletions: `git branch`, `git tag` and
//! `git update-ref`, with the transaction `update-ref --stdin` reads.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, attrs};

use super::git_options::{git_controls_known, git_options, parsed_effective_flag};
use super::git_recovery::{STASH_REF, stash_destroyed};
use super::{SubCtx, request_attrs, unmodeled_subcommand_boundary};

/// `git branch` and `git tag` outside their read forms update a ref;
/// with `-d`, `-D` or `--delete` each operand is a ref delete request.
pub(super) fn branch_or_tag(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[],
            known_flags: if sub == "branch" {
                // Listing and remote-tracking selection leave a
                // deletion a deletion, and may share its cluster
                // (`-vrd`).
                &[
                    "-d",
                    "-D",
                    "--delete",
                    "--no-delete",
                    "-f",
                    "--force",
                    "--no-force",
                    "-r",
                    "--remotes",
                    "-v",
                    "--verbose",
                    "-q",
                    "--quiet",
                ]
            } else {
                &[
                    "-d",
                    "-D",
                    "--delete",
                    "--no-delete",
                    "-f",
                    "--force",
                    "--no-force",
                ]
            },
            allow_abbreviation: true,
        },
    );
    let delete = parsed_effective_flag(&parsed, &["-d", "-D", "--delete"], &["--no-delete"]);
    let a = attrs(&[
        ("delete", delete),
        (
            "force",
            parsed_effective_flag(&parsed, &["-D", "-f", "--force"], &["--no-force"]),
        ),
    ]);
    if delete {
        for (_, word) in s.operands(false) {
            let mut a = a.clone();
            if let Some(name) = word.as_literal() {
                a.insert("ref".into(), AttrValue::String(name.into()));
                if git_controls_known(&parsed) {
                    let mut request = request_attrs(&[(
                        "force",
                        matches!(a.get("force"), Some(AttrValue::Bool(true))),
                    )]);
                    request.insert("ref".into(), AttrValue::String(name.into()));
                    request.insert("delete".into(), AttrValue::Bool(true));
                    request.insert("scope".into(), AttrValue::String("selected".into()));
                    request.insert("broad".into(), AttrValue::Bool(false));
                    s.request_effect(builder, "git.ref_delete_request", request);
                }
            }
            s.repo_effect(builder, "git.ref_update", a);
        }
    } else {
        s.repo_effect(builder, "git.ref_update", a);
    }
}

/// `git update-ref [-d] <ref> ...` updates or deletes one ref. Deleting
/// `refs/stash` destroys every stash.
pub(super) fn update_ref(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[],
            known_flags: &["-d", "--no-deref", "--no-create-reflog"],
            allow_abbreviation: true,
        },
    );
    let delete = parsed.has(&["-d"]);
    let mut a = attrs(&[("delete", delete)]);
    if let Some(name) = s.operands(false).first().and_then(|(_, w)| w.as_literal()) {
        a.insert("ref".into(), AttrValue::String(name.into()));
        // An optional old value only makes the deletion conditional.
        if delete
            && name == STASH_REF
            && git_controls_known(&parsed)
            && s.operands(false).len() <= 2
        {
            stash_destroyed(builder, s);
        }
        if delete && git_controls_known(&parsed) && s.operands(false).len() == 1 {
            let mut request = request_attrs(&[("delete", true)]);
            request.insert("ref".into(), AttrValue::String(name.into()));
            request.insert("target_complete".into(), AttrValue::Bool(true));
            request.insert("scope".into(), AttrValue::String("selected".into()));
            request.insert("broad".into(), AttrValue::Bool(false));
            s.request_effect(builder, "git.ref_delete_request", request);
        }
    }
    s.repo_effect(builder, "git.ref_update", a);
}

/// `git update-ref --stdin` reads one command per line (git-update-ref(1)).
/// Ref commands and `option no-deref` queue into a transaction. Without
/// `start`, the end of input commits it; after `start`, only `commit` does,
/// and `abort` or the end of input discards it. After `prepare` only
/// `commit` or `abort` may follow, and after either of those only `start`.
/// A transaction's effects are planned when it commits, so nothing later
/// takes them back. git dies at a line every supported release refuses,
/// discarding the open transaction. A line the model does not classify (a
/// verb such as the `symref-*` family that only some releases accept, a
/// quoted non-UTF-8 name) ends what the model reads: it adds the
/// unmodeled-subcommand boundary and asserts nothing about the open
/// transaction or the lines after it. Returns false, leaving the whole input
/// to that boundary, only for input or options the model cannot read at all
/// (`-z`, dynamic input).
pub(super) fn update_ref_stdin(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum UpdateRefTransactionState {
        Open,
        Started,
        Prepared,
        Closed,
    }
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-m"],
            known_flags: &["--stdin", "--no-deref", "--create-reflog"],
            allow_abbreviation: true,
        },
    );
    let Some(input) = s.ctx.stdin_literal() else {
        return false;
    };
    if !git_controls_known(&parsed) || !parsed.operands.is_empty() {
        return false;
    }
    // Only a full-length run of zeros, or an empty value, is the null object
    // ID; a shorter run is an object name git resolves (`refs/heads/0`).
    let null_oid = |value: &str| {
        value.is_empty() || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte == b'0')
    };
    let commit = |builder: &mut PlanBuilder, queued: &mut Vec<(&str, String, bool)>| {
        for (verb, name, delete) in queued.drain(..) {
            if verb == "verify" {
                s.repo_effect(builder, "git.read", Attrs::new());
                continue;
            }
            let mut a = attrs(&[("delete", delete)]);
            a.insert("ref".into(), AttrValue::String(name.clone()));
            s.repo_effect(builder, "git.ref_update", a);
            if delete {
                let mut request = request_attrs(&[("delete", true)]);
                request.insert("ref".into(), AttrValue::String(name.clone()));
                request.insert("target_complete".into(), AttrValue::Bool(true));
                request.insert("scope".into(), AttrValue::String("selected".into()));
                request.insert("broad".into(), AttrValue::Bool(false));
                s.request_effect(builder, "git.ref_delete_request", request);
                if name == STASH_REF {
                    stash_destroyed(builder, s);
                }
            }
        }
    };
    let mut state = UpdateRefTransactionState::Open;
    let mut queued: Vec<(&str, String, bool)> = Vec::new();
    let mut unread = None;
    let mut died = false;
    for (number, line) in input.lines().enumerate() {
        let (verb, arguments) = match line.split_once(' ') {
            Some((verb, rest)) => match update_ref_arguments(rest) {
                Some(Ok(arguments)) => (verb, arguments),
                Some(Err(())) => {
                    died = true;
                    break;
                }
                None => {
                    unread = Some(number + 1);
                    break;
                }
            },
            None => (line, Vec::new()),
        };
        let next = match verb {
            // `option` takes only `no-deref`, and only where a ref command
            // may appear.
            "option" => (line == "option no-deref"
                && matches!(
                    state,
                    UpdateRefTransactionState::Open | UpdateRefTransactionState::Started
                ))
            .then_some(state),
            "start" | "prepare" | "commit" | "abort" if !arguments.is_empty() => None,
            "start" => matches!(
                state,
                UpdateRefTransactionState::Open | UpdateRefTransactionState::Closed
            )
            .then_some(UpdateRefTransactionState::Started),
            "prepare" => matches!(
                state,
                UpdateRefTransactionState::Open | UpdateRefTransactionState::Started
            )
            .then_some(UpdateRefTransactionState::Prepared),
            "commit" | "abort" if state == UpdateRefTransactionState::Closed => None,
            "commit" => {
                commit(builder, &mut queued);
                Some(UpdateRefTransactionState::Closed)
            }
            "abort" => {
                queued.clear();
                Some(UpdateRefTransactionState::Closed)
            }
            "update" | "create" | "delete" | "verify"
                if matches!(
                    state,
                    UpdateRefTransactionState::Open | UpdateRefTransactionState::Started
                ) =>
            {
                let arity = match verb {
                    "update" => 2..=3,
                    "create" => 2..=2,
                    _ => 1..=2,
                };
                let (name, values) = match arguments.split_first() {
                    Some((name, values)) if arity.contains(&arguments.len()) => (name, values),
                    _ => {
                        died = true;
                        break;
                    }
                };
                // git refuses a delete whose old value or a create whose new
                // value is the null object ID, and a ref named twice in one
                // transaction. An update to the null ID deletes the ref,
                // unless its old value is null too, which only asserts the
                // ref is absent.
                let delete = match verb {
                    "delete" => values
                        .first()
                        .is_none_or(|old| !null_oid(old))
                        .then_some(true),
                    "create" => (!null_oid(&values[0])).then_some(false),
                    "update" => {
                        Some(null_oid(&values[0]) && values.get(1).is_none_or(|old| !null_oid(old)))
                    }
                    _ => Some(false),
                };
                match delete {
                    Some(delete) if queued.iter().all(|(_, queued, _)| queued != name) => {
                        queued.push((verb, name.clone(), delete));
                        Some(state)
                    }
                    _ => None,
                }
            }
            "update" | "create" | "delete" | "verify" => None,
            _ => {
                unread = Some(number + 1);
                break;
            }
        };
        let Some(next) = next else {
            died = true;
            break;
        };
        state = next;
    }
    if let Some(line) = unread {
        unmodeled_subcommand_boundary(
            builder,
            s,
            &format!("git update-ref --stdin line {line} and the lines after it are not modeled"),
        );
    } else if !died && state == UpdateRefTransactionState::Open {
        commit(builder, &mut queued);
    }
    true
}

/// The space-separated arguments of an update-ref `--stdin` line. An
/// argument may be C-quoted, which git unquotes; `Err` is a line git dies on
/// (a bad quote, or a character after the closing quote), and `None` a
/// quoted name that is not UTF-8.
fn update_ref_arguments(mut rest: &str) -> Option<Result<Vec<String>, ()>> {
    let mut arguments = Vec::new();
    loop {
        let (argument, after) = if let Some(quoted) = rest.strip_prefix('"') {
            let mut argument = Vec::new();
            let mut chars = quoted.char_indices();
            let end = loop {
                let Some((index, c)) = chars.next() else {
                    return Some(Err(()));
                };
                match c {
                    '"' => break index + 1,
                    '\\' => argument.push(match chars.next().map(|(_, c)| c) {
                        Some('a') => 0x07,
                        Some('b') => 0x08,
                        Some('f') => 0x0c,
                        Some('n') => b'\n',
                        Some('r') => b'\r',
                        Some('t') => b'\t',
                        Some('v') => 0x0b,
                        Some(c @ ('\\' | '"')) => c as u8,
                        Some(first @ '0'..='3') => {
                            let mut code = first as u8 - b'0';
                            for _ in 0..2 {
                                let Some(digit) = chars.next().and_then(|(_, c)| c.to_digit(8))
                                else {
                                    return Some(Err(()));
                                };
                                code = code * 8 + digit as u8;
                            }
                            code
                        }
                        _ => return Some(Err(())),
                    }),
                    c => argument.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                }
            };
            (String::from_utf8(argument).ok()?, &quoted[end..])
        } else {
            let (argument, after) = rest.split_at(rest.find(' ').unwrap_or(rest.len()));
            (argument.to_string(), after)
        };
        arguments.push(argument);
        match after.strip_prefix(' ') {
            Some(next) => rest = next,
            None if after.is_empty() => return Some(Ok(arguments)),
            None => return Some(Err(())),
        }
    }
}
