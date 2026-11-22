//! Loop values: the members of a `for` list, the lines a `while read`
//! loop reads and the choices a `select` menu offers, each walked as one
//! iteration bound to its value, so a body that runs a value as code
//! (`node -e "$c"`, `sh "$f"`) is judged on every value rather than on one
//! unknown binding. The statement walk hands a `for` or `select` item to
//! `walk_for_loop`. A `for` list needs words, globs included, that expand
//! to known members (`finite_for_value`); the members are walked in order
//! (`walk_iterations`). A list walked under one binding instead fails closed
//! where its body runs a value it could not read
//! (`fail_closed_on_unread_values`). The lines of a `while read` loop over
//! literal input or a named file (`read_loop`, `walk_read_loop`) and the
//! members a `select` offers (`walk_choices`) are walked the same way
//! (`Iterations`). A `for (( ))` loop whose header evaluates is walked one
//! iteration per counter value (`walk_counted_arithmetic`). Their verdicts
//! are the `loop-values.*` corpus rows; the same fan-out through `xargs` is
//! the `Xargs` model's `XargsCut` (`models/subprocess/xargs.rs`).

use effinterp_proto::{BoundaryReason, ProvenanceKind, ProvenanceNode};

use crate::builder::PlanBuilder;
use crate::flow::FlowRef;
use crate::nest::{RegionEntryFilesystem, SourceResolution};
use crate::value::{SemanticValue, SemanticValueKind, join_branches};
use crate::word::{Word, WordPart};

use super::captured_file::captured_file_path;
use super::eval::command_substitution::spelled_text;
use super::eval::redirection::redirected_file;
use super::eval::source_and_eval::note_expanded_assignments;
use super::eval::variable_binding::{
    READ_OPTIONS_WITH_VALUE, bind_for_var, bind_read_array, captured_list_fields,
    for_list_producers, read_loop_lines,
};
use super::lex::RedirKind;
use super::lex::{Seg, ShellSpan, WordTok};
use super::parse::ShellItem;
use super::shell_env::{ArrayValue, ShellEnv};
use super::{Shell, Termination, eval, literal_word_text, parse};

/// Whether a loop body reaches its end on every iteration. `break`,
/// `continue`, `return` and `exit` each leave part of the body reached only
/// on some paths, and a construct this frontend does not walk could hold one,
/// so only a body free of all of them turns a fixed iteration list into a
/// fixed sequence of unconditional iterations.
pub(super) fn body_runs_every_iteration(items: &[ShellItem]) -> bool {
    items.iter().all(|item| match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().all(|cmd| {
            !cmd.words
                .first()
                .and_then(parse::literal_text)
                .is_some_and(|name| {
                    matches!(name.as_str(), "break" | "continue" | "return" | "exit")
                })
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            body_runs_every_iteration(items)
        }
        ShellItem::Alternatives { arms, .. } => {
            arms.iter().all(|arm| body_runs_every_iteration(arm))
        }
        ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => true,
        ShellItem::Unsupported { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    })
}

/// Whether a loop body runs `ssh` or `scp`, read off a literal command head.
/// A loop with such a remote command in its body is not walked once per
/// member: it keeps the single walk under an unknown binding.
pub(super) fn body_has_remote_command(items: &[ShellItem]) -> bool {
    items.iter().any(|item| match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().any(|cmd| {
            cmd.words
                .first()
                .and_then(parse::literal_text)
                .is_some_and(|head| matches!(head.as_str(), "ssh" | "scp"))
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            body_has_remote_command(items)
        }
        ShellItem::Alternatives { arms, .. } => arms.iter().any(|arm| body_has_remote_command(arm)),
        ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => false,
        ShellItem::Unsupported { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    })
}

/// Where a loop body certainly leaves the loop on its first iteration: a
/// top-level `exit`, `return` or `break` (`break 1`) that every iteration
/// reaches, and whether it also ends the walk (`exit`, `return`) rather
/// than only the loop (`break`). A name the script may redefine as a
/// function leaves nothing certain.
fn first_iteration_leaves(items: &[ShellItem], env: &ShellEnv) -> Option<(usize, bool)> {
    items.iter().enumerate().find_map(|(stop, item)| {
        let ShellItem::Pipeline {
            cmds,
            conditional: false,
            ..
        } = item
        else {
            return None;
        };
        let [cmd] = cmds.as_slice() else {
            return None;
        };
        if !cmd.redirs.is_empty() || !cmd.assignments.is_empty() {
            return None;
        }
        let words = cmd
            .words
            .iter()
            .map(parse::literal_text)
            .collect::<Option<Vec<_>>>()?;
        let terminates = match words.as_slice() {
            [head, ..] if head == "exit" => true,
            // Outside a function or sourced file `return` fails and the
            // iteration goes on, as the walk treats it.
            [head, ..] if head == "return" && (env.sourced || !env.active.is_empty()) => true,
            [head] if head == "break" => false,
            [head, level] if head == "break" && level == "1" => false,
            _ => return None,
        };
        (!env.may_redefine(&words[0]) && body_runs_every_iteration(&items[..stop]))
            .then_some((stop, terminates))
    })
}

/// Which iterations a list of members runs.
#[derive(Clone, Copy, PartialEq)]
enum Iterations {
    /// A `for` list: every member, in order.
    ForList,
    /// The lines of a `while read` loop: in order, each only while no
    /// earlier iteration consumed the input that holds it.
    ReadLines,
    /// A `select` menu: whichever members its input chooses, in any order
    /// and any number of times, or an empty value for a choice that names
    /// none. They are walked in the order `walk_choices` gives.
    SelectChoices,
}

/// How the statement walk goes on after `walk_for_loop`.
pub(super) enum ForLoopWalk {
    /// The loop's body ended the walk.
    Terminated((Termination, u32)),
    /// The loop lifted its own source hazards: the walk goes on with the
    /// next item, the item's status as the loop left it.
    HazardsSettled,
    /// The walk lifts the item's source hazards, as after any other item.
    Walked,
}

/// What one iteration binds to one of the loop's variables.
#[derive(Clone)]
enum IterationValue {
    Scalar(Word, Vec<FlowRef>),
    /// The fields `read -a` stores in its array, one element each.
    Array(Vec<String>),
}

/// Walk a `select` loop's `count` choices, each by `walk`, in an order its
/// input could give them. Every choice runs once in list order. Then every
/// choice that wrote a file runs right before each choice, after the run
/// of choices that first led it to write, so a choice's program is also
/// judged as each writer leaves it, whatever the menu's order and whatever
/// another writer would restore. A choice that writes only once another
/// has run is found the same way. Those runs stop before they would pass
/// `limit` walks; `false` then says some orders were left unwalked.
pub(super) fn walk_choices(
    builder: &mut PlanBuilder,
    count: usize,
    limit: usize,
    mut walk: impl FnMut(&mut PlanBuilder, usize),
) -> bool {
    let mut run = |builder: &mut PlanBuilder, choice: usize| {
        let writes = builder.source_write_count();
        walk(builder, choice);
        builder.source_write_count() > writes
    };
    let mut writers: Vec<(Vec<usize>, usize)> = Vec::new();
    for choice in 0..count {
        if run(builder, choice) {
            writers.push((Vec::new(), choice));
        }
    }
    let (mut next, mut walks) = (0, 0);
    while let Some((prefix, writer)) = writers.get(next).cloned() {
        next += 1;
        walks += count * (prefix.len() + 2);
        if walks > limit {
            return false;
        }
        for choice in 0..count {
            for &earlier in &prefix {
                run(builder, earlier);
            }
            run(builder, writer);
            if run(builder, choice) && writers.iter().all(|(_, known)| *known != choice) {
                let mut led = prefix.clone();
                led.push(writer);
                writers.push((led, choice));
            }
        }
    }
    true
}

/// The `read` command that is a `while` loop's whole condition, reading
/// input the request spells or a file it names.
pub(super) struct ReadLoop {
    /// The variables it stores each line in, with the words that name them:
    /// REPLY, named by the command's last word, when it names none.
    names: Vec<(String, ShellSpan)>,
    /// `-a`: the one name is an array that takes every field of a line.
    array: bool,
    /// An unquoted glob, brace or tilde may expand a word of the command
    /// into other words, so which variables it stores is not known.
    expands: bool,
    /// The `read` command itself.
    command: ShellSpan,
    /// What it stores for each iteration: one value per variable, or the
    /// array's fields; `None` when the input is not cut into known lines
    /// and fields.
    lines: Option<Vec<Vec<String>>>,
}

/// Where a `read` loop condition reads from.
enum ReadInput<'a> {
    /// The loop's own standard input.
    Loop(&'a crate::models::StdinValue),
    /// The condition's own `<`, here-document or here-string, opened again
    /// by every `read`, which so reads its first line each iteration: the
    /// file it names, or the text it spells (`None` when not literal).
    Own {
        file: Option<String>,
        text: Option<String>,
    },
}

impl Shell<'_> {
    /// A `read` loop condition whose input spells some of its text (a
    /// here-document, a here-string or a printed list) or is a file the
    /// request names (`< FILE`, `cat FILE |`), whether the loop's standard
    /// input or the condition's own. Its lines are known when it takes no
    /// option but `-r`, `-a` and those that change nothing it stores from
    /// such input, which is no terminal: `-s`, `-e`, `-p PROMPT`, and `-t`
    /// with a timeout above zero where no pipe can deliver a line late. No
    /// unquoted glob, brace or tilde may expand its words, the input's text
    /// must be known, and several variables or an array split each line
    /// under the default IFS. `None`
    /// for any other condition, or one a function or alias may replace.
    pub(super) fn read_loop(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        condition: &ShellItem,
    ) -> Option<ReadLoop> {
        let ShellItem::Pipeline { cmds, .. } = condition else {
            return None;
        };
        let [cmd] = cmds.as_slice() else {
            return None;
        };
        if cmd.assignments.iter().any(|assign| assign.name != "IFS") || env.may_redefine("read") {
            return None;
        }
        // `read` sees its words after quote removal: `-p "> "` is a prompt.
        // An unquoted glob, brace or tilde is expanded first, into words
        // this walk does not know: `-p prompt_*` may name more than one.
        let expands = cmd.words[1..].iter().any(|word| {
            word.segs.iter().any(|seg| {
                matches!(seg, Seg::Literal { text, quoted: false }
                    if text.contains(['*', '?', '[', '{', '~']))
            })
        });
        let words = cmd
            .words
            .iter()
            .map(parse::command_name_text)
            .collect::<Option<Vec<_>>>()?;
        // The variables `read` stores, from its options as bash parses
        // them, clustered or not. With `-a` the array takes every field and
        // other names are ignored.
        let (mut raw, mut cut, mut options) = (false, !expands, true);
        // A `-t` timeout above zero: one that can cut a line short only
        // where it arrives late through a pipe.
        let mut timed = false;
        let mut names = Vec::new();
        let mut array = None;
        let mut index = 1;
        while index < words.len() {
            let word = words[index].as_str();
            match word {
                "--" if options => options = false,
                "-" if options => cut = false,
                flags if options && flags.starts_with('-') => {
                    for (offset, flag) in flags.char_indices().skip(1) {
                        match flag {
                            'r' => raw = true,
                            // Readline and silence act on a terminal only.
                            'e' | 's' => {}
                            flag if READ_OPTIONS_WITH_VALUE.contains(flag) => {
                                // Its value is the rest of the word, or the next.
                                let value = if offset + 1 < flags.len() {
                                    (flags[offset + 1..].to_owned(), cmd.words[index].span)
                                } else {
                                    index += 1;
                                    (words.get(index)?.clone(), cmd.words[index].span)
                                };
                                match flag {
                                    'a' => {
                                        cut &= array.is_none();
                                        array = Some(value);
                                    }
                                    // A prompt is printed to a terminal only.
                                    'p' => {}
                                    // `-t 0` reads nothing; an invalid
                                    // timeout ends the loop before its body.
                                    't' if value
                                        .0
                                        .parse::<f64>()
                                        .is_ok_and(|timeout| timeout > 0.0) =>
                                    {
                                        timed = true;
                                    }
                                    _ => cut = false,
                                }
                                break;
                            }
                            _ => cut = false,
                        }
                    }
                }
                name => names.push((name.to_owned(), cmd.words[index].span)),
            }
            index += 1;
        }
        if let Some(array) = &array {
            names = vec![array.clone()];
        }
        let reply = names.is_empty();
        if reply {
            names.push(("REPLY".to_owned(), cmd.words.last()?.span));
        }
        let input = match cmd.redirs.as_slice() {
            [] => ReadInput::Loop(env.stdin.as_ref()?),
            [redir] if redir.named_fd.is_none() && redir.fd.unwrap_or(0) == 0 => match redir.kind {
                RedirKind::In => ReadInput::Own {
                    file: redirected_file(redir.target.as_ref(), env.cwd_resource.clone())
                        .as_literal()
                        .map(str::to_owned),
                    text: None,
                },
                RedirKind::HereDoc => ReadInput::Own {
                    file: None,
                    text: redir
                        .heredoc
                        .as_ref()
                        .filter(|doc| doc.quoted || !doc.body.contains(['$', '`', '\\']))
                        .map(|doc| doc.body.clone()),
                },
                RedirKind::HereString => ReadInput::Own {
                    file: None,
                    text: redir
                        .target
                        .as_ref()
                        .and_then(spelled_text)
                        .map(|text| text + "\n"),
                },
                _ => return None,
            },
            _ => return None,
        };
        let (text, again) = match input {
            ReadInput::Loop(stdin) => {
                let file = match stdin.file.as_deref() {
                    Some(file) => Some(file.as_literal()?),
                    None => None,
                };
                if file.is_none()
                    && !stdin
                        .word
                        .parts
                        .iter()
                        .any(|part| matches!(part, WordPart::Literal(_)))
                {
                    return None;
                }
                let text = (cut && !(timed && stdin.piped))
                    .then(|| match file {
                        Some(path) => self.value_list_file_text(builder, path),
                        None => stdin.word.as_literal().map(str::to_owned),
                    })
                    .flatten();
                (text, false)
            }
            ReadInput::Own { file, text } => {
                let text = cut
                    .then(|| match file {
                        Some(path) => self.value_list_file_text(builder, &path),
                        None => text,
                    })
                    .flatten();
                (text, true)
            }
        };
        let lines = text
            .and_then(|text| {
                read_loop_lines(env, cmd, raw, reply, array.is_some(), names.len(), &text)
            })
            .map(|mut lines| {
                // Input the condition opens again yields its first line to
                // every `read`: twice is enough for a body that changes what
                // the next run of that line does.
                if again {
                    lines.truncate(1);
                    lines.extend(lines.clone());
                }
                lines
            })
            .filter(|lines| lines.len() as u64 <= self.nest.limits.max_value_cardinality);
        Some(ReadLoop {
            names,
            array: array.is_some(),
            expands,
            command: cmd.span,
            lines,
        })
    }

    /// The bytes of a value list file: one whose lines or fields a `while
    /// read` loop, a `for` list's `$(cat FILE)` or `mapfile` takes as
    /// values, as the host and the writes recorded so far left it. `None`
    /// when they cannot be read, or hold a NUL byte, which no shell variable
    /// can. A file it cannot read records no gap: its values fail the call
    /// closed only where the body runs one as code. xargs reads its own
    /// list file with `xargs_file_text`.
    pub(super) fn value_list_file_text(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
    ) -> Option<String> {
        let purpose = crate::SourcePurpose::InvocationInput;
        if !self.nest.host_source_readable(builder, path, purpose) {
            return None;
        }
        match self
            .nest
            .resolve_source_file(builder, path, purpose, "shell")
        {
            SourceResolution::Source { source, .. } => (!source.contains('\0')).then_some(source),
            _ => None,
        }
    }

    /// Walk a `while read` loop over input the request spells or a file it
    /// names: the `read` once, as the loop's condition, then the body once
    /// per line it reads, its variables bound to that line's values, as
    /// `walk_iterations` walks a `for` list. Input not cut into lines stands
    /// for all of them at once, and fails closed where the body runs one as
    /// code. After the loop each variable holds what the condition left,
    /// which names no line outside the loop.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn walk_read_loop(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        read: ReadLoop,
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> Option<(Termination, u32)> {
        let (condition, body) = items.split_at(1);
        self.walk_may_region(builder, env, condition, walk_depth + 1);
        let held = read
            .names
            .iter()
            .map(|(name, _)| env.vars.get(name).cloned())
            .collect::<Vec<_>>();
        let held_array = read
            .array
            .then(|| env.arrays.get(&read.names[0].0).cloned())
            .flatten();
        let producers = held
            .iter()
            .map(|entry| {
                entry
                    .as_ref()
                    .map(|entry| entry.producers.clone())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let termination = match read.lines {
            Some(lines) => self.walk_iterations(
                builder,
                env,
                &read.names,
                lines
                    .into_iter()
                    .map(|values| {
                        if read.array {
                            return vec![IterationValue::Array(values)];
                        }
                        values
                            .into_iter()
                            .zip(producers.iter().cloned())
                            .map(|(value, producers)| {
                                IterationValue::Scalar(Word::literal(value), producers)
                            })
                            .collect()
                    })
                    .collect(),
                body,
                Iterations::ReadLines,
                force_conditional,
                walk_depth,
                hazard_depth,
                entry_filesystem,
            ),
            None => {
                let first_boundary = builder.boundaries_len();
                for ((name, span), producers) in read.names.iter().zip(&producers) {
                    bind_for_var(builder, env, name.clone(), None, *span, producers.clone());
                }
                self.walk_loop(builder, env, body, None, |builder, env, _| {
                    self.walk_may_region(builder, env, body, walk_depth + 1);
                    None
                });
                // An element of the array names no binding, nor does a name
                // an expansion may replace, so with `-a` or such a word any
                // code the body could not read fails closed.
                let spans = read.names.iter().map(|(_, span)| *span).collect::<Vec<_>>();
                self.fail_closed_on_unread_values(
                    builder,
                    env,
                    (!read.array && !read.expands).then_some(spans.as_slice()),
                    read.command,
                    first_boundary,
                );
                None
            }
        };
        if read.array {
            let name = &read.names[0].0;
            match held_array {
                Some(array) => {
                    env.arrays.insert(name.clone(), array);
                }
                None => {
                    env.arrays.remove(name);
                }
            }
        }
        for ((name, _), entry) in read.names.into_iter().zip(held) {
            match entry {
                Some(entry) => {
                    env.vars.insert(name, entry);
                }
                None => {
                    env.vars.remove(&name);
                }
            }
        }
        termination
    }

    /// Walk a `for` or `select` item: its list's members one iteration
    /// each where they are known, its body once under an unknown binding
    /// otherwise, which fails closed where the body runs a value it could
    /// not read. Kept out of line: `walk_items` recurses once per nested
    /// group, so its frame size bounds nesting.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn walk_for_loop(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        item: &ShellItem,
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> ForLoopWalk {
        let ShellItem::For {
            var,
            values,
            arithmetic,
            select,
            items,
        } = item
        else {
            unreachable!("walk_for_loop walks a for or select item");
        };
        let iterations = if *select {
            Iterations::SelectChoices
        } else {
            Iterations::ForList
        };
        if let Some(values) = values {
            self.assign_list_defaults(builder, env, values, force_conditional);
        }
        // The loop variable and its list, when the body is
        // walked only under one binding for every value and the
        // list is longer than the walk takes one by one or
        // spells a value: text no expansion changes, or a quoted
        // variable.
        let mut single_walk_list = None;
        if let Some((name, span)) = var {
            let original_values = values;
            let mut list_producers = values
                .as_deref()
                .map(|values| for_list_producers(builder, env, values))
                .unwrap_or_default();
            // The list is expanded whatever the body does with
            // the variable, and `select` prints it as a menu.
            note_expanded_assignments(builder, &list_producers);
            // A command substitution in the list runs once, ahead
            // of the first iteration, and each iteration binds a
            // field of its output: the value is not known here,
            // but what printed it is.
            let substitutes = values.as_deref().is_some_and(|values| {
                values.iter().any(|value| {
                    value
                        .segs
                        .iter()
                        .any(|seg| matches!(seg, Seg::CommandSub { .. }))
                })
            });
            if let Some(values) = values.as_deref().filter(|_| substitutes) {
                let expansion = self.expand_words(builder, env, values, true, false);
                list_producers.extend(
                    expansion
                        .variants
                        .into_iter()
                        .flatten()
                        .flat_map(|value| value.producers),
                );
                list_producers.sort();
                list_producers.dedup();
            }
            let values = values.as_ref().map(|values| {
                values
                    .iter()
                    .flat_map(|value| self.brace_words(builder, value))
                    .collect::<Vec<_>>()
            });
            let expanded_values = values.as_deref().and_then(|values| {
                let has_unquoted_env = values
                    .iter()
                    .any(|value| matches!(value.segs.as_slice(), [Seg::Env { quoted: false, .. }]));
                let unknown = values
                    .iter()
                    .any(|value| matches!(value.segs.as_slice(), [Seg::Special | Seg::ShellPid]));
                (has_unquoted_env && !unknown && !substitutes).then(|| {
                    self.expand_words(
                        builder,
                        env,
                        original_values.as_deref().unwrap(),
                        true,
                        false,
                    )
                })
            });
            if let Some(expansion) = expanded_values {
                for values in expansion.variants {
                    // A list of fixed words runs the body once
                    // for each: the members are its iterations.
                    // A member that is a pattern or an unknown
                    // value stands for any number of them.
                    let counted = values.iter().all(|value| value.word.as_literal().is_some());
                    // Counted iterations run in order, so each
                    // meets the writes of those before it as
                    // recorded, as `walk_iterations` explains.
                    let suspended = hazard_depth
                        .filter(|_| counted)
                        .map(|depth| builder.suspend_source_hazards(depth));
                    let mut members = values
                        .into_iter()
                        .map(|value| (value.word, value.producers))
                        .collect::<Vec<_>>();
                    // An invalid choice runs a `select` body with
                    // its variable empty.
                    if *select && !members.is_empty() {
                        members.push((Word::literal(""), Vec::new()));
                    }
                    let mut walk = || {
                        let mut iteration = 0;
                        let mut walk_member = |builder: &mut PlanBuilder, member: usize| {
                            let (word, producers) = members[member].clone();
                            bind_for_var(builder, env, name.clone(), Some(word), *span, producers);
                            let instance = self.enter_loop_iteration(builder, items, iteration);
                            iteration += 1;
                            if counted {
                                self.walk_may_region(builder, env, items, walk_depth + 1);
                            } else {
                                self.walk_loop(builder, env, items, None, |builder, env, _| {
                                    self.walk_may_region(builder, env, items, walk_depth + 1);
                                    None
                                });
                            }
                            if let Some(previous) = instance {
                                builder.leave_condition_call(previous);
                            }
                        };
                        // Its input may choose them in any order.
                        if *select {
                            let code_reads = builder.code_read_count();
                            let limit = self.nest.limits.max_value_cardinality as usize;
                            let explored = walk_choices(builder, members.len(), limit, walk_member);
                            self.fail_closed_on_unwalked_choices(
                                builder,
                                env,
                                explored,
                                code_reads,
                                &[(name.clone(), *span)],
                            );
                        } else {
                            for member in 0..members.len() {
                                walk_member(builder, member);
                            }
                        }
                    };
                    match entry_filesystem.filter(|_| counted) {
                        Some(entry) => self.nest.budget.walk_from_region_entry(entry, walk),
                        None => walk(),
                    }
                    if let Some(suspended) = suspended {
                        builder.resume_source_hazards(suspended);
                    }
                }
                if let Some(depth) = hazard_depth {
                    builder.truncate_source_hazards(depth);
                }
                return ForLoopWalk::HazardsSettled;
            }
            // An unconditional break on the first iteration prevents every
            // later value from reaching the body or the following command.
            if !select
                && let Some(values) = values.as_deref()
                && !values.is_empty()
                && values.iter().all(|value| literal_word_text(value).is_some())
                && !values.iter().any(|value| matches!(value.segs.first(),
                    Some(Seg::Literal { text, quoted: false }) if text.starts_with('~')))
                && !env.may_redefine("break")
                && let Some(stop) = items.iter().position(|item| matches!(item,
                    ShellItem::Pipeline { cmds, conditional: false, .. }
                    if cmds.len() == 1 && cmds[0].redirs.is_empty() && cmds[0].assignments.is_empty()
                        && cmds[0].words.iter().map(parse::literal_text).collect::<Option<Vec<_>>>()
                            .is_some_and(|words| words == ["break"] || words == ["break", "1"])))
                && body_runs_every_iteration(&items[..stop])
            {
                bind_for_var(builder, env, name.clone(), Some(Word::literal(literal_word_text(&values[0]).unwrap())), *span, Vec::new());
                // The one iteration runs after nothing but what came before the loop.
                let mut walk = || self.walk(builder, env, &items[..stop], force_conditional, walk_depth + 1);
                let termination = match entry_filesystem {
                    Some(entry) => self.nest.budget.walk_from_region_entry(entry, walk),
                    None => walk(),
                };
                if let Some(depth) = hazard_depth { builder.truncate_source_hazards(depth); }
                if let Some(termination) = termination { return ForLoopWalk::Terminated(termination); }
                env.status = Some(true);
                return ForLoopWalk::HazardsSettled;
            }
            if let Some(termination) = self.walk_for_members(
                builder,
                env,
                item,
                force_conditional,
                walk_depth,
                hazard_depth,
                entry_filesystem,
            ) {
                if let Some(termination) = termination {
                    return ForLoopWalk::Terminated(termination);
                }
                return ForLoopWalk::HazardsSettled;
            }
            let (value, fixed) = values
                .as_deref()
                .map(|values| {
                    self.finite_for_value(builder, env, values, hazard_depth, entry_filesystem)
                })
                .unwrap_or((None, None));
            // A fixed literal list runs its iterations in order.
            // Walk each binding separately so an operand read is
            // an exact occurrence rather than one conservative
            // union.
            if let Some(fixed) = fixed
                && !body_has_remote_command(items)
            {
                let termination = self.walk_iterations(
                    builder,
                    env,
                    &[(name.clone(), *span)],
                    fixed
                        .into_iter()
                        .map(|value| vec![IterationValue::Scalar(value, Vec::new())])
                        .collect(),
                    items,
                    iterations,
                    force_conditional,
                    walk_depth,
                    hazard_depth,
                    entry_filesystem,
                );
                if let Some(termination) = termination {
                    return ForLoopWalk::Terminated(termination);
                }
                return ForLoopWalk::HazardsSettled;
            }
            let max_cardinality = self.nest.limits.value_limits().max_cardinality;
            single_walk_list = values
                .as_deref()
                .filter(|values| {
                    values.len() > max_cardinality
                        || values.iter().any(|value| {
                            value.segs.iter().all(|seg| match seg {
                                Seg::Literal { text, quoted } => {
                                    *quoted || !text.contains(['*', '?', '[', '~'])
                                }
                                Seg::Env { quoted, .. } => *quoted,
                                _ => false,
                            })
                            // A file the request names holds
                            // values too, captured or stored in an
                            // array by `mapfile`.
                            || matches!(value.segs.as_slice(),
                                [Seg::CommandSub { source, .. }]
                                    if captured_file_path(env, source).is_some())
                            || matches!(value.segs.as_slice(),
                                [Seg::ArrayAll { name, .. }]
                                    if matches!(env.arrays.get(name),
                                        Some(ArrayValue::Unknown { file_lines: true, .. })))
                        })
                })
                .and_then(|values| {
                    Some(ShellSpan {
                        start: values.first()?.span.start,
                        end: values.last()?.span.end,
                    })
                })
                .map(|list| (*span, list));
            bind_for_var(builder, env, name.clone(), value, *span, list_producers);
        }
        if let Some(header) = *arithmetic {
            if let Some(walked) = self.walk_counted_arithmetic(
                builder,
                env,
                header,
                items,
                force_conditional,
                walk_depth,
                hazard_depth,
                entry_filesystem,
            ) {
                return walked;
            }
            // Otherwise what the header assigns is unknown in the body and
            // after the loop.
            self.forget_arithmetic_counters(builder, env, header);
        }
        // A `for (( ))` whose condition holds for its initial
        // values certainly runs a body that always reaches its end.
        if arithmetic.is_some_and(|header| {
            body_runs_every_iteration(items)
                && self
                    .source
                    .get(header.start as usize..header.end as usize)
                    .is_some_and(eval::arithmetic::arithmetic_for_enters)
        }) {
            if let Some(termination) = self.walk_loop(
                builder,
                env,
                items,
                entry_filesystem,
                |builder, env, again| {
                    if again {
                        self.walk_may_region(builder, env, items, walk_depth + 1);
                        return None;
                    }
                    self.walk(builder, env, items, force_conditional, walk_depth + 1)
                },
            ) {
                if let Some(depth) = hazard_depth {
                    builder.truncate_source_hazards(depth);
                }
                return ForLoopWalk::Terminated(termination);
            }
        } else {
            let first_boundary = builder.boundaries_len();
            self.walk_loop(builder, env, items, entry_filesystem, |builder, env, _| {
                self.walk_may_region(builder, env, items, walk_depth + 1);
                None
            });
            if let Some((var_span, list_span)) = single_walk_list {
                self.fail_closed_on_unread_values(
                    builder,
                    env,
                    Some(&[var_span]),
                    list_span,
                    first_boundary,
                );
            }
        }
        env.status = None;
        ForLoopWalk::Walked
    }

    /// A `for` list expands once in the current shell, so the `:=` defaults
    /// it assigns persist after the loop. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame bounds nesting depth.
    #[inline(never)]
    fn assign_list_defaults(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        values: &[WordTok],
        conditional: bool,
    ) {
        let assigning = values
            .iter()
            .filter(|value| eval::assigns_default(value))
            .cloned()
            .collect::<Vec<_>>();
        if assigning.is_empty() {
            return;
        }
        let expansion = self.expand_words(builder, env, &assigning, true, false);
        for mut converted in expansion.variants.into_iter().flatten() {
            self.apply_pending_assigns(builder, env, &mut converted, conditional, false);
        }
    }

    /// A `for` over `"$@"` or `"${ARRAY[@]}"` with known members walks its
    /// body once per member, bound to it; `None` when the loop is not of that
    /// form. Kept out of line: `walk_items` recurses once per nested group, so
    /// its frame size bounds nesting.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn walk_for_members(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        item: &ShellItem,
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> Option<Option<(Termination, u32)>> {
        let ShellItem::For {
            var: Some((name, span)),
            values: Some(values),
            select,
            items,
            ..
        } = item
        else {
            return None;
        };
        let members = match values.as_slice() {
            [value] => match value.segs.as_slice() {
                [Seg::AllArgs { quoted: true }] => env.positional.clone(),
                [
                    Seg::ArrayAll {
                        name: array,
                        quoted: true,
                    },
                ] => env
                    .arrays
                    .get(array)
                    .and_then(|array| match array.candidates() {
                        [members] => Some(members.clone()),
                        _ => None,
                    }),
                _ => None,
            },
            _ => None,
        }?;
        if members.is_empty() || body_has_remote_command(items) {
            return None;
        }
        Some(
            self.walk_iterations(
                builder,
                env,
                &[(name.clone(), *span)],
                members
                    .into_iter()
                    .map(|member| vec![IterationValue::Scalar(member.word, member.producers)])
                    .collect(),
                items,
                if *select {
                    Iterations::SelectChoices
                } else {
                    Iterations::ForList
                },
                force_conditional,
                walk_depth,
                hazard_depth,
                entry_filesystem,
            ),
        )
    }

    /// A `for (( INIT; COND; STEP ))` whose header this shell can evaluate
    /// is walked as bash runs it: INIT once, then each iteration while COND
    /// holds, the body bound to the counters' values and STEP after it. Each
    /// section is expanded whole before it is evaluated
    /// (`expand_arithmetic`), and the counters are read back after each
    /// body, so a body that changes one changes the iterations after it.
    /// Like a counted list (`walk_iterations`), each iteration meets the
    /// writes of the ones before it and starts from the filesystem the loop
    /// found on entry. A COND false from the start runs no body. `None` when
    /// INIT or the first COND is unknown, a counter is stored other than as
    /// a plain variable, or a body that runs may leave the loop early; a
    /// later STEP or COND that is unknown, or more iterations than the value
    /// bound, leaves the rest of the loop to the walk of a loop whose count
    /// is unknown.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn walk_counted_arithmetic(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        header: ShellSpan,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> Option<ForLoopWalk> {
        let text = self
            .source
            .get(header.start as usize..header.end as usize)?;
        let [init, condition, step] = text.split(';').collect::<Vec<_>>()[..] else {
            return None;
        };
        if condition.trim().is_empty() {
            return None;
        }
        // An assignment to a nameref, an array or a readonly name does not
        // store the value in a plain variable of that name.
        let plain = |env: &ShellEnv, name: &str| {
            !env.readonly.contains(name)
                && !env.arrays.contains_key(name)
                && !env.vars.get(name).is_some_and(|entry| entry.nameref)
        };
        let assign = |builder: &mut PlanBuilder, env: &mut ShellEnv, section: &str| {
            let section = self.expand_arithmetic(env, section)?;
            for (name, expression) in eval::arithmetic::arithmetic_assignments(&section)? {
                let value = self.evaluate_arithmetic(env, &expression)?;
                if !plain(env, &name) {
                    return None;
                }
                bind_for_var(
                    builder,
                    env,
                    name,
                    Some(Word::literal(value.to_string())),
                    header,
                    Vec::new(),
                );
            }
            Some(())
        };
        assign(builder, env, init)?;
        let mut holds = self.known_condition(env, condition)?;
        if !holds {
            env.status = Some(true);
            return Some(ForLoopWalk::Walked);
        }
        if !body_runs_every_iteration(items) || body_has_remote_command(items) {
            return None;
        }
        let limit = self.nest.limits.value_limits().max_cardinality;
        let mut unfinished = false;
        let suspended = hazard_depth.map(|depth| builder.suspend_source_hazards(depth));
        let mut walk = || {
            let mut iteration = 0;
            while holds {
                if iteration == limit {
                    unfinished = true;
                    return None;
                }
                let instance = self.enter_loop_iteration(builder, items, iteration as u32);
                let termination = self.walk(builder, env, items, force_conditional, walk_depth + 1);
                if let Some(previous) = instance {
                    builder.leave_condition_call(previous);
                }
                if termination.is_some() {
                    return termination;
                }
                iteration += 1;
                match assign(builder, env, step).and_then(|()| self.known_condition(env, condition))
                {
                    Some(next) => holds = next,
                    None => {
                        unfinished = true;
                        return None;
                    }
                }
            }
            None
        };
        let termination = match entry_filesystem {
            Some(entry) => self.nest.budget.walk_from_region_entry(entry, walk),
            None => walk(),
        };
        if let Some(suspended) = suspended {
            builder.resume_source_hazards(suspended);
        }
        if let Some(termination) = termination {
            return Some(ForLoopWalk::Terminated(termination));
        }
        if unfinished {
            self.forget_arithmetic_counters(builder, env, header);
            self.walk_loop(builder, env, items, None, |builder, env, _| {
                self.walk_may_region(builder, env, items, walk_depth + 1);
                None
            });
            env.status = None;
        }
        Some(ForLoopWalk::Walked)
    }

    /// Leave unknown what a `for (( ))` header may assign: the variable a
    /// nameref names, and an array's elements, as well as a plain variable.
    fn forget_arithmetic_counters(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        header: ShellSpan,
    ) {
        let text = self
            .source
            .get(header.start as usize..header.end as usize)
            .unwrap_or_default();
        for name in eval::arithmetic::arithmetic_counters(text) {
            let target = env.reference_target(&name).unwrap_or_else(|| name.clone());
            env.arrays.remove(&target);
            bind_for_var(builder, env, target, None, header, Vec::new());
        }
    }

    /// Walk a `for` body once per member, in order, bound to it. The loop's
    /// probe noted every iteration's writes, as source hazards and as
    /// filesystem changes, for reads that may race them. The iterations run
    /// one after another, so each walk meets the writes of the iterations
    /// before it as recorded, and none of the iterations after it: those
    /// hazards are lifted, and the walk starts from the filesystem facts the
    /// loop found on entry. Both hold again after the loop. Otherwise one
    /// value whose program changes the files a later value runs would leave
    /// that later program unread, and the call judged on the values before.
    /// A body that can leave the loop early (`break`, `continue`, `return`,
    /// `exit`) runs each iteration only on some paths, so each is walked as
    /// a region that may run, unless it certainly leaves on the first.
    /// `while read` lines, with one value for each variable `read` stores,
    /// are walked so too, and `select` choices in the order `walk_choices`
    /// gives. The first choice need not be the first member, so no choice
    /// certainly leaves the loop.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn walk_iterations(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        names: &[(String, ShellSpan)],
        mut members: Vec<Vec<IterationValue>>,
        items: &[ShellItem],
        iterations: Iterations,
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> Option<(Termination, u32)> {
        let every = iterations == Iterations::ForList && body_runs_every_iteration(items);
        let leaves = (iterations != Iterations::SelectChoices)
            .then(|| first_iteration_leaves(items, env))
            .flatten();
        // An invalid choice runs a `select` body with its variable empty.
        if iterations == Iterations::SelectChoices && !members.is_empty() {
            members.push(
                names
                    .iter()
                    .map(|_| IterationValue::Scalar(Word::literal(""), Vec::new()))
                    .collect(),
            );
        }
        let suspended = hazard_depth.map(|depth| builder.suspend_source_hazards(depth));
        let walk = || {
            if iterations == Iterations::SelectChoices {
                let (mut iteration, code_reads) = (0, builder.code_read_count());
                let limit = self.nest.limits.max_value_cardinality as usize;
                let explored = walk_choices(builder, members.len(), limit, |builder, choice| {
                    self.bind_iteration(builder, env, names, members[choice].clone());
                    let instance = self.enter_loop_iteration(builder, items, iteration);
                    iteration += 1;
                    self.walk_may_region(builder, env, items, walk_depth + 1);
                    if let Some(previous) = instance {
                        builder.leave_condition_call(previous);
                    }
                });
                self.fail_closed_on_unwalked_choices(builder, env, explored, code_reads, names);
                return None;
            }
            for (iteration, member) in members.into_iter().enumerate() {
                self.bind_iteration(builder, env, names, member);
                let instance = self.enter_loop_iteration(builder, items, iteration as u32);
                if let Some((stop, terminates)) = leaves {
                    // The statements before the leaving one run, then the
                    // loop ends: no later member runs.
                    let reached = if terminates {
                        &items[..=stop]
                    } else {
                        &items[..stop]
                    };
                    let termination =
                        self.walk(builder, env, reached, force_conditional, walk_depth + 1);
                    if let Some(previous) = instance {
                        builder.leave_condition_call(previous);
                    }
                    return termination;
                }
                let termination = if every {
                    self.walk(builder, env, items, force_conditional, walk_depth + 1)
                } else {
                    self.walk_may_region(builder, env, items, walk_depth + 1);
                    None
                };
                if let Some(previous) = instance {
                    builder.leave_condition_call(previous);
                }
                if termination.is_some() {
                    return termination;
                }
            }
            None
        };
        let termination = match entry_filesystem {
            Some(entry) => self.nest.budget.walk_from_region_entry(entry, walk),
            None => walk(),
        };
        if let Some(suspended) = suspended {
            builder.resume_source_hazards(suspended);
        }
        if let Some(depth) = hazard_depth {
            builder.truncate_source_hazards(depth);
        }
        termination
    }
}

impl Shell<'_> {
    /// Where `walk_choices` left orders of a `select` unwalked and the body
    /// read code, which a choice in one of those orders may have rewritten:
    /// state the run of a hidden program, so the call is not judged on the
    /// orders walked alone. `code_reads` is the count before the walk.
    pub(super) fn fail_closed_on_unwalked_choices(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        explored: bool,
        code_reads: usize,
        names: &[(String, ShellSpan)],
    ) {
        if !explored
            && builder.code_read_count() > code_reads
            && let Some((_, span)) = names.first()
        {
            self.emit_hidden_program_effect(builder, env, *span, None);
        }
    }

    /// Bind one iteration's values to the loop's variables.
    fn bind_iteration(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        names: &[(String, ShellSpan)],
        member: Vec<IterationValue>,
    ) {
        for ((name, span), value) in names.iter().zip(member) {
            match value {
                IterationValue::Scalar(word, producers) => {
                    bind_for_var(builder, env, name.clone(), Some(word), *span, producers);
                }
                IterationValue::Array(fields) => bind_read_array(
                    builder,
                    env,
                    name.clone(),
                    fields,
                    *span,
                    self.nest.limits.max_shell_words,
                ),
            }
        }
    }

    /// A list spelled in the request that the walk did not take value by
    /// value, because it holds values the walk cannot resolve, more than it
    /// evaluates, or a body it walks once under one binding, stands for all
    /// of its values at once. When that walk left unread the code of a
    /// process the loop variable supplied, as `node -e "$c"` or `sh "$f"`,
    /// the values the walk did resolve say nothing of the ones it read none
    /// of: state the hidden program effect, so the call is not judged on
    /// them alone. `var_spans` names the variables' bindings; `None` takes
    /// any code the body left unread, for values whose uses name no
    /// binding, as an array's elements do. `first_boundary` is where the
    /// body's boundaries begin.
    pub(super) fn fail_closed_on_unread_values(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        var_spans: Option<&[ShellSpan]>,
        list_span: ShellSpan,
        first_boundary: usize,
    ) {
        let binding = |node: &ProvenanceNode| {
            var_spans.is_some_and(|spans| {
                spans.iter().any(|span| {
                    node.kind
                        == ProvenanceKind::SourceSpan {
                            start: span.start,
                            end: span.end,
                        }
                })
            }) && node.antecedents.as_slice() == self.scope.as_slice()
        };
        let unread = (first_boundary..builder.boundaries_len()).any(|index| {
            builder.boundary_at(index).is_some_and(|boundary| {
                (boundary.reason == BoundaryReason::DYNAMIC_SOURCE
                    || boundary.reason == BoundaryReason::UNRECOVERABLE_SOURCE)
                    && (var_spans.is_none()
                        || builder.nearest_execution_given(&boundary.provenance, binding))
            })
        });
        if unread {
            self.emit_hidden_program_effect(builder, env, list_span, None);
        }
    }

    /// The joined value of a `for` list, and whether the list is a fixed,
    /// non-empty sequence of iterations. A glob is still matched against the
    /// filesystem and may match nothing, so a list holding one names no
    /// iteration that is certain to run.
    pub(super) fn finite_for_value(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        values: &[WordTok],
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> (Option<Word>, Option<Vec<Word>>) {
        let limits = self.nest.limits.value_limits();
        // Every listed word was lexed, so the list's length is work the run
        // did even when it is too wide to keep as a finite value.
        if let Some(first) = values.first()
            && !self.charge(builder, values.len() as u64, 0, first.span)
        {
            return (None, None);
        }
        if values.is_empty() || values.len() > limits.max_cardinality {
            return (None, None);
        }
        // The words each iteration binds, when every one is fixed text; an
        // unquoted leading `~` or a quoted variable such as `"$HOME"/.nah`
        // may still expand to the environment's value, which quoting keeps
        // one field.
        let mut fixed = Some(Vec::with_capacity(values.len()));
        let mut joined = Some(Vec::with_capacity(values.len()));
        let mut members = 0;
        for value in values {
            // A lone `$(cat FILE)` holds the file's text, which bash already
            // printed before the first iteration.
            if let [Seg::CommandSub { source, quoted, .. }] = value.segs.as_slice()
                && let Some(path) = captured_file_path(env, source)
            {
                let Some(fields) = self
                    .captured_list_members(
                        builder,
                        env,
                        &path,
                        *quoted,
                        hazard_depth,
                        entry_filesystem,
                    )
                    .filter(|fields| members + fields.len() <= limits.max_cardinality)
                else {
                    return (None, None);
                };
                members += fields.len();
                if let Some(joined) = &mut joined {
                    joined.extend(fields.iter().cloned().map(SemanticValue::literal));
                }
                if let Some(fixed) = &mut fixed {
                    fixed.extend(fields.into_iter().map(Word::literal));
                }
                continue;
            }
            if !value
                .segs
                .iter()
                .all(|seg| matches!(seg, Seg::Literal { .. } | Seg::Env { quoted: true, .. }))
            {
                return (None, None);
            }
            let converted = self.convert(builder, env, value, true, true);
            match converted.word.parts.as_slice() {
                [WordPart::Literal(value)] => {
                    if let Some(joined) = &mut joined {
                        joined.push(SemanticValue::literal(value.clone()));
                    }
                }
                [WordPart::Glob(pattern)] => {
                    // bash expands the pattern once, before the first
                    // iteration, into the entries it matches.
                    if let Some(matches) = self
                        .listed_glob_matches(builder, env, pattern, entry_filesystem)
                        .filter(|matches| members + matches.len() <= limits.max_cardinality)
                    {
                        members += matches.len();
                        if let Some(joined) = &mut joined {
                            joined.extend(matches.iter().cloned().map(SemanticValue::literal));
                        }
                        if let Some(fixed) = &mut fixed {
                            fixed.extend(matches.into_iter().map(Word::literal));
                        }
                        continue;
                    }
                    fixed = None;
                    if let Some(joined) = &mut joined {
                        joined.push(SemanticValue::new(SemanticValueKind::Pattern {
                            pattern: effinterp_proto::ResourcePattern::FsPath {
                                glob: pattern.clone(),
                                narrowing: Default::default(),
                            },
                        }));
                    }
                }
                parts
                    if parts
                        .iter()
                        .all(|part| matches!(part, WordPart::Literal(_) | WordPart::Env(_))) =>
                {
                    joined = None;
                }
                _ => return (None, None),
            }
            members += 1;
            if let Some(fixed) = &mut fixed {
                fixed.push(converted.word);
            }
        }
        (
            joined.and_then(|joined| for_value_word(join_branches(joined, limits))),
            fixed,
        )
    }

    /// The members a lone `$(cat FILE)` in a `for` list holds: FILE's text
    /// less its trailing newlines, as `value_list_file_text` reads it, whole
    /// when the substitution is quoted and split into fields when not. bash
    /// prints the file before the first iteration, so it is read as the loop
    /// found it, with none of the writes its probe noted.
    fn captured_list_members(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        path: &str,
        quoted: bool,
        hazard_depth: Option<crate::builder::HazardDepth>,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> Option<Vec<String>> {
        let suspended = hazard_depth.map(|depth| builder.suspend_source_hazards(depth));
        let text = match entry_filesystem {
            Some(entry) => self
                .nest
                .budget
                .at_region_entry(entry, || self.value_list_file_text(builder, path)),
            None => self.value_list_file_text(builder, path),
        };
        if let Some(suspended) = suspended {
            builder.resume_source_hazards(suspended);
        }
        let text = text?;
        let text = text.trim_end_matches('\n');
        if quoted {
            return Some(vec![text.to_owned()]);
        }
        captured_list_fields(env, text)
    }

    /// The names an unquoted glob in a `for` list expands to, from the served
    /// listing of the one directory it searches, spelled as the pattern
    /// spells that directory. `None` when the listing is unavailable or may
    /// no longer hold, when nothing matches (bash then keeps the pattern
    /// text), or under `nocaseglob`, `dotglob` or `GLOBIGNORE`, which change
    /// matching.
    fn listed_glob_matches(
        &self,
        builder: &PlanBuilder,
        env: &ShellEnv,
        pattern: &str,
        entry_filesystem: Option<&RegionEntryFilesystem>,
    ) -> Option<Vec<String>> {
        if env.nocaseglob || env.dotglob || env.vars.contains_key("GLOBIGNORE") {
            return None;
        }
        let (directory, name, searched, entries) =
            self.glob_directory_listing(builder, env, pattern)?;
        let budget = &self.nest.budget;
        // The listing is of the directory as the invocation found it; a
        // modeled write before the loop may have added an entry.
        let stale = || {
            budget.listing_stale(&searched, budget.unmodeled_steps())
                || entries.first().is_some_and(|entry| {
                    budget.changed_under_another_name(
                        entry.rsplit_once('/').map_or("/", |(parent, _)| parent),
                    )
                })
        };
        if entry_filesystem.map_or_else(stale, |entry| budget.at_region_entry(entry, stale)) {
            return None;
        }
        let mut matches = Vec::new();
        for entry in &entries {
            let entry = entry.rsplit('/').next().unwrap_or(entry);
            if effinterp_proto::glob_match(name, entry).ok()? {
                matches.push(match directory {
                    Some("/") => format!("/{entry}"),
                    Some(directory) => format!("{directory}/{entry}"),
                    None => entry.to_owned(),
                });
            }
        }
        (!matches.is_empty()).then_some(matches)
    }
}

fn for_value_word(value: SemanticValue) -> Option<Word> {
    match value.kind {
        SemanticValueKind::Literal(value) => Some(Word::literal(value)),
        SemanticValueKind::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. },
        } => Some(Word::new(vec![WordPart::Glob(pattern)])),
        SemanticValueKind::Union(alternatives) => Some(Word::new(vec![WordPart::Union(
            alternatives
                .into_iter()
                .map(for_value_word)
                .collect::<Option<Vec<_>>>()?,
        )])),
        _ => None,
    }
}
