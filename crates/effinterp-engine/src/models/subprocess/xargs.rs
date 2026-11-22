//! The `xargs` model: how xargs cuts the items it reads, from standard input
//! or an `-a` file, into command lines (`XargsCut`), and the run of its
//! command each line makes, so `xargs -n1 node` judges every script it
//! names rather than passing the later ones as arguments to the first. The
//! shell's own fan-out of values to a command is `shell/loop_values.rs`.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance, CoverageLevel, Domain,
    ExecutionRealm, Port, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::common::{arg_node, operand_effect, program_input_attrs};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{SourceResolution, word_resource};
use crate::word::{Word, WordPart};

/// `xargs [flags] [command [initial-args]]`: the command runs with arguments
/// supplied from stdin, either appended or substituted for a replacement string.
pub(super) struct Xargs;

/// The parsed `xargs` option prefix: where the child argv starts, the
/// replacement string, and whether the argument list comes from a file
/// instead of standard input.
struct XargsOptions<'a> {
    rest: usize,
    replacement: Option<&'a str>,
    no_run_if_empty: bool,
    file_input: bool,
    /// argv index of the `-a` flag or its separate value, and the file it names.
    arg_file: Option<(usize, Word)>,
    /// False once a delimiter or end-of-file option redefines how stdin is
    /// cut into items, which literal item recovery does not model.
    default_splitting: bool,
    /// `-0`: NUL bytes alone separate items, taken verbatim.
    null_separated: bool,
    newline_separated: bool,
    /// How many items or lines a command line takes.
    batches: XargsBatches,
    /// The `-s` length a command line's arguments may not exceed, counting
    /// a terminating NUL each; `usize::MAX` when its value is not spelled.
    max_chars: Option<usize>,
}

/// How xargs cuts its items into command lines, each a run of the command.
/// For an interpreter the cut decides which item is the program and which
/// are its arguments.
#[derive(Clone, Copy, PartialEq)]
enum XargsBatches {
    /// One command line takes every item.
    All,
    /// Each command line takes at most this many items (`-n`).
    Items(usize),
    /// Each command line takes the items of at most this many nonblank
    /// input lines (`-L`, `-l`).
    Lines(usize),
    /// A count the invocation does not spell ends a command line.
    Unknown,
}

/// The argument bytes every xargs's default command-line length holds: GNU's
/// default is 128 KiB, BSD's the exec limit less 4 KiB and the environment.
const XARGS_DEFAULT_FITS: usize = 64 * 1024;

/// The `-n`, `-L` or `-l` count `value` spells; the last such option wins.
fn xargs_count(value: Option<&str>, batch: fn(usize) -> XargsBatches) -> XargsBatches {
    match value.and_then(|value| value.parse::<usize>().ok()) {
        Some(count) if count > 0 => batch(count),
        _ => XargsBatches::Unknown,
    }
}

fn xargs_options(argv: &[Word]) -> XargsOptions<'_> {
    let mut replacement = None;
    let mut no_run_if_empty = false;
    let mut file_input = false;
    let mut arg_file = None;
    let mut default_splitting = true;
    let mut null_separated = false;
    let mut newline_separated = false;
    let mut batches = XargsBatches::All;
    let mut max_chars = None;
    let value_flags = [
        "-n",
        "--max-args",
        "-L",
        "--max-lines",
        "-P",
        "--max-procs",
        "-s",
        "--max-chars",
        "-a",
        "--arg-file",
        "-d",
        "--delimiter",
        "-E",
        "-e",
    ];
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_literal() {
            Some("--") => {
                i += 1;
                break;
            }
            Some("-r" | "--no-run-if-empty") => {
                no_run_if_empty = true;
                i += 1;
            }
            Some("-I") => {
                replacement = argv.get(i + 1).and_then(Word::as_literal);
                i += 2;
            }
            Some("-i") => {
                replacement = Some("{}");
                i += 1;
            }
            Some(t) if t.starts_with("-I") || t.starts_with("-i") => {
                replacement = Some(&t[2..]);
                i += 1;
            }
            // GNU's long spelling of `-i`: `{}` unless a value is attached.
            Some("--replace") => {
                replacement = Some("{}");
                i += 1;
            }
            Some(t) if t.starts_with("--replace=") => {
                replacement = Some(&t["--replace=".len()..]);
                i += 1;
            }
            Some("-a" | "--arg-file") => {
                file_input = true;
                arg_file = argv.get(i + 1).map(|file| (i + 1, file.clone()));
                i += 2;
            }
            Some(t) if t.starts_with("-a") || t.starts_with("--arg-file=") => {
                file_input = true;
                let prefix = if t.starts_with("-a") {
                    2
                } else {
                    "--arg-file=".len()
                };
                arg_file = Some((
                    i,
                    crate::models::args::strip_literal_prefix(&argv[i], prefix),
                ));
                i += 1;
            }
            Some("-0" | "--null") => {
                default_splitting = false;
                null_separated = true;
                newline_separated = false;
                i += 1;
            }
            Some(t)
                if matches!(t, "-d" | "--delimiter")
                    || t.starts_with("-d")
                    || t.starts_with("--delimiter=") =>
            {
                let value = if matches!(t, "-d" | "--delimiter") {
                    let value = argv.get(i + 1).and_then(Word::as_literal);
                    i += 2;
                    value
                } else {
                    i += 1;
                    t.strip_prefix("--delimiter=")
                        .or_else(|| t.strip_prefix("-d"))
                };
                default_splitting = false;
                null_separated = matches!(value, Some("\\0" | "\\000"));
                newline_separated = matches!(value, Some("\\n" | "\n" | "\\012" | "\\x0a"));
            }
            Some(t)
                if t.starts_with("--delimiter")
                    || t.starts_with("-E")
                    || t.starts_with("-e")
                    || t.starts_with("--eof") =>
            {
                default_splitting = false;
                // EOF markers are ignored in -0/-d mode, in either order.
                i += if t == "-E" { 2 } else { 1 };
            }
            Some(t) if value_flags.contains(&t) => {
                let value = argv.get(i + 1).and_then(Word::as_literal);
                match t {
                    "-n" | "--max-args" => batches = xargs_count(value, XargsBatches::Items),
                    "-L" | "--max-lines" => batches = xargs_count(value, XargsBatches::Lines),
                    "-s" | "--max-chars" => {
                        max_chars = Some(
                            value
                                .and_then(|value| value.parse().ok())
                                .unwrap_or(usize::MAX),
                        )
                    }
                    _ => {}
                }
                i += 2;
            }
            Some(t) if t.starts_with('-') && t.len() > 1 => {
                // Attached (-n5) or boolean (-0, -r, -t); self-contained.
                if let Some(count) = t.strip_prefix("--max-args=") {
                    batches = xargs_count(Some(count), XargsBatches::Items);
                } else if let Some(count) = t.strip_prefix("--max-lines=") {
                    batches = xargs_count(Some(count), XargsBatches::Lines);
                } else if let Some(length) = t
                    .strip_prefix("--max-chars=")
                    .or_else(|| t.strip_prefix("-s"))
                {
                    max_chars = Some(length.parse().unwrap_or(usize::MAX));
                } else if let Some(count) = t.strip_prefix("-n") {
                    batches = xargs_count(Some(count), XargsBatches::Items);
                } else if let Some(count) = t.strip_prefix("-L") {
                    batches = xargs_count(Some(count), XargsBatches::Lines);
                } else if let Some(count) = t.strip_prefix("-l") {
                    // `-l` alone is one line.
                    batches = xargs_count(
                        Some(count).filter(|count| !count.is_empty()).or(Some("1")),
                        XargsBatches::Lines,
                    );
                } else if !t.starts_with("--") && t[1..].contains(['n', 'L', 'l', 's']) {
                    // A cluster such as `-rn1` may hold a count.
                    batches = XargsBatches::Unknown;
                }
                i += 1;
            }
            _ => break,
        }
    }
    XargsOptions {
        rest: i.min(argv.len()),
        replacement,
        no_run_if_empty,
        file_input,
        arg_file,
        default_splitting,
        null_separated,
        newline_separated,
        batches,
        max_chars,
    }
}

/// An xargs stage that hands every item it reads to one command as operands.
#[derive(Clone)]
pub(crate) struct XargsConsumer {
    /// `-0`: items end at a NUL. Otherwise blanks and newlines separate them
    /// and quotes are read, so a printed name that holds one is cut apart.
    pub(crate) nul: bool,
    /// `-n`, `-L`: the command runs once per batch of items. The batches' operands
    /// together are the items, which is all a command needs when every
    /// operand has the same role.
    pub(crate) batched: bool,
    /// `-I`: each line is one item, put in place of the replacement string.
    pub(crate) lines: bool,
    /// The command and its initial arguments.
    pub(crate) command: Vec<Word>,
}

/// The consumer a literal `xargs` argv is, or `None` when its options may
/// reject execution, place the items elsewhere than at the end, or cut the
/// input some other way: they cannot certify path operands.
pub(crate) fn xargs_printed_path_consumer(argv: &[Word]) -> Option<XargsConsumer> {
    let options = xargs_options(argv);
    if options.file_input
        || options.rest == argv.len()
        || !(options.null_separated || options.default_splitting)
    {
        return None;
    }
    let mut batched = false;
    let mut i = 1;
    while i < options.rest {
        match argv[i].as_literal()? {
            // `-t` only echoes each command line to stderr.
            "-0" | "--null" | "-r" | "--no-run-if-empty" | "-t" | "--verbose" | "--" => i += 1,
            "-I" => i += 2,
            flag if flag.starts_with("-I")
                || flag.starts_with("-i")
                || flag == "--replace"
                || flag.starts_with("--replace=") =>
            {
                i += 1
            }
            // A delimiter xargs reads as NUL is `-0`'s.
            "-d" | "--delimiter" if options.null_separated => i += 2,
            flag if options.null_separated
                && (flag.starts_with("-d") || flag.starts_with("--delimiter=")) =>
            {
                i += 1
            }
            // EOF markers are ignored in -0 mode, and change the default
            // splitting, which `default_splitting` already excludes.
            "-E" if options.null_separated => i += 2,
            flag if options.null_separated
                && (flag.starts_with("-e") || flag.starts_with("--eof")) =>
            {
                i += 1
            }
            "-P" | "--max-procs" => i += 2,
            "-n" | "--max-args" | "-L" => {
                batched = true;
                i += 2;
            }
            flag if flag.starts_with("--max-procs=")
                || flag.strip_prefix("-P").is_some_and(digits) =>
            {
                i += 1
            }
            flag if flag.starts_with("--max-args=")
                || flag.starts_with("--max-lines=")
                || flag.strip_prefix("-n").is_some_and(digits)
                || flag.strip_prefix("-L").is_some_and(digits) =>
            {
                batched = true;
                i += 1;
            }
            _ => return None,
        }
    }
    Some(XargsConsumer {
        nul: options.null_separated,
        batched,
        lines: options.replacement.is_some(),
        command: argv[options.rest..].to_vec(),
    })
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

impl CommandModel for Xargs {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "findutils/xargs@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["xargs"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // `-a FILE` reads its argument list from a file.
        let XargsOptions {
            rest: i,
            replacement,
            no_run_if_empty,
            file_input,
            arg_file,
            default_splitting,
            null_separated,
            newline_separated,
            batches,
            max_chars,
        } = xargs_options(ctx.argv);
        // Without `-a`, standard input is the argument list, so a file
        // redirected onto it is program input as the `-a` file is.
        if !file_input {
            builder.note_stdin_consumed();
        }
        // Its bytes become the command's arguments, so the command, not
        // xargs, decides where they go: the read is program input.
        let file_read = arg_file.as_ref().and_then(|(index, file)| {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index as u32,
                file,
                "filesystem.read",
                program_input_attrs(),
            )
        });
        // The file xargs cuts its items from: the `-a` file, or a file the
        // request names as its standard input.
        let input_file = if file_input {
            arg_file
                .as_ref()
                .and_then(|(_, file)| match ctx.resolve_fs_word(file) {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => Some(path),
                    _ => None,
                })
        } else {
            ctx.stdin
                .filter(|stdin| stdin.word.as_literal().is_none())
                .and_then(|stdin| stdin.file.as_deref())
                .and_then(Word::as_literal)
                .map(str::to_owned)
        };
        // A NUL byte separates items only under `-0`.
        let file_text = input_file
            .as_deref()
            .and_then(|path| xargs_file_text(ctx, builder, path))
            .filter(|text| null_separated || !text.contains('\0'));
        // The input as literal text, and with the environment values the
        // invocation knows spelled out.
        let (input_literal, input_text) = if file_input {
            (file_text.clone(), file_text)
        } else {
            (
                ctx.stdin_literal().map(str::to_owned).or(file_text.clone()),
                xargs_stdin_text(ctx).or(file_text),
            )
        };
        if no_run_if_empty && !file_input && ctx.stdin_literal() == Some("") {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        let rest = &ctx.argv[i..];
        if rest.is_empty() {
            // Default command is `echo`; no external effect.
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        // Literal stdin supplies the appended arguments outright; a stream
        // this model cannot read keeps them input-determined.
        let recovered = if replacement.is_some() {
            None
        } else if default_splitting {
            input_literal.as_deref().and_then(xargs_input_items)
        } else if null_separated {
            input_literal
                .as_deref()
                .map(|input| xargs_delimited_items(input, '\0'))
        } else if newline_separated {
            input_literal
                .as_deref()
                .map(|input| xargs_delimited_items(input, '\n'))
        } else {
            None
        };
        // Entry names printed under a directory name nothing on their own;
        // only a replacement that joins them under it does.
        let printed = (!file_input)
            .then(|| ctx.stdin.and_then(|stdin| stdin.paths.as_ref()))
            .flatten()
            .filter(|printed| printed.under.is_none() || replacement.is_some());
        let under = printed.and_then(|printed| printed.under.as_deref());
        let paths = printed.and_then(|printed| {
            if (printed.nul && null_separated)
                || (!printed.nul && (default_splitting || newline_separated))
            {
                Some(printed.paths.clone())
            } else if printed.nul && newline_separated {
                // exec argv ends at NUL: a newline-delimited item containing
                // NUL-separated names passes only its first pathname.
                printed
                    .paths
                    .first()
                    .and_then(|word| match word.parts.as_slice() {
                        [WordPart::Union(members)] => members.first(),
                        _ => Some(word),
                    })
                    .filter(|word| word.as_literal().is_some())
                    .map(|word| vec![word.clone()])
            } else {
                None
            }
        });
        // `-I` runs the command once per input line with the line in place of
        // every replacement string; lines recovered as text are substituted.
        let substituted = replacement
            .filter(|replacement| !replacement.is_empty() && default_splitting && paths.is_none())
            .and_then(|replacement| {
                let lines = xargs_replacement_lines(input_text.as_deref()?)?;
                Some(
                    lines
                        .iter()
                        .map(|line| {
                            rest.iter()
                                .map(|word| {
                                    Word::new(
                                        word.parts
                                            .iter()
                                            .map(|part| match part {
                                                WordPart::Literal(text) => WordPart::Literal(
                                                    text.replace(replacement, line),
                                                ),
                                                part => part.clone(),
                                            })
                                            .collect(),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>(),
                )
            });
        // The items each command line appends, when xargs places them at the
        // end. Too many cut points to name keep them unrecovered.
        let cut = XargsCut {
            batches,
            max_chars,
            fixed: rest
                .iter()
                .map(|word| word.as_literal().map(|text| text.len() + 1))
                .sum(),
            limit: ctx.nest.limits.max_value_cardinality as usize,
        };
        let command_lines = if replacement.is_some() {
            None
        } else if let Some(items) = &recovered {
            cut.command_lines(
                items.iter().map(Word::literal).collect(),
                input_text.as_deref().filter(|_| default_splitting),
            )
        } else {
            paths
                .clone()
                .and_then(|paths| cut.command_lines(paths, None))
        };
        let recovered = recovered.filter(|_| command_lines.is_some());
        let paths = paths.filter(|_| replacement.is_some() || command_lines.is_some());
        let mut words: Vec<Word> = rest.to_vec();
        let mut argv_provenance = ctx.argv_provenance_range(builder, i..ctx.argv.len());
        let mut input_arguments = Vec::new();
        // Arguments that receive one whole input item, so a selection the
        // input stream carries names exactly what they operate on.
        let mut item_arguments = Vec::new();
        if let Some(replacement) = replacement.filter(|_| substituted.is_none()) {
            // A word containing the replacement depends on unrecovered stdin.
            for (index, word) in words.iter_mut().enumerate().skip(1) {
                if word.parts.iter().any(
                    |part| matches!(part, WordPart::Literal(text) if text.contains(replacement)),
                ) {
                    // `prefix-{}` names something derived from the item, not the item,
                    // except `DIR/{}` for the entry names of DIR.
                    let joined = word
                        .as_literal()
                        .and_then(|word| word.strip_suffix(replacement))
                        .filter(|prefix| prefix.ends_with('/'))
                        .filter(|prefix| {
                            under.is_some_and(|under| {
                                matches!(
                                    ctx.resolve_fs_word(&Word::literal(prefix.trim_end_matches('/'))),
                                    ResourceExpr::Concrete {
                                        identity: ResourceIdentity::FsPath { path },
                                    } if path == under
                                )
                            })
                        });
                    if !replacement.is_empty()
                        && under.is_none()
                        && word.as_literal() == Some(replacement)
                    {
                        item_arguments.push((index as u32, None));
                    } else if !replacement.is_empty()
                        && let Some(prefix) = joined
                    {
                        item_arguments.push((index as u32, Some(prefix.to_string())));
                    }
                    *word = Word::new(vec![WordPart::Unknown]);
                    input_arguments.push(index as u32);
                }
            }
        } else if let Some(lines) = &command_lines {
            // The items keep the stream that produced them as their source.
            // The first command line, which takes the most items, names the
            // arguments xargs fills.
            for item in lines.first().into_iter().flatten() {
                input_arguments.push(words.len() as u32);
                words.push(item.clone());
                argv_provenance.push(
                    ctx.stdin
                        .map(|stdin| stdin.provenance.clone())
                        .unwrap_or_default(),
                );
            }
        } else if substituted.is_none() {
            input_arguments.push(words.len() as u32);
            item_arguments.push((words.len() as u32, None));
            words.push(Word::new(vec![WordPart::Unknown]));
            argv_provenance.push(Vec::new());
        }
        // A command that removes or empties its operands changes nothing when
        // a modeled producer prints no name for it, as a `find` whose tests
        // match nothing, and it has no operand of its own: GNU xargs still
        // runs it once, and `rm -rf ../outside` then deletes what it names.
        if replacement.is_none()
            && paths.as_ref().is_some_and(Vec::is_empty)
            && crate::models::find::find_command_discards(rest, ctx.os_dialect(builder))
            && rest[1..]
                .iter()
                .all(|word| word.as_literal().is_some_and(|word| word.starts_with('-')))
        {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            return;
        }
        let arg = arg_node(builder, ctx, i as u32);
        // The names a modeled producer prints, each one path, are the items
        // themselves, as `find . -name x -print0` prints them.
        let replayed = recovered.is_some()
            || (command_lines.is_some() || replacement.is_some() && under.is_none())
                && paths
                    .as_ref()
                    .is_some_and(|paths| paths.iter().all(|path| path.as_literal().is_some()));
        if !replayed && substituted.is_none() {
            // Items in an argument file or a file redirected to stdin, in
            // input the invocation spells out, or printed by a modeled
            // producer could be replayed; only input from elsewhere is decided
            // at run time.
            let replayable = file_input
                || paths.is_some()
                || ctx.stdin.is_some_and(|stdin| stdin.file.is_some())
                || xargs_stdin_text(ctx).is_some();
            builder.boundary(Boundary {
                reason: if replayable {
                    BoundaryReason::PARTIAL_ANALYSIS
                } else {
                    BoundaryReason::INPUT_DETERMINED_ARGUMENTS
                },
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("process"), Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    if replayable {
                        "xargs arguments come from a file, literal input or a modeled producer whose items are not replayed"
                    } else {
                        "xargs supplies arguments from stdin"
                    }
                    .to_string(),
                ),
            });
        }
        let start = builder.effects_len() as u32;
        let first_boundary = builder.boundaries_len();
        let parent = builder.current_execution();
        let mut streams = effinterp_proto::ExecutionStreams {
            stdout: Some(effinterp_proto::ExecutionStreamRef {
                node: parent,
                stream: effinterp_proto::ExecutionStream::Stdout,
            }),
            stderr: Some(effinterp_proto::ExecutionStreamRef {
                node: parent,
                stream: effinterp_proto::ExecutionStream::Stderr,
            }),
            ..Default::default()
        };
        // xargs reads its input itself and gives the child /dev/null unless
        // -a selects a separate argument-input file.
        if file_input {
            streams.stdin = Some(effinterp_proto::ExecutionStreamRef {
                node: parent,
                stream: effinterp_proto::ExecutionStream::Stdin,
            });
        }
        // Replacement runs once per selected item. Keep multiple placeholders
        // correlated instead of merging distinct operands into a union read.
        // Items the request spells, or holds in a file it names, but this
        // model could not cut or read stand for all of them at once.
        let unread_items = recovered.is_none()
            && paths.is_none()
            && substituted.is_none()
            && (input_file.is_some()
                || !file_input && ctx.stdin.is_some_and(|stdin| stdin.spelled));
        let variants = if substituted.is_some() {
            substituted
        } else if replacement.is_none() {
            command_lines.filter(|lines| lines.len() > 1).map(|lines| {
                lines
                    .into_iter()
                    .map(|items| rest.iter().cloned().chain(items).collect())
                    .collect()
            })
        } else {
            paths.as_ref().map(|paths| {
                paths
                    .iter()
                    .map(|path| {
                        let mut selected = words.clone();
                        for (argument, prefix) in &item_arguments {
                            selected[*argument as usize] = match prefix {
                                Some(prefix) => match path.parts.as_slice() {
                                    [WordPart::Glob(name)] => Word::new(vec![WordPart::Glob(
                                        crate::paths::escape_fs_glob_path(prefix) + name,
                                    )]),
                                    parts => {
                                        let mut joined = vec![WordPart::Literal(prefix.clone())];
                                        joined.extend(parts.iter().cloned());
                                        Word::new(joined)
                                    }
                                },
                                None => path.clone(),
                            };
                        }
                        selected
                    })
                    .collect::<Vec<_>>()
            })
        };
        if no_run_if_empty && paths.as_ref().is_some_and(Vec::is_empty) {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        for words in variants.unwrap_or_else(|| vec![words]) {
            // Each appended item keeps the stream it came from.
            let mut provenance = argv_provenance.clone();
            provenance.resize(
                words.len(),
                ctx.stdin
                    .map(|stdin| stdin.provenance.clone())
                    .unwrap_or_default(),
            );
            ctx.nest.nest(
                builder,
                crate::nest::Transition::exec(
                    words.iter().map(word_resource).collect(),
                    words.clone(),
                )
                .exec_cwd(ctx.cwd)
                .cwd(ctx.cwd_resource.clone(), ctx.cwd_node)
                .runtime_cwd(ctx.runtime_cwd)
                .argv_provenance(Some(provenance.as_slice()))
                .streams(streams.clone())
                .kind(effinterp_proto::ExecutionEdgeKind::ToolModel),
                &[model_node, arg],
                ctx.depth,
            );
        }
        // Where the command could not read the code one of those items
        // names, as `node` an unknown script, the items say nothing of that
        // code: state the run of the hidden program, as a loop over values
        // the walk could not read does.
        if unread_items
            && (first_boundary..builder.boundaries_len()).any(|index| {
                builder.boundary_at(index).is_some_and(|boundary| {
                    boundary.reason == BoundaryReason::DYNAMIC_SOURCE
                        || boundary.reason == BoundaryReason::UNRECOVERABLE_SOURCE
                })
            })
        {
            let mut attributes = builder.computed_command_attributes(true, model_node);
            attributes.insert(
                "source".into(),
                effinterp_proto::AttrValue::String("argument".into()),
            );
            builder.effect(effinterp_proto::Effect {
                request_assurance: effinterp_proto::RequestAssurance::Exact,
                id: Default::default(),
                operation: effinterp_proto::Operation::new("process.code_execution"),
                resource: ResourceExpr::Concrete {
                    identity: crate::paths::process_identity_with_cwd(
                        &[Word::literal("sh")],
                        ctx.cwd_resource.clone(),
                    ),
                },
                attributes,
                modality: effinterp_proto::Modality::May,
                realm: ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![model_node],
            });
        }
        if input_arguments.is_empty() || file_input && file_read.is_none() {
            return;
        }
        let end = builder.effects_len() as u32;
        // Default and newline splitting preserve newline-separated IDs.
        // Other delimiters can pass several IDs as one operand.
        if !file_input && (default_splitting || newline_separated) {
            for (argument, prefix) in item_arguments {
                if prefix.is_none() {
                    builder.record_stdin_argument(start..end, argument);
                }
            }
        }
        let Some(spawn) = (start..end)
            .find(|effect| builder.effect_operation(*effect as usize) == Some("process.exec"))
        else {
            return;
        };
        let execution = builder.effect_execution(spawn as usize);
        let mut bindings = Vec::new();
        for argument in &input_arguments {
            for effect in start..end {
                if builder.effect_execution(effect as usize) == execution
                    && builder.effect_operation(effect as usize) == Some("process.code_execution")
                    && builder.effect_string_attribute(effect as usize, "source")
                        == Some("argument")
                    && builder.effect_has_argument(effect as usize, *argument)
                {
                    bindings.push(crate::flow::PortBinding {
                        assurance: CausalAssurance::Exact,
                        from: crate::flow::BindEnd::Port(Port::Arg(*argument)),
                        to: crate::flow::BindEnd::Effect(effect),
                    });
                    bindings.push(crate::flow::PortBinding {
                        assurance: CausalAssurance::Exact,
                        from: crate::flow::BindEnd::Port(Port::Arg(*argument)),
                        to: crate::flow::BindEnd::Effect(spawn),
                    });
                }
            }
        }
        // The arguments come from xargs' stdin, or from the bytes it read
        // out of the `-a` file.
        let (from, from_port) = match file_read {
            Some(read) => (
                builder.flow_stage(crate::flow::FlowStage {
                    execution: None,
                    effects: vec![read],
                    bindings: vec![crate::flow::PortBinding {
                        assurance: CausalAssurance::Exact,
                        from: crate::flow::BindEnd::Effect(read),
                        to: crate::flow::BindEnd::Port(Port::Value),
                    }],
                    provenance: vec![model_node, arg],
                }),
                Port::Value,
            ),
            None => (
                builder.flow_stage(crate::flow::FlowStage {
                    execution: Some(parent),
                    effects: Vec::new(),
                    bindings: Vec::new(),
                    provenance: vec![model_node, arg],
                }),
                Port::Stdin,
            ),
        };
        let to = builder.flow_stage(crate::flow::FlowStage {
            execution,
            effects: (start..end).collect(),
            bindings,
            provenance: vec![model_node, arg],
        });
        if let (Some(from), Some(to)) = (from, to) {
            for argument in input_arguments {
                builder.flow_edge(crate::flow::Flow {
                    assurance: CausalAssurance::Exact,
                    from: crate::flow::FlowRef {
                        stage: from,
                        port: from_port.clone(),
                    },
                    to: crate::flow::FlowRef {
                        stage: to,
                        port: Port::Arg(argument),
                    },
                    reason: crate::flow::FlowReason::new("executor argument"),
                    provenance: vec![model_node, arg],
                });
            }
        }
    }
}

/// The text of the value list file xargs reads its items from, as the host
/// and the writes recorded so far left it. `None` when it cannot be read,
/// which records no gap: unread items fail the call closed only where the
/// command runs one as code. The shell's `value_list_file_text` reads a
/// loop's list file the same way but refuses NUL bytes, which `xargs -0`
/// separates items with.
fn xargs_file_text(ctx: &InvocationCtx, builder: &mut PlanBuilder, path: &str) -> Option<String> {
    let purpose = SourcePurpose::InvocationInput;
    if !ctx.nest.host_source_readable(builder, path, purpose) {
        return None;
    }
    match ctx.resolve_source_operand(builder, path, purpose) {
        SourceResolution::Source { source, .. } => Some(source),
        _ => None,
    }
}

/// The text on xargs' stdin, with each environment value the invocation
/// knows spelled out; `None` when any part is not text.
fn xargs_stdin_text(ctx: &InvocationCtx) -> Option<String> {
    ctx.stdin?
        .word
        .parts
        .iter()
        .map(|part| match part {
            WordPart::Literal(text) => Some(text.clone()),
            WordPart::Env(name) => match ctx.environment_value(name)? {
                ResourceExpr::Literal { value } => Some(value),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// How xargs cuts the items it appends into command lines.
struct XargsCut {
    batches: XargsBatches,
    max_chars: Option<usize>,
    /// The argument bytes of the command and its initial arguments, when
    /// they are literal.
    fixed: Option<usize>,
    /// The most command lines to name.
    limit: usize,
}

impl XargsCut {
    /// The items each command line takes, in order. `text` is the input
    /// they were cut from by default splitting, which `-L` counts in lines.
    /// Where the count or length that ends a line is not known, any run of
    /// consecutive items may be one command line, up to the count and the
    /// `-s` length; `None` when that names more than `limit` lines.
    fn command_lines(&self, items: Vec<Word>, text: Option<&str>) -> Option<Vec<Vec<Word>>> {
        // A pattern or union stands for an unknown number of items.
        let counted = items.iter().all(|item| item.as_literal().is_some());
        let size = |run: &[Word]| -> Option<usize> {
            run.iter()
                .map(|item| item.as_literal().map(|text| text.len() + 1))
                .sum::<Option<usize>>()
                .zip(self.fixed)
                .map(|(items, fixed)| items + fixed)
        };
        let exact = match self.batches {
            XargsBatches::All => Some(vec![items.clone()]),
            XargsBatches::Items(count) if counted => {
                Some(items.chunks(count).map(<[Word]>::to_vec).collect())
            }
            // A line ending in a blank continues on the next one.
            XargsBatches::Lines(count) => text
                .map(|text| {
                    text.split('\n')
                        .filter(|line| !line.trim_matches([' ', '\t']).is_empty())
                        .collect::<Vec<_>>()
                })
                .filter(|lines| !lines.iter().any(|line| line.ends_with([' ', '\t'])))
                .and_then(|lines| {
                    lines
                        .chunks(count)
                        .map(|batch| {
                            batch
                                .iter()
                                .map(|line| xargs_input_items(line))
                                .collect::<Option<Vec<_>>>()
                                .map(|items| {
                                    items.concat().into_iter().map(Word::literal).collect()
                                })
                        })
                        .collect::<Option<Vec<Vec<Word>>>>()
                }),
            _ => None,
        }
        .filter(|lines| {
            self.max_chars.is_none()
                && lines
                    .iter()
                    .all(|line| size(line).is_some_and(|size| size <= XARGS_DEFAULT_FITS))
        });
        let lines = match exact {
            Some(lines) => lines,
            None => {
                let longest = match self.batches {
                    XargsBatches::Items(count) => count,
                    _ => items.len(),
                };
                let fits = |run: &[Word]| {
                    self.max_chars
                        .is_none_or(|max| size(run).is_none_or(|size| size <= max))
                };
                let mut lines = Vec::new();
                for start in 0..items.len() {
                    for end in start + 1..=items.len().min(start + longest) {
                        if fits(&items[start..end]) {
                            lines.push(items[start..end].to_vec());
                        }
                        if lines.len() > self.limit {
                            return None;
                        }
                    }
                }
                lines
            }
        };
        Some(if lines.is_empty() {
            vec![Vec::new()]
        } else {
            lines
        })
    }
}

/// `xargs -I` input items: one per nonblank line, leading blanks removed.
/// Quotes, backslashes and trailing blanks change that grammar, so input
/// carrying them is not recovered.
pub(crate) fn xargs_replacement_lines(input: &str) -> Option<Vec<String>> {
    if input.contains(['\'', '"', '\\']) {
        return None;
    }
    input
        .split('\n')
        .map(|line| line.trim_start_matches([' ', '\t']))
        .filter(|line| !line.is_empty())
        .map(|line| (!line.ends_with([' ', '\t'])).then(|| line.to_string()))
        .collect()
}

/// Default xargs input splitting: blanks and newlines separate items. A
/// single- or double-quoted run keeps its blanks, and a backslash keeps the
/// character after it. `None` where a quote is left open or holds a newline,
/// which xargs rejects, or a backslash ends a line.
pub(crate) fn xargs_input_items(input: &str) -> Option<Vec<String>> {
    let mut items = Vec::new();
    let mut item: Option<String> = None;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' => items.extend(item.take()),
            '\'' | '"' => {
                let item = item.get_or_insert_with(String::new);
                loop {
                    match chars.next()? {
                        '\n' => return None,
                        quote if quote == c => break,
                        other => item.push(other),
                    }
                }
            }
            '\\' => match chars.next()? {
                '\n' => return None,
                escaped => item.get_or_insert_with(String::new).push(escaped),
            },
            other => item.get_or_insert_with(String::new).push(other),
        }
    }
    items.extend(item);
    Some(items)
}

/// `xargs -0` or `-d DELIMITER` input: each item ends at the delimiter, and
/// quotes, backslashes and blanks are ordinary characters. Text after the
/// last delimiter is a final item, and an empty item is still an argument.
fn xargs_delimited_items(input: &str, delimiter: char) -> Vec<String> {
    if input.is_empty() {
        return Vec::new();
    }
    input
        .strip_suffix(delimiter)
        .unwrap_or(input)
        .split(delimiter)
        .map(str::to_owned)
        .collect()
}
