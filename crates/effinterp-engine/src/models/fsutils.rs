//! Filesystem-oriented coreutils beyond the original four (rm, mv, cat,
//! mkdir live in coreutils.rs).

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, ExecutionRealm,
    Modality, Operation, ProvenanceRef, RequestAssurance, ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, basename, scan, scan_with_value_indices};
use crate::models::common::{
    Attrs, attrs, filesystem_read_stdout_binding, follow_parent_links, fs_arg_effect, fs_arg_node,
    fs_full_no_spawn, operand_effect, operands_read_stdin, program_input_attrs,
    program_output_attrs, stdin_stdout_binding, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx, ModelCausalBinding};
use crate::paths::resolve_fs_word_with_cwd;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

pub(super) fn fsutils_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Mkfifo { mknod: false }),
        Box::new(Mkfifo { mknod: true }),
        Box::new(Tee),
        Box::new(HeadTail),
        Box::new(Sed),
        Box::new(Ls),
        Box::new(Stat),
        Box::new(Patch),
        Box::new(Vim),
    ]
}

/// An operand effect whose request the model states: `Exact` where the
/// command performs the operation on every entry the operand names, as tee
/// writes each file operand and `shred -u` removes each one. `operand_effect`
/// states a conservative request, which establishes the operation only for
/// one concrete path; an exact request also establishes it for a pattern or
/// a tree selection, such as the entries `find -exec` passes.
#[allow(clippy::too_many_arguments)]
pub(super) fn requested_operand_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operand: &Word,
    operation: &str,
    attributes: Attrs,
    request_assurance: RequestAssurance,
) -> Option<u32> {
    let arg = fs_arg_node(builder, ctx, index, operand);
    let mut resource = ctx.resolve_fs_word(operand);
    let provenance = vec![arg, model_node];
    if !follow_parent_links(builder, ctx, operand, &mut resource, &provenance) {
        return None;
    }
    builder.effect(Effect {
        request_assurance,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance,
    })
}

struct Patch;

impl CommandModel for Patch {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "util/patch@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["patch"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: &[
                "-B",
                "--prefix",
                "-D",
                "--ifdef",
                "-d",
                "--directory",
                "-F",
                "--fuzz",
                "-g",
                "--get",
                "-i",
                "--input",
                "-o",
                "--output",
                "-p",
                "--strip",
                "-r",
                "--reject-file",
                "-V",
                "--version-control",
                "-x",
                "--debug",
                "-Y",
                "--basename-prefix",
                "-z",
                "--suffix",
                "--quoting-style",
            ],
            known_flags: &[
                "-b",
                "--backup",
                "-C",
                "--check",
                "--dry-run",
                "-c",
                "--context",
                "-E",
                "--remove-empty-files",
                "-e",
                "--ed",
                "-f",
                "--force",
                "-l",
                "--ignore-whitespace",
                "-N",
                "--forward",
                "-n",
                "--normal",
                "--posix",
                "-R",
                "--reverse",
                "-s",
                "--quiet",
                "--silent",
                "-t",
                "--batch",
                "-T",
                "--set-time",
                "-u",
                "--unified",
                "-v",
                "--version",
                "--help",
            ],
        };
        let scanned = scan_with_value_indices(ctx.argv, &SPEC, true);
        let mut unknown = scanned.unknown_flags.clone();
        unknown.extend(
            scanned
                .operands
                .iter()
                .skip(2)
                .map(|(index, operand)| (*index, operand.render_raw())),
        );
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown);
        if scanned.has(&["--help", "-v", "--version"]) || !unknown.is_empty() {
            return;
        }

        let directory = scanned
            .value_of(&["-d", "--directory"])
            .map(|word| ctx.resolve_fs_word(word));
        let target = scanned.operands.first().copied();
        let patch_file = scanned
            .values_of(&["-i", "--input"])
            .into_iter()
            .last()
            .or_else(|| scanned.operands.get(1).copied());
        if let Some((index, patch_file)) = patch_file
            && patch_file.as_literal() != Some("-")
        {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                patch_file,
                "filesystem.read",
                program_input_attrs(),
            );
        }

        if let Some((index, target)) = target {
            let resource =
                resolve_fs_word_with_cwd(target, directory.clone().or_else(|| ctx.cwd_resource()));
            fs_arg_effect(
                builder,
                ctx,
                model_node,
                index,
                target,
                "filesystem.read",
                resource.clone(),
                program_input_attrs(),
            );
            let dry_run = scanned.has(&["-C", "--check", "--dry-run"]);
            let output = scanned.values_of(&["-o", "--output"]).into_iter().last();
            if let Some((output_index, output)) = output {
                if output.as_literal() != Some("-") {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        output_index,
                        output,
                        "filesystem.write",
                        Default::default(),
                    );
                }
            } else if !dry_run {
                fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    target,
                    "filesystem.write",
                    resource,
                    Default::default(),
                );
            }
        } else {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                &["filesystem"],
                if patch_file.is_some() {
                    "patch target is selected by file names in the patch input"
                } else {
                    "patch target is selected by file names in standard input"
                },
            );
        }
    }
}

struct Vim;

impl CommandModel for Vim {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "editor/vim@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["vim", "vi", "nvim"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut commands = Vec::new();
        let mut files = Vec::new();
        let mut scripts = Vec::new();
        let mut unknown = Vec::new();
        let mut ex_silent = false;
        let mut writes_disabled = false;
        let mut flags = true;
        let mut i = 1;
        while i < ctx.argv.len() {
            let word = &ctx.argv[i];
            let index = i as u32;
            let Some(text) = word.as_literal() else {
                unknown.push((index, word.render_raw()));
                i += 1;
                continue;
            };
            if flags && text == "--" {
                flags = false;
            } else if flags && matches!(text, "-c" | "--cmd") {
                if let Some(command) = ctx.argv.get(i + 1).and_then(Word::as_literal) {
                    commands.push((index + 1, command));
                    i += 1;
                } else {
                    unknown.push((index, text.into()));
                }
            } else if flags && text.starts_with("-c") && text.len() > 2 {
                commands.push((index, &text[2..]));
            } else if flags && text.starts_with('+') {
                if text.len() > 1 {
                    commands.push((index, &text[1..]));
                }
            } else if flags && matches!(text, "-es" | "-e" | "-E") {
                ex_silent = true;
            } else if flags && matches!(text, "-m" | "-M") {
                writes_disabled = true;
            } else if flags
                && matches!(
                    text,
                    "-u" | "-U"
                        | "-T"
                        | "-S"
                        | "-s"
                        | "-w"
                        | "-W"
                        | "-i"
                        | "--startuptime"
                        | "--log"
                )
            {
                if let Some(value) = ctx.argv.get(i + 1) {
                    // `-S FILE` sources an Ex script and `-u`/`-U FILE` name
                    // the startup scripts; `NONE`, `NORC` and `DEFAULTS`
                    // name no file.
                    if matches!(text, "-S" | "-u" | "-U")
                        && !matches!(value.as_literal(), Some("NONE" | "NORC" | "DEFAULTS"))
                    {
                        scripts.push((index + 1, value));
                    }
                    i += 1;
                } else {
                    unknown.push((index, text.into()));
                }
            } else if flags
                && (text.starts_with('-')
                    && !matches!(
                        text,
                        "-v" | "-b"
                            | "-l"
                            | "-C"
                            | "-N"
                            | "-V"
                            | "-D"
                            | "-n"
                            | "-R"
                            | "-Z"
                            | "--clean"
                            | "--noplugin"
                            | "--not-a-term"
                            | "--ttyfail"
                    ))
            {
                unknown.push((index, text.into()));
            } else if !text.starts_with('-') {
                files.push((index, word));
            }
            i += 1;
        }

        for (index, file) in &files {
            if file.as_literal() != Some("-") {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.read",
                    program_input_attrs(),
                );
            }
        }
        // A script file is read by Vim but not here, so the Ex commands it
        // holds are unknown.
        for (index, script) in &scripts {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                script,
                "filesystem.read",
                Default::default(),
            );
        }
        if !scripts.is_empty() {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::UNPARSED_SCRIPT,
                BoundaryClass::Unsupported,
                &["filesystem", "process"],
                "Vim script files are not read",
            );
        }
        let mut write_current = false;
        let mut write_all = false;
        let mut unmodeled = false;
        // Standard input has no argv word of its own, so its commands are
        // attributed to the editor.
        let stdin_commands = ex_silent.then(|| ctx.stdin_literal()).flatten();
        for (index, command) in commands
            .into_iter()
            .chain(stdin_commands.iter().map(|source| (0, *source)))
            .flat_map(|(index, source)| source.lines().map(move |line| (index, line)))
            .flat_map(|(index, line)| ex_commands(line).into_iter().map(move |c| (index, c)))
        {
            match command {
                ExCommand::Inert => {}
                ExCommand::WriteCurrent => write_current = true,
                ExCommand::WriteAll => write_all = true,
                ExCommand::WriteFile(_) if writes_disabled => {}
                ExCommand::WriteFile(name) => match ex_file_word(ctx, name) {
                    Some(file) => {
                        operand_effect(
                            builder,
                            ctx,
                            model_node,
                            index,
                            &file,
                            "filesystem.write",
                            Default::default(),
                        );
                    }
                    None => unmodeled = true,
                },
                ExCommand::Shell(source) => {
                    // Vim replaces `%`, `#` and `!` in the command before the
                    // shell reads it.
                    unmodeled |= source.contains(['%', '#', '!']);
                    let arg = crate::models::common::arg_node(builder, ctx, index);
                    ctx.nest_subject(
                        builder,
                        effinterp_proto::Subject::Shell {
                            source: source.to_string(),
                            cwd: ctx.cwd.map(str::to_string),
                            context: Default::default(),
                        },
                        &[model_node, arg],
                    );
                }
                ExCommand::Unmodeled => unmodeled = true,
            }
        }
        if unmodeled {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::UNPARSED_SCRIPT,
                BoundaryClass::Unsupported,
                &["filesystem", "process"],
                "Vim Ex commands other than writes, quits and shell escapes are not modeled",
            );
        }
        if !writes_disabled {
            let selected = if write_all {
                files.as_slice()
            } else if write_current {
                &files[..files.len().min(1)]
            } else {
                &[]
            };
            for (index, file) in selected {
                if file.as_literal() != Some("-") {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        file,
                        "filesystem.write",
                        Default::default(),
                    );
                }
            }
        }
        if ex_silent && ctx.stdin.is_some() && ctx.stdin_literal().is_none() {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                &["filesystem", "process"],
                "Vim Ex commands from standard input are not statically recoverable",
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(builder, model_node, &["filesystem", "process"], &unknown);
    }
}

/// What one Vim Ex command does, as far as the Vim model reads it.
enum ExCommand<'a> {
    /// A quit, a line jump or a search: no effect outside the editor.
    Inert,
    WriteCurrent,
    WriteAll,
    /// `w FILE`, `saveas FILE` and the like write the file they name.
    WriteFile(&'a str),
    /// `!CMD` and `w !CMD` hand the rest of the line to the shell.
    Shell(&'a str),
    Unmodeled,
}

/// The Ex commands on one line. `|` separates commands, except after `!`,
/// which takes the rest of the line as its shell command.
fn ex_commands(line: &str) -> Vec<ExCommand<'_>> {
    // `name` is `full` or an abbreviation of it no shorter than `short`.
    fn is(name: &str, short: &str, full: &str) -> bool {
        name.len() >= short.len() && full.starts_with(name)
    }
    let mut commands = Vec::new();
    let mut rest = line;
    'commands: loop {
        // The range before the command name: line numbers, `%`, marks and
        // `/pattern/` addresses. A pattern left open is a search for it.
        loop {
            rest = rest.trim_start_matches([
                ' ', '\t', ':', '%', '$', '.', ',', ';', '+', '-', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9',
            ]);
            match rest.chars().next() {
                Some(delimiter @ ('/' | '?')) => {
                    let mut escaped = false;
                    let close = rest[1..].find(|c| {
                        let closes = c == delimiter && !escaped;
                        escaped = c == '\\' && !escaped;
                        closes
                    });
                    match close {
                        Some(close) => rest = &rest[close + 2..],
                        None => {
                            commands.push(ExCommand::Inert);
                            break 'commands;
                        }
                    }
                }
                Some('\'') => rest = rest.get(2..).unwrap_or(""),
                _ => break,
            }
        }
        if let Some(source) = rest.strip_prefix('!') {
            commands.push(ExCommand::Shell(source));
            break;
        }
        let name_end = rest
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(rest.len());
        let (name, after) = rest.split_at(name_end);
        let after = after.strip_prefix('!').unwrap_or(after);
        if is(name, "sil", "silent") {
            rest = after;
            continue;
        }
        if is(name, "w", "write") && after.trim_start().starts_with('!') {
            commands.push(ExCommand::Shell(&after.trim_start()[1..]));
            break;
        }
        let (argument, next) = match after.split_once('|') {
            Some((argument, next)) => (argument, Some(next)),
            None => (after, None),
        };
        let argument = argument.trim();
        let argument = argument.strip_prefix(">>").unwrap_or(argument).trim();
        commands.push(
            if is(name, "w", "write")
                || is(name, "up", "update")
                || is(name, "sav", "saveas")
                || is(name, "x", "xit")
                || is(name, "exi", "exit")
                || name == "wq"
            {
                if argument.is_empty() {
                    ExCommand::WriteCurrent
                } else {
                    ExCommand::WriteFile(argument)
                }
            } else if !argument.is_empty() {
                ExCommand::Unmodeled
            } else if is(name, "wa", "wall") || is(name, "wqa", "wqall") || is(name, "xa", "xall") {
                ExCommand::WriteAll
            } else if name.is_empty()
                || is(name, "q", "quit")
                || is(name, "qa", "qall")
                || is(name, "quita", "quitall")
                || is(name, "cq", "cquit")
            {
                ExCommand::Inert
            } else {
                ExCommand::Unmodeled
            },
        );
        match next {
            Some(next) => rest = next,
            None => break,
        }
    }
    commands
}

/// The file an Ex write names, or None where Vim would expand the name (`%`,
/// `#`, an environment variable, a wildcard, backticks) or take part of it as
/// an option (`++enc=`). A leading `~` is the home directory.
fn ex_file_word(ctx: &InvocationCtx, name: &str) -> Option<Word> {
    if name.starts_with("++")
        || name.contains([' ', '\t', '%', '#', '$', '`', '*', '?', '[', '{', '\\', '<'])
    {
        return None;
    }
    Some(match name.strip_prefix('~') {
        Some(below) if below.is_empty() || below.starts_with('/') => {
            match ctx.environment_value("HOME") {
                Some(ResourceExpr::Literal { value }) => Word::literal(format!("{value}{below}")),
                _ => Word::new(vec![
                    WordPart::Env("HOME".into()),
                    WordPart::Literal(below.into()),
                ]),
            }
        }
        Some(_) => return None,
        None => Word::literal(name),
    })
}

/// Destination for an operand placed *into* a directory: `dir/basename(op)`
/// when both are literal, `dir/basename(pattern)` when the operand is a glob,
/// a symbolic join otherwise.
///
/// A glob operand is a selection, and each member lands in the directory under
/// its own basename, so the member-wise destination is the directory joined
/// with the glob's last component: `mv /* /tmp` writes `/tmp/*`, which keeps
/// the selection a pattern instead of naming a literal `*` entry.
pub(crate) fn dest_in_dir(
    dir: &Word,
    operand: &Word,
    cwd: Option<ResourceExpr>,
    platform: effinterp_proto::PathPlatform,
) -> ResourceExpr {
    match (dir.as_literal(), operand.as_literal()) {
        (Some(dir_text), Some(op_text)) => {
            let joined = format!(
                "{}/{}",
                dir_text.trim_end_matches('/'),
                if op_text.ends_with('/') {
                    ""
                } else {
                    basename(op_text)
                }
            );
            crate::paths::resolve_fs_word_with_cwd_on_platform(
                &Word::literal(joined),
                cwd,
                platform,
            )
        }
        (Some(dir_text), None) => match operand.parts.as_slice() {
            [WordPart::Glob(pattern)] => crate::paths::resolve_fs_word_with_cwd_on_platform(
                &Word::new(vec![WordPart::Glob(format!(
                    "{}/{}",
                    dir_text.trim_end_matches('/'),
                    basename(pattern)
                ))]),
                cwd,
                platform,
            ),
            _ => unresolved_dest_in_dir(dir, cwd, platform),
        },
        _ => unresolved_dest_in_dir(dir, cwd, platform),
    }
}

fn unresolved_dest_in_dir(
    dir: &Word,
    cwd: Option<ResourceExpr>,
    platform: effinterp_proto::PathPlatform,
) -> ResourceExpr {
    ResourceExpr::Join {
        parts: vec![
            crate::paths::resolve_fs_word_with_cwd_on_platform(dir, cwd, platform),
            unresolved_resource("filesystem"),
        ],
    }
}

/// `mkfifo NAME...` and `mknod NAME p` both create a named pipe. mknod's
/// other types make device nodes, which this model does not carry.
struct Mkfifo {
    mknod: bool,
}

impl CommandModel for Mkfifo {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        if self.mknod {
            "coreutils/mknod@v0"
        } else {
            "coreutils/mkfifo@v0"
        }
    }

    fn command_names(&self) -> &'static [&'static str] {
        if self.mknod { &["mknod"] } else { &["mkfifo"] }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut scanned = scan(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: true,
                value_flags: &["-m", "--mode"],
                // --context's optional value is attached; it never consumes a name.
                known_flags: &["-Z", "--context", "--help", "--version"],
            },
        );
        for flag in &scanned.flags {
            if (matches!(flag.name, "-m" | "--mode") && flag.value.is_none())
                || (matches!(flag.name, "--help" | "--version")
                    && ctx.argv[flag.index as usize]
                        .as_literal()
                        .is_some_and(|value| value.contains('=')))
            {
                scanned.unknown_flags.push((flag.index, flag.name.into()));
            }
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
        if !scanned.unknown_flags.is_empty() || scanned.has(&["--help", "--version"]) {
            return;
        }
        let mut names = scanned.operands;
        if self.mknod {
            if !matches!(&names[..], [_, (_, kind)] if kind.as_literal() == Some("p")) {
                crate::models::common::boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    BoundaryClass::Unmodeled,
                    &["filesystem"],
                    "mknod device nodes are unmodeled",
                );
                return;
            }
            names.truncate(1);
        }
        for (index, operand) in names {
            let arg = fs_arg_node(builder, ctx, index, operand);
            builder.effect(Effect {
                request_assurance: RequestAssurance::Exact,
                id: Default::default(),
                operation: Operation::new("filesystem.create"),
                resource: ctx.resolve_fs_word(operand),
                attributes: attrs(&[("fifo", true)]),
                modality: Modality::May,
                realm: ExecutionRealm::Host,
                condition: None,
                execution: Default::default(),
                provenance: vec![arg, model_node],
            });
        }
    }
}

struct Tee;

const TEE_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[],
    known_flags: &[
        "-a",
        "--append",
        "-i",
        "--ignore-interrupts",
        "-p",
        "--output-error",
    ],
};

/// GNU `--output-error[=MODE]` only changes how tee reports a failed write.
/// Its mode is optional and attached; an invalid one makes tee exit before
/// it opens any file, so only a valid spelling is a known flag.
fn tee_scan(argv: &[Word]) -> Scanned<'_> {
    let mut scanned = scan(argv, &TEE_SPEC);
    let mut invalid = Vec::new();
    scanned.flags.retain(|flag| {
        let valid = flag.name != "--output-error"
            || argv[flag.index as usize]
                .as_literal()
                .and_then(|text| text.strip_prefix("--output-error"))
                .is_some_and(|mode| {
                    ["", "=warn", "=warn-nopipe", "=exit", "=exit-nopipe"].contains(&mode)
                });
        if !valid {
            invalid.push((flag.index, flag.name.to_string()));
        }
        valid
    });
    scanned.unknown_flags.extend(invalid);
    scanned.unknown_flags.sort();
    scanned
}

impl CommandModel for Tee {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/tee@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["tee"]
    }

    /// tee copies its stdin unchanged to stdout and to each file operand.
    /// Appending keeps what the file held before, so only a truncating copy
    /// makes a file's contents exactly its stdin.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        use crate::models::ModelBindingEnd;
        use effinterp_proto::{CausalAssurance, Port};
        let scanned = tee_scan(argv);
        if !scanned.unknown_flags.is_empty() {
            return Vec::new();
        }
        vec![
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Port(Port::Stdout),
            },
            ModelCausalBinding {
                assurance: if scanned.has(&["-a", "--append"]) {
                    CausalAssurance::Conservative
                } else {
                    CausalAssurance::Exact
                },
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Effect {
                    operation: "filesystem.write".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
            },
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = tee_scan(ctx.argv);
        let mut attributes = attrs(&[("append", scanned.has(&["-a", "--append"]))]);
        attributes.extend(program_output_attrs());
        // tee opens every file operand for writing; an option the model does
        // not read may change that.
        let request_assurance = if scanned.unknown_flags.is_empty() {
            RequestAssurance::Exact
        } else {
            RequestAssurance::Conservative
        };
        for (index, operand) in &scanned.operands {
            if operand.as_literal() == Some("-") {
                continue;
            }
            requested_operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.write",
                attributes.clone(),
                request_assurance,
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

struct HeadTail;

const HEAD_TAIL_VALUE_FLAGS: &[&str] = &[
    "-n",
    "-c",
    "--lines",
    "--bytes",
    "--pid",
    "-s",
    "--sleep-interval",
];

impl CommandModel for HeadTail {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/head-tail@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["head", "tail"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let scanned = scan(
            argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: HEAD_TAIL_VALUE_FLAGS,
                known_flags: &[],
            },
        );
        let mut bindings = Vec::new();
        if operands_read_stdin(&scanned.operands) {
            bindings.push(stdin_stdout_binding());
        }
        if scanned
            .operands
            .iter()
            .any(|(_, operand)| operand.as_literal() != Some("-"))
        {
            bindings.push(filesystem_read_stdout_binding());
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: HEAD_TAIL_VALUE_FLAGS,
            known_flags: &[
                "-q",
                "-v",
                "-f",
                "-F",
                "--follow",
                "-z",
                "--zero-terminated",
                "-r",
            ],
        };
        let scanned = scan(ctx.argv, &SPEC);
        // Historic `head -5` numeric flags are harmless; ignore them.
        let unknown: Vec<(u32, String)> = scanned
            .unknown_flags
            .iter()
            .filter(|(_, name)| !name[1..].chars().all(|c| c.is_ascii_digit()))
            .cloned()
            .collect();
        // With no operand, or `-`, standard input is what is printed, so a
        // file redirected onto it is program input as an operand is.
        if operands_read_stdin(&scanned.operands) && unknown.is_empty() {
            builder.note_stdin_consumed();
        }
        for (index, operand) in &scanned.operands {
            if operand.as_literal() == Some("-") {
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.read",
                if unknown.is_empty() {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown);
    }
}

/// One sed invocation's options, scripts and file operands.
struct SedInvocation<'a> {
    in_place: bool,
    files: Vec<(u32, &'a Word)>,
    script_files: Vec<(u32, Word)>,
    /// Each script text, or None when a script word is not literal.
    scripts: Vec<Option<String>>,
    unknown: Vec<(u32, String)>,
    /// `--help` or `--version`.
    terminal: bool,
}

fn sed_invocation<'a>(argv: &'a [Word]) -> SedInvocation<'a> {
    let mut in_place = false;
    let mut have_script = false;
    let mut script_operand_taken = false;
    let mut files: Vec<(u32, &'a Word)> = Vec::new();
    let mut script_files: Vec<(u32, Word)> = Vec::new();
    // Each script text, or None when a script word is not literal.
    let mut scripts: Vec<Option<String>> = Vec::new();
    let mut unknown: Vec<(u32, String)> = Vec::new();
    let mut flags_done = false;
    let mut terminal = false;

    let mut i = 1;
    while i < argv.len() {
        let word = &argv[i];
        let index = i as u32;
        let text = word.as_literal();
        match text {
            Some("--") if !flags_done => flags_done = true,
            Some(t) if !flags_done && t.starts_with('-') && t.len() > 1 => {
                if t == "--expression" {
                    have_script = true;
                    scripts.push(
                        argv.get(i + 1)
                            .and_then(Word::as_literal)
                            .map(str::to_string),
                    );
                    i += 1;
                } else if t == "--file" {
                    if i + 1 < argv.len() {
                        script_files.push((index, argv[i + 1].clone()));
                    }
                    have_script = true;
                    i += 1;
                } else if let Some(rest) = t.strip_prefix("--file=") {
                    script_files.push((index, Word::literal(rest)));
                    have_script = true;
                } else if t == "--in-place" || t.starts_with("--in-place=") {
                    in_place = true;
                } else if matches!(
                    t,
                    "--quiet"
                        | "--silent"
                        | "--posix"
                        | "--regexp-extended"
                        | "--separate"
                        | "--unbuffered"
                        | "--null-data"
                        | "--debug"
                ) {
                } else if matches!(t, "--help" | "--version") {
                    terminal = true;
                } else if t.starts_with("--") {
                    unknown.push((index, t.to_string()));
                } else {
                    // A short-option cluster: `-Ei`, `-ne SCRIPT`, `-ni.bak`.
                    // `-e` and `-f` take the rest of the word or the next
                    // word as their value, and whatever follows `-i` in the
                    // word is its backup suffix.
                    for (at, flag) in t.char_indices().skip(1) {
                        let rest = &t[at + flag.len_utf8()..];
                        match flag {
                            'n' | 'r' | 'E' | 's' | 'u' | 'z' => continue,
                            'e' => {
                                have_script = true;
                                if rest.is_empty() {
                                    scripts.push(
                                        argv.get(i + 1)
                                            .and_then(Word::as_literal)
                                            .map(str::to_string),
                                    );
                                    i += 1;
                                } else {
                                    scripts.push(Some(rest.to_string()));
                                }
                            }
                            'f' => {
                                have_script = true;
                                if !rest.is_empty() {
                                    script_files.push((index, Word::literal(rest)));
                                } else {
                                    if i + 1 < argv.len() {
                                        script_files.push((index, argv[i + 1].clone()));
                                    }
                                    i += 1;
                                }
                            }
                            'i' => {
                                in_place = true;
                                // BSD's empty backup suffix follows a bare `-i`.
                                if rest.is_empty()
                                    && argv.get(i + 1).and_then(Word::as_literal) == Some("")
                                {
                                    i += 1;
                                }
                            }
                            _ => unknown.push((index, t.to_string())),
                        }
                        break;
                    }
                }
            }
            _ => {
                if !have_script && !script_operand_taken {
                    script_operand_taken = true; // first operand is the script
                    scripts.push(word.as_literal().map(str::to_string));
                } else {
                    files.push((index, word));
                }
            }
        }
        i += 1;
    }
    SedInvocation {
        in_place,
        files,
        script_files,
        scripts,
        unknown,
        terminal,
    }
}

/// sed's script is an opaque mini-program: `w` writes arbitrary files and
/// GNU `e` executes commands. A literal script that provably uses only
/// stream-editing commands needs no boundary; anything else keeps one.
struct Sed;

impl CommandModel for Sed {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/sed@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["sed"]
    }

    /// The edited stream reaches stdout: stdin when no file operand (or `-`)
    /// names the input, and the files it reads otherwise. In-place editing
    /// writes the files back instead.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let sed = sed_invocation(argv);
        if sed.terminal || sed.in_place {
            return Vec::new();
        }
        let mut bindings = Vec::new();
        if operands_read_stdin(&sed.files) {
            bindings.push(stdin_stdout_binding());
        }
        if sed
            .files
            .iter()
            .any(|(_, file)| file.as_literal() != Some("-"))
        {
            bindings.push(filesystem_read_stdout_binding());
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let SedInvocation {
            in_place,
            files,
            script_files,
            scripts,
            unknown,
            terminal,
        } = sed_invocation(ctx.argv);

        // --help and --version print their text and exit before sed compiles
        // a script or opens a file.
        if terminal {
            fs_full_no_spawn(builder);
            return;
        }

        for (index, script_file) in &script_files {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                script_file,
                "filesystem.read",
                Default::default(),
            );
        }
        for (index, file) in &files {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                file,
                "filesystem.read",
                program_input_attrs(),
            );
            if in_place {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.write",
                    attrs(&[("in_place", true)]),
                );
            }
        }
        // With no file operand, or `-`, the stream sed edits is its standard
        // input, which it takes as program input as it does a file's. An
        // option the model does not read may have named the input instead.
        if !in_place && unknown.is_empty() && operands_read_stdin(&files) {
            builder.note_stdin_consumed();
        }
        fs_full_no_spawn(builder);
        // A boundary only for scripts we cannot prove pure: a script file we
        // do not read, a non-literal or unparsable script, or one using the
        // commands with effects outside the stream. An unknown flag may have
        // swallowed a script, so it also keeps the boundary.
        let pure = script_files.is_empty()
            && unknown.is_empty()
            && scripts
                .iter()
                .all(|s| s.as_deref().is_some_and(sed_script_is_pure));
        if !pure {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNPARSED_SCRIPT,
                class: BoundaryClass::Unsupported,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("process")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("sed scripts may write files (w) or execute commands (e)".to_string()),
            });
        }
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown);
    }
}

/// Whether a literal sed script provably avoids the commands with effects
/// outside the stream: `w`/`W` (write a file), `r`/`R` (read a file), `e`
/// (execute a command), and `s///` with a `w` or `e` flag. Anything this
/// walker does not recognize counts as impure, keeping the boundary.
fn sed_script_is_pure(script: &str) -> bool {
    // The character after an unescaped opening delimiter sequence, or None
    // when the delimiter never closes.
    fn skip_delimited(chars: &[char], mut i: usize, delim: char) -> Option<usize> {
        while i < chars.len() {
            match chars[i] {
                '\\' => i += 2,
                c if c == delim => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    }

    let chars: Vec<char> = script.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        match chars[i] {
            // Separators, addresses (`5`, `$`, `1,3`, `0~4`), and negation.
            ' ' | '\t' | '\n' | ';' | '0'..='9' | '$' | ',' | '!' | '~' => i += 1,
            // `/regex/` address.
            '/' => match skip_delimited(&chars, i + 1, '/') {
                Some(j) => i = j,
                None => return false,
            },
            // `\cREGEXc` address.
            '\\' => {
                let Some(&delim) = chars.get(i + 1) else {
                    return false;
                };
                match skip_delimited(&chars, i + 2, delim) {
                    Some(j) => i = j,
                    None => return false,
                }
            }
            's' => {
                let Some(&delim) = chars.get(i + 1) else {
                    return false;
                };
                let Some(after_pattern) = skip_delimited(&chars, i + 2, delim) else {
                    return false;
                };
                let Some(after_replacement) = skip_delimited(&chars, after_pattern, delim) else {
                    return false;
                };
                i = after_replacement;
                while i < n && !matches!(chars[i], ';' | '\n' | '}') {
                    match chars[i] {
                        // `w FILE` and `e` flags fall through to impure.
                        '0'..='9' | 'g' | 'p' | 'i' | 'I' | 'm' | 'M' | ' ' => i += 1,
                        _ => return false,
                    }
                }
            }
            'y' => {
                let Some(&delim) = chars.get(i + 1) else {
                    return false;
                };
                let Some(after_source) = skip_delimited(&chars, i + 2, delim) else {
                    return false;
                };
                match skip_delimited(&chars, after_source, delim) {
                    Some(j) => i = j,
                    None => return false,
                }
            }
            // Stream-only commands.
            'd' | 'D' | 'p' | 'P' | 'n' | 'N' | 'h' | 'H' | 'g' | 'G' | 'x' | 'z' | '=' | 'l'
            | 'q' | 'Q' | '{' | '}' => i += 1,
            // A label ends at `;`, a blank or `}` in GNU sed, so the script
            // continues after it: `$!b;e CMD` runs CMD. Reading the rest as
            // commands is also safe where another sed takes the whole line
            // as the label, since that only keeps a boundary.
            'b' | 't' | 'T' | ':' => {
                i += 1;
                while i < n && matches!(chars[i], ' ' | '\t') {
                    i += 1;
                }
                while i < n && !matches!(chars[i], ';' | '\n' | ' ' | '\t' | '}') {
                    i += 1;
                }
            }
            // Output text and comments run to end of line (an escaped
            // newline continues `a\` text).
            'a' | 'i' | 'c' | '#' => {
                while i < n && chars[i] != '\n' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            // `w`, `W`, `r`, `R`, `e`, and anything unrecognized.
            _ => return false,
        }
    }
    true
}

/// `ls [FILE]...`: a metadata read of each operand, or of the current
/// directory when none is given.
struct Ls;

impl CommandModel for Ls {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/ls@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["ls"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: &[
                "-w",
                "--width",
                "-T",
                "--tabsize",
                "-I",
                "--ignore",
                "--hide",
                "--format",
                "--sort",
                "--time",
                "--time-style",
                "--color",
                "--quoting-style",
                "--block-size",
                "--indicator-style",
            ],
            known_flags: &[
                "-1",
                "-a",
                "--all",
                "-A",
                "--almost-all",
                "-b",
                "--escape",
                "-B",
                "-c",
                "-C",
                "-d",
                "--directory",
                "-f",
                "-F",
                "--classify",
                "-g",
                "-G",
                "--no-group",
                "-h",
                "--human-readable",
                "-H",
                "-i",
                "--inode",
                "-k",
                "-l",
                "-L",
                "--dereference",
                "-m",
                "-n",
                "--numeric-uid-gid",
                "-N",
                "--literal",
                "-o",
                "-p",
                "--file-type",
                "-q",
                "--hide-control-chars",
                "-Q",
                "--quote-name",
                "-r",
                "--reverse",
                "-R",
                "--recursive",
                "-s",
                "--size",
                "-S",
                "--si",
                "-t",
                "-u",
                "-U",
                "-v",
                "-x",
                "-X",
                "-Z",
                "--group-directories-first",
            ],
        };
        let scanned = scan(ctx.argv, &SPEC);
        let recursive = scanned.has(&["-R", "--recursive"]);
        let attributes = attrs(&[("metadata", true), ("recursive", recursive)]);
        if scanned.operands.is_empty() {
            let operand = Word::literal(".");
            operand_effect(
                builder,
                ctx,
                model_node,
                0,
                &operand,
                "filesystem.read",
                attributes,
            );
        } else {
            for (index, operand) in &scanned.operands {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    operand,
                    "filesystem.read",
                    attributes.clone(),
                );
            }
        }
        // Outside a terminal, `ls [-A] DIR` prints each entry name of the
        // directory on its own line: every name but the dot entries with
        // `-A`, every name without a leading dot otherwise.
        if scanned.unknown_flags.is_empty()
            && scanned
                .flags
                .iter()
                .all(|flag| matches!(flag.name, "-A" | "--almost-all" | "-1"))
            && let [(_, operand)] = scanned.operands.as_slice()
            && let ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } = ctx.resolve_fs_word(operand)
            // A second pass may leave the answer ambiguous once the plan
            // mutates below the directory; only an answered other kind
            // (a file prints its own name) rules the listing out.
            && super::sysutils::find_observe(builder, &path, model_node)
                .is_none_or(|fact| fact.kind == effinterp_proto::PathKind::Directory)
        {
            let mut names = vec![Word::new(vec![WordPart::Glob("*".into())])];
            if scanned.has(&["-A", "--almost-all"]) {
                names.push(Word::new(vec![WordPart::Glob(".*".into())]));
            }
            builder.record_stdout_paths(crate::models::PrintedPaths {
                paths: names,
                nul: false,
                under: Some(path),
            });
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// `stat [OPTION]... FILE...`: a metadata read of each file operand.
struct Stat;

impl CommandModel for Stat {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/stat@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["stat"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: &["-c", "--format", "--printf"],
            known_flags: &[
                "-L",
                "--dereference",
                "-f",
                "--file-system",
                "-t",
                "--terse",
            ],
        };
        let scanned = scan(ctx.argv, &SPEC);
        for (index, operand) in &scanned.operands {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.read",
                attrs(&[("metadata", true)]),
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}
